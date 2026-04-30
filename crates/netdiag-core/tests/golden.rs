use float_cmp::approx_eq;
use netdiag_core::error::NetdiagError;
use netdiag_core::ingest::ingest_trace;
use netdiag_core::models::{
    FaultLabel, HilFeedbackRecord, HilReviewSummary, HilState, Recommendation, RunIndexEntry,
    RunManifest,
};
use netdiag_core::pipeline::diagnose_file;
use netdiag_core::report::Report;
use netdiag_core::rules::diagnose_rules;
use netdiag_core::storage::{review_recommendation, save_json_atomic};
use netdiag_core::telemetry::summarize_telemetry;
use netdiag_core::twin::run_simulated_whatif;
use serde::ser::{Error as _, Serialize, Serializer};
use std::fs;
use std::path::PathBuf;

fn sample(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/samples")
        .join(format!("{name}.csv"))
}

#[test]
fn sample_rules_match_expected_business_labels() {
    let cases = [
        ("normal", vec![FaultLabel::Normal]),
        (
            "congestion",
            vec![FaultLabel::Congestion, FaultLabel::RandomLoss],
        ),
        ("random_loss", vec![FaultLabel::RandomLoss]),
        ("dns_failure", vec![FaultLabel::DnsFailure]),
        ("tls_failure", vec![FaultLabel::TlsFailure]),
        ("udp_quic_blocked", vec![FaultLabel::UdpQuicBlocked]),
    ];

    for (name, expected) in cases {
        let ingest = ingest_trace(sample(name)).expect("sample ingest");
        assert_eq!(ingest.schema.rows, 80, "{name}");
        let summary = summarize_telemetry(&ingest.records, 5).expect("summary");
        assert_eq!(summary.windows.len(), 16, "{name}");
        let first_window = &summary.windows[0].latency_ms;
        assert!(first_window.p50 <= first_window.p95, "{name}");
        assert!(first_window.p95 <= first_window.p99, "{name}");
        let labels = diagnose_rules(&summary, "golden")
            .into_iter()
            .map(|event| event.evidence.symptom)
            .collect::<Vec<_>>();
        assert_eq!(labels, expected, "{name}");
    }
}

#[test]
fn whatif_reroute_preserves_expected_formula() {
    let ingest = ingest_trace(sample("congestion")).expect("sample ingest");
    let summary = summarize_telemetry(&ingest.records, 5).expect("summary");
    let whatif = run_simulated_whatif(&summary.overall, "line", "reroute_path_b").expect("whatif");
    assert_eq!(whatif.action_id, "reroute_path_b");
    assert_eq!(whatif.topology, "line");
    assert!(approx_eq!(
        f64,
        whatif.delta["latency_pct"],
        -25.0,
        epsilon = 0.001
    ));
    assert!(whatif.proposed["qoe_risk"].as_str().is_some());
}

#[test]
fn full_pipeline_writes_artifacts_and_rust_ml_top_label() {
    let temp = tempfile::tempdir().expect("tempdir");
    let cases = [
        ("normal", FaultLabel::Normal),
        ("congestion", FaultLabel::Congestion),
        ("random_loss", FaultLabel::RandomLoss),
        ("dns_failure", FaultLabel::DnsFailure),
        ("tls_failure", FaultLabel::TlsFailure),
        ("udp_quic_blocked", FaultLabel::UdpQuicBlocked),
    ];
    let expected_runs = cases.len();

    for (name, expected_ml) in cases {
        let result = diagnose_file(sample(name), temp.path(), Some(("line", "reroute_path_b")))
            .expect("diagnose");
        assert!(result.run_dir.join("manifest.json").exists(), "{name}");
        assert!(result.run_dir.join("report.json").exists(), "{name}");
        let manifest: RunManifest =
            serde_json::from_slice(&fs::read(result.run_dir.join("manifest.json")).unwrap())
                .expect("manifest json");
        for (key, path) in &manifest.artifact_paths {
            if key == "run_id" {
                continue;
            }
            let path = PathBuf::from(path);
            assert!(path.starts_with(&result.run_dir), "{name}: {key}");
            assert!(path.exists(), "{name}: {key}");
            assert_eq!(
                path.parent(),
                Some(result.run_dir.as_path()),
                "{name}: {key}"
            );
        }
        assert!(
            result
                .recommendations
                .iter()
                .all(|rec| rec.recommendation_need_approval)
        );
        let ml_top = result.ml_result.top_predictions[0].label;
        assert_eq!(ml_top, expected_ml, "{name}");
    }

    let index_path = temp.path().join("run_index.json");
    let run_index: Vec<RunIndexEntry> =
        serde_json::from_slice(&fs::read(index_path).expect("run index")).expect("index json");
    assert_eq!(run_index.len(), expected_runs);
    assert!(
        run_index
            .iter()
            .all(|entry| entry.status == "pending_review")
    );
}

#[test]
fn hil_review_updates_feedback_recommendations_report_and_index() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose_file(
        sample("congestion"),
        temp.path(),
        Some(("line", "reroute_path_b")),
    )
    .expect("diagnose");

    for recommendation in &result.recommendations {
        assert!(!recommendation.recommendation_id.is_empty());
        review_recommendation(
            temp.path(),
            &result.run_id,
            &recommendation.recommendation_id,
            HilState::Accepted,
            "approved in regression",
            "tester",
        )
        .expect("review recommendation");
    }

    let recommendations: Vec<Recommendation> = serde_json::from_slice(
        &fs::read(result.run_dir.join("recommendations.json")).expect("recommendations"),
    )
    .expect("recommendations json");
    assert!(
        recommendations
            .iter()
            .all(|recommendation| recommendation.hil_state == HilState::Accepted)
    );
    assert!(recommendations.iter().all(|recommendation| {
        recommendation
            .review
            .as_ref()
            .is_some_and(|review| review.notes == "approved in regression")
    }));

    let report: Report =
        serde_json::from_slice(&fs::read(result.run_dir.join("report.json")).expect("report"))
            .expect("report json");
    assert_eq!(
        report.hil_summary,
        HilReviewSummary {
            total: recommendations.len(),
            accepted: recommendations.len(),
            ..HilReviewSummary::default()
        }
    );

    let feedback: std::collections::BTreeMap<String, HilFeedbackRecord> = serde_json::from_slice(
        &fs::read(result.run_dir.join("hil_feedback.json")).expect("feedback"),
    )
    .expect("feedback json");
    assert_eq!(feedback.len(), recommendations.len());

    let run_index: Vec<RunIndexEntry> =
        serde_json::from_slice(&fs::read(temp.path().join("run_index.json")).expect("run index"))
            .expect("index json");
    assert_eq!(run_index[0].status, "reviewed");

    let manifest: RunManifest =
        serde_json::from_slice(&fs::read(result.run_dir.join("manifest.json")).expect("manifest"))
            .expect("manifest json");
    assert!(manifest.artifact_paths.contains_key("hil_feedback"));
}

#[test]
fn hil_review_rejects_unknown_recommendation_id() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose_file(
        sample("normal"),
        temp.path(),
        Some(("line", "reroute_path_b")),
    )
    .expect("diagnose");

    let err = review_recommendation(
        temp.path(),
        &result.run_id,
        "missing-recommendation",
        HilState::Rejected,
        "no such item",
        "tester",
    )
    .expect_err("unknown id should fail");
    assert!(matches!(
        err,
        NetdiagError::UnknownRecommendation(ref id) if id == "missing-recommendation"
    ));
}

#[test]
fn recommendation_serde_accepts_pre_hil_artifacts() {
    let old = r#"[{
        "run_id": "run-1",
        "diagnosis_symptom": "normal",
        "recommended_action": "Monitor",
        "expected_effect": "None",
        "risk_level": "low",
        "confidence": 0.5,
        "recommendation_need_approval": true,
        "hil_state": "unreviewed"
    }]"#;
    let recommendations: Vec<Recommendation> =
        serde_json::from_str(old).expect("old recommendation schema");
    assert_eq!(recommendations[0].recommendation_id, "");
    assert!(recommendations[0].review.is_none());
}

#[test]
fn ingest_rejects_missing_required_column() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("missing_latency.csv");
    fs::write(
        &path,
        "timestamp,jitter_ms,packet_loss_rate,retransmission_rate,throughput_mbps\n\
         2026-01-01 00:00:00,1,0.1,0.2,10\n",
    )
    .expect("write trace");

    let err = ingest_trace(&path).expect_err("missing required column should fail");
    assert!(matches!(err, NetdiagError::MissingColumn(column) if column == "latency_ms"));
}

#[test]
fn ingest_rejects_bad_numbers_and_timestamps() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bad_number = temp.path().join("bad_number.csv");
    fs::write(
        &bad_number,
        "timestamp,latency_ms,jitter_ms,packet_loss_rate,retransmission_rate,throughput_mbps\n\
         2026-01-01 00:00:00,nope,1,0.1,0.2,10\n",
    )
    .expect("write bad number");
    let err = ingest_trace(&bad_number).expect_err("bad number should fail");
    assert!(matches!(
        err,
        NetdiagError::InvalidNumber {
            row: 1,
            ref column,
            ..
        } if column == "latency_ms"
    ));

    let bad_timestamp = temp.path().join("bad_timestamp.csv");
    fs::write(
        &bad_timestamp,
        "timestamp,latency_ms,jitter_ms,packet_loss_rate,retransmission_rate,throughput_mbps\n\
         tomorrow-ish,10,1,0.1,0.2,10\n",
    )
    .expect("write bad timestamp");
    let err = ingest_trace(&bad_timestamp).expect_err("bad timestamp should fail");
    assert!(matches!(err, NetdiagError::InvalidTimestamp { row: 1, .. }));
}

#[test]
fn ingest_warns_when_event_columns_are_missing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("missing_events.csv");
    fs::write(
        &path,
        "timestamp,latency_ms,jitter_ms,packet_loss_rate,retransmission_rate,throughput_mbps\n\
         2026-01-01 00:00:00,10,1,0.1,0.2,10\n",
    )
    .expect("write trace");

    let ingest = ingest_trace(&path).expect("event columns are optional");
    assert_eq!(ingest.records[0].timeout_events, 0.0);
    assert_eq!(ingest.warnings.len(), 5);
    assert!(
        ingest
            .warnings
            .iter()
            .any(|warning| warning.column == "timeout_events")
    );
}

#[test]
fn save_json_atomic_writes_readable_json_and_avoids_partial_final_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("atomic.json");

    save_json_atomic(&path, &serde_json::json!({ "ok": true })).expect("atomic write");
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).expect("read atomic json")).expect("valid json");
    assert_eq!(value["ok"], true);
    assert!(!path.with_extension("json.tmp").exists());

    let failing_path = temp.path().join("failing.json");
    let err = save_json_atomic(&failing_path, &FailingSerialize).expect_err("serialize fails");
    assert!(
        err.to_string()
            .contains("intentional serialization failure")
    );
    assert!(!failing_path.exists());
    assert!(!failing_path.with_extension("json.tmp").exists());
}

struct FailingSerialize;

impl Serialize for FailingSerialize {
    fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(S::Error::custom("intentional serialization failure"))
    }
}
