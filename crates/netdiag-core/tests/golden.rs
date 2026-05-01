use float_cmp::approx_eq;
use netdiag_core::error::NetdiagError;
use netdiag_core::ingest::ingest_trace;
use netdiag_core::ml::{
    MODEL_FILE_NAME, MODEL_MANIFEST_FILE_NAME, export_feedback_training_dataset,
    load_or_train_model, train_model_from_jsonl,
};
use netdiag_core::models::{
    FaultLabel, HilFeedbackRecord, HilReviewSummary, HilState, MetricProvenance, MetricQuality,
    ModelManifest, Recommendation, RecommendationKind, RunIndexEntry, RunManifest,
    TwinPolicyActionKind,
};
use netdiag_core::pipeline::{PipelineResult, diagnose_file};
use netdiag_core::report::Report;
use netdiag_core::rules::diagnose_rules;
use netdiag_core::storage::{review_recommendation, save_json_atomic};
use netdiag_core::telemetry::summarize_telemetry;
use netdiag_core::twin::run_simulated_whatif;
use serde::ser::{Error as _, Serialize, Serializer};
use serde_json::json;
use std::fs;
use std::io::Write;
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
        -11.45,
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
        let whatif_path = PathBuf::from(
            manifest
                .artifact_paths
                .get("whatif_default")
                .expect("whatif path"),
        );
        let whatif_json: serde_json::Value =
            serde_json::from_slice(&fs::read(&whatif_path).expect("whatif artifact"))
                .expect("whatif json");
        assert!(whatif_json["topology_snapshot"].is_object(), "{name}");
        assert_eq!(whatif_json["policy_action"]["kind"], "reroute", "{name}");

        let report_artifact: Report =
            serde_json::from_slice(&fs::read(result.run_dir.join("report.json")).expect("report"))
                .expect("report json");
        let report_whatif = report_artifact.what_if.as_ref().expect("report whatif");
        assert!(report_whatif.topology_snapshot.is_some(), "{name}");
        assert_eq!(
            report_whatif
                .policy_action
                .as_ref()
                .map(|action| action.kind),
            Some(TwinPolicyActionKind::Reroute),
            "{name}"
        );
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

    let model_manifest: ModelManifest = serde_json::from_slice(
        &fs::read(temp.path().join("model").join(MODEL_MANIFEST_FILE_NAME))
            .expect("model manifest"),
    )
    .expect("model manifest json");
    assert!(model_manifest.synthetic_fallback);
    assert_eq!(model_manifest.model_file, MODEL_FILE_NAME);
    assert_eq!(model_manifest.feature_names.len(), 11);
    assert_eq!(model_manifest.labels.len(), FaultLabel::ALL.len());
}

#[test]
fn training_jsonl_writes_model_manifest() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset_path = temp.path().join("training.jsonl");
    let mut dataset = fs::File::create(&dataset_path).expect("create dataset");
    for name in [
        "normal",
        "congestion",
        "random_loss",
        "dns_failure",
        "tls_failure",
        "udp_quic_blocked",
    ] {
        let ingest = ingest_trace(sample(name)).expect("sample ingest");
        let row = json!({
            "label": name,
            "records": ingest.records,
        });
        writeln!(dataset, "{row}").expect("write training row");
    }

    let model_dir = temp.path().join("trained-model");
    let manifest = train_model_from_jsonl(&dataset_path, &model_dir).expect("train model");
    assert!(!manifest.synthetic_fallback);
    assert_eq!(manifest.training_examples, FaultLabel::ALL.len());
    assert_eq!(manifest.feature_names.len(), 11);
    assert_eq!(manifest.labels.len(), FaultLabel::ALL.len());
    assert!(model_dir.join(MODEL_FILE_NAME).exists());
    assert!(model_dir.join(MODEL_MANIFEST_FILE_NAME).exists());
}

#[test]
fn load_or_train_model_writes_synthetic_fallback_manifest() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    load_or_train_model(&model_dir).expect("fallback model");

    let manifest: ModelManifest = serde_json::from_slice(
        &fs::read(model_dir.join(MODEL_MANIFEST_FILE_NAME)).expect("model manifest"),
    )
    .expect("model manifest json");
    assert!(manifest.synthetic_fallback);
    assert_eq!(manifest.training_source, "synthetic_fallback");
    assert_eq!(manifest.model_file, MODEL_FILE_NAME);
    assert_eq!(manifest.labels.len(), FaultLabel::ALL.len());
}

#[test]
fn stable_golden_summaries_cover_six_sample_contracts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let cases = [
        (
            "normal",
            json!({
                "sample": "normal",
                "root_causes": ["normal"],
                "rule_labels": ["normal"],
                "ml_top3": [
                    { "label": "normal", "prob": 0.9997 },
                    { "label": "random_loss", "prob": 0.0002 },
                    { "label": "udp_quic_blocked", "prob": 0.0001 }
                ],
                "recommendations": [
                    {
                        "symptom": "normal",
                        "action": "No action required; continue monitoring.",
                        "effect": "What-if expects throughput improve by 0.0% with latency -11.4% change.",
                        "risk": "low",
                        "confidence": 0.855,
                        "approval": true,
                        "hil": "unreviewed",
                        "what_if": null
                    }
                ],
                "what_if_delta": { "latency_pct": -11.45, "loss_pct": -32.61, "throughput_pct": 0.0 }
            }),
        ),
        (
            "congestion",
            json!({
                "sample": "congestion",
                "root_causes": ["congestion", "random_loss"],
                "rule_labels": ["congestion", "random_loss"],
                "ml_top3": [
                    { "label": "congestion", "prob": 0.9972 },
                    { "label": "dns_failure", "prob": 0.0021 },
                    { "label": "random_loss", "prob": 0.0006 }
                ],
                "recommendations": [
                    {
                        "symptom": "congestion",
                        "action": "Reroute traffic window + check queue limits and active queue management.",
                        "effect": "What-if expects throughput improve by 21.6% with latency -11.4% change.",
                        "risk": "medium",
                        "confidence": 0.774,
                        "approval": true,
                        "hil": "unreviewed",
                        "what_if": null
                    },
                    {
                        "symptom": "random_loss",
                        "action": "Enable packet-loss mitigation profile and inspect underlay noise source.",
                        "effect": "What-if expects throughput improve by 21.6% with latency -11.4% change.",
                        "risk": "medium",
                        "confidence": 0.729,
                        "approval": true,
                        "hil": "unreviewed",
                        "what_if": null
                    },
                    {
                        "symptom": "none",
                        "action": "Execute what-if action: reroute_path_b (Reroute to less-loaded path B)",
                        "effect": "Expected latency/throughput changes validated in simulation.",
                        "risk": "low",
                        "confidence": 0.85,
                        "approval": true,
                        "hil": "unreviewed",
                        "what_if": "reroute_path_b"
                    }
                ],
                "what_if_delta": { "latency_pct": -11.45, "loss_pct": -32.61, "throughput_pct": 21.65 }
            }),
        ),
        (
            "random_loss",
            json!({
                "sample": "random_loss",
                "root_causes": ["random_loss"],
                "rule_labels": ["random_loss"],
                "ml_top3": [
                    { "label": "random_loss", "prob": 0.9416 },
                    { "label": "dns_failure", "prob": 0.0557 },
                    { "label": "congestion", "prob": 0.002 }
                ],
                "recommendations": [
                    {
                        "symptom": "random_loss",
                        "action": "Enable packet-loss mitigation profile and inspect underlay noise source.",
                        "effect": "What-if expects throughput improve by 15.6% with latency -11.4% change.",
                        "risk": "medium",
                        "confidence": 0.729,
                        "approval": true,
                        "hil": "unreviewed",
                        "what_if": null
                    },
                    {
                        "symptom": "none",
                        "action": "Execute what-if action: reroute_path_b (Reroute to less-loaded path B)",
                        "effect": "Expected latency/throughput changes validated in simulation.",
                        "risk": "low",
                        "confidence": 0.85,
                        "approval": true,
                        "hil": "unreviewed",
                        "what_if": "reroute_path_b"
                    }
                ],
                "what_if_delta": { "latency_pct": -11.45, "loss_pct": -32.61, "throughput_pct": 15.63 }
            }),
        ),
        (
            "dns_failure",
            json!({
                "sample": "dns_failure",
                "root_causes": ["dns_failure"],
                "rule_labels": ["dns_failure"],
                "ml_top3": [
                    { "label": "dns_failure", "prob": 0.7735 },
                    { "label": "normal", "prob": 0.2115 },
                    { "label": "random_loss", "prob": 0.0121 }
                ],
                "recommendations": [
                    {
                        "symptom": "dns_failure",
                        "action": "Check DNS resolver health and confirm certificate trust path.",
                        "effect": "What-if expects throughput improve by 13.4% with latency -11.4% change.",
                        "risk": "high",
                        "confidence": 0.855,
                        "approval": true,
                        "hil": "unreviewed",
                        "what_if": null
                    },
                    {
                        "symptom": "none",
                        "action": "Execute what-if action: reroute_path_b (Reroute to less-loaded path B)",
                        "effect": "Expected latency/throughput changes validated in simulation.",
                        "risk": "low",
                        "confidence": 0.85,
                        "approval": true,
                        "hil": "unreviewed",
                        "what_if": "reroute_path_b"
                    }
                ],
                "what_if_delta": { "latency_pct": -11.45, "loss_pct": -32.61, "throughput_pct": 13.41 }
            }),
        ),
        (
            "tls_failure",
            json!({
                "sample": "tls_failure",
                "root_causes": ["tls_failure"],
                "rule_labels": ["tls_failure"],
                "ml_top3": [
                    { "label": "tls_failure", "prob": 0.994 },
                    { "label": "normal", "prob": 0.0051 },
                    { "label": "random_loss", "prob": 0.0005 }
                ],
                "recommendations": [
                    {
                        "symptom": "tls_failure",
                        "action": "Validate TLS versions/ciphers and retry handshake after cert rotation.",
                        "effect": "What-if expects throughput improve by 14.5% with latency -11.4% change.",
                        "risk": "high",
                        "confidence": 0.873,
                        "approval": true,
                        "hil": "unreviewed",
                        "what_if": null
                    },
                    {
                        "symptom": "none",
                        "action": "Execute what-if action: reroute_path_b (Reroute to less-loaded path B)",
                        "effect": "Expected latency/throughput changes validated in simulation.",
                        "risk": "low",
                        "confidence": 0.85,
                        "approval": true,
                        "hil": "unreviewed",
                        "what_if": "reroute_path_b"
                    }
                ],
                "what_if_delta": { "latency_pct": -11.45, "loss_pct": -32.61, "throughput_pct": 14.49 }
            }),
        ),
        (
            "udp_quic_blocked",
            json!({
                "sample": "udp_quic_blocked",
                "root_causes": ["udp_quic_blocked"],
                "rule_labels": ["udp_quic_blocked"],
                "ml_top3": [
                    { "label": "udp_quic_blocked", "prob": 0.9989 },
                    { "label": "dns_failure", "prob": 0.0011 },
                    { "label": "congestion", "prob": 0.0 }
                ],
                "recommendations": [
                    {
                        "symptom": "udp_quic_blocked",
                        "action": "Fall back to TCP transport or alternative relay while verifying UDP policy.",
                        "effect": "What-if expects throughput improve by 16.3% with latency -11.4% change.",
                        "risk": "high",
                        "confidence": 0.675,
                        "approval": true,
                        "hil": "unreviewed",
                        "what_if": null
                    },
                    {
                        "symptom": "none",
                        "action": "Execute what-if action: reroute_path_b (Reroute to less-loaded path B)",
                        "effect": "Expected latency/throughput changes validated in simulation.",
                        "risk": "low",
                        "confidence": 0.85,
                        "approval": true,
                        "hil": "unreviewed",
                        "what_if": "reroute_path_b"
                    }
                ],
                "what_if_delta": { "latency_pct": -11.45, "loss_pct": -32.61, "throughput_pct": 16.27 }
            }),
        ),
    ];

    for (name, expected) in cases {
        let result = diagnose_file(sample(name), temp.path(), Some(("line", "reroute_path_b")))
            .expect("diagnose");
        let summary = stable_golden_summary(name, &result);
        assert_eq!(summary, expected, "{name}");

        let encoded = serde_json::to_string(&summary).expect("summary json");
        assert!(!encoded.contains(&result.run_id), "{name}: run_id leaked");
        assert!(
            !encoded.contains(&result.run_dir.display().to_string()),
            "{name}: run_dir leaked"
        );
    }
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
            recommendation.diagnosis_symptom,
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
fn feedback_export_ignores_whatif_actions_without_final_label() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose_file(
        sample("congestion"),
        temp.path(),
        Some(("line", "reroute_path_b")),
    )
    .expect("diagnose");
    let whatif = result
        .recommendations
        .iter()
        .find(|recommendation| recommendation.kind == RecommendationKind::WhatIfAction)
        .expect("what-if recommendation");
    assert!(whatif.diagnosis_symptom.is_none());

    review_recommendation(
        temp.path(),
        &result.run_id,
        &whatif.recommendation_id,
        HilState::Accepted,
        "accepted action but not a fault label",
        "tester",
        None,
    )
    .expect("review what-if");

    let output = temp.path().join("feedback.jsonl");
    let summary = export_feedback_training_dataset(temp.path(), &output).expect("feedback export");

    assert_eq!(summary.rows, 0);
    assert_eq!(summary.skipped_runs, 1);
    assert_eq!(fs::read_to_string(output).expect("feedback file"), "");
}

#[test]
fn rules_do_not_treat_fallback_metrics_as_measured_congestion_evidence() {
    let records = vec![
        netdiag_core::models::TraceRecord {
            timestamp: chrono::Utc::now(),
            latency_ms: 250.0,
            jitter_ms: 20.0,
            packet_loss_rate: 5.0,
            retransmission_rate: 5.0,
            timeout_events: 0.0,
            retry_events: 0.0,
            throughput_mbps: 1.0,
            dns_failure_events: 0.0,
            tls_failure_events: 0.0,
            quic_blocked_ratio: 0.0,
        },
        netdiag_core::models::TraceRecord {
            timestamp: chrono::Utc::now() + chrono::Duration::seconds(5),
            latency_ms: 260.0,
            jitter_ms: 22.0,
            packet_loss_rate: 5.0,
            retransmission_rate: 5.0,
            timeout_events: 0.0,
            retry_events: 0.0,
            throughput_mbps: 1.0,
            dns_failure_events: 0.0,
            tls_failure_events: 0.0,
            quic_blocked_ratio: 0.0,
        },
    ];
    let mut summary = summarize_telemetry(&records, 5).expect("summary");
    summary.metric_provenance = [
        "latency_ms",
        "jitter_ms",
        "packet_loss_rate",
        "retransmission_rate",
    ]
    .into_iter()
    .map(|field| MetricProvenance {
        field: field.to_string(),
        quality: MetricQuality::Fallback,
        source: "system_counters".to_string(),
        reason: "not measured by connector".to_string(),
    })
    .collect();

    let events = diagnose_rules(&summary, "quality-guard");

    assert_eq!(events[0].evidence.symptom, FaultLabel::Normal);
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
        None,
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
    assert_eq!(
        recommendations[0].kind,
        RecommendationKind::DiagnosisMitigation
    );
    assert_eq!(
        recommendations[0].diagnosis_symptom,
        Some(FaultLabel::Normal)
    );
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

fn stable_golden_summary(sample_name: &str, result: &PipelineResult) -> serde_json::Value {
    let root_causes = result
        .report
        .root_causes
        .iter()
        .map(|cause| cause.symptom.as_str())
        .collect::<Vec<_>>();
    let ml_top3 = result
        .ml_result
        .top_predictions
        .iter()
        .take(3)
        .map(|prediction| {
            json!({
                "label": prediction.label.as_str(),
                "prob": round4(prediction.prob),
            })
        })
        .collect::<Vec<_>>();
    let recommendations = result
        .recommendations
        .iter()
        .map(|recommendation| {
            json!({
                "symptom": recommendation
                    .diagnosis_symptom
                    .map(|label| label.as_str())
                    .unwrap_or("none"),
                "action": recommendation.recommended_action,
                "effect": recommendation.expected_effect,
                "risk": recommendation.risk_level,
                "confidence": round4(recommendation.confidence),
                "approval": recommendation.recommendation_need_approval,
                "hil": recommendation.hil_state.as_str(),
                "what_if": recommendation.what_if_action_id.as_deref(),
            })
        })
        .collect::<Vec<_>>();
    let mut what_if_delta = serde_json::Map::new();
    if let Some(what_if) = &result.what_if {
        for (key, value) in &what_if.delta {
            what_if_delta.insert(key.clone(), json!(round2(*value)));
        }
    }

    json!({
        "sample": sample_name,
        "root_causes": root_causes,
        "rule_labels": result.comparison.rule_labels,
        "ml_top3": ml_top3,
        "recommendations": recommendations,
        "what_if_delta": what_if_delta,
    })
}

fn round4(value: f64) -> f64 {
    round_to(value, 10_000.0)
}

fn round2(value: f64) -> f64 {
    round_to(value, 100.0)
}

fn round_to(value: f64, scale: f64) -> f64 {
    (value * scale).round() / scale
}
