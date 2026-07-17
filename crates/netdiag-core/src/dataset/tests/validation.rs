use super::super::*;
use super::feature_payload;

#[test]
fn unsupported_dataset_publication_fails_before_writing() {
    let error = validate_publication_support(Path::new("dataset-output"), false)
        .expect_err("unsupported publication");
    assert_eq!(
        error.atomic_publish_phase(),
        Some(crate::error::AtomicPublishPhase::NotPublished)
    );
}

#[test]
fn dataset_validation_propagates_missing_file_errors() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing = temp.path().join("missing.jsonl");
    let error = validate_dataset_jsonl(&missing)
        .expect_err("missing dataset must not return a report with an empty hash");
    assert!(error.to_string().contains("missing.jsonl"));
}

#[test]
fn dataset_validate_rejects_malformed_records_payload() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    std::fs::write(
        &dataset,
        serde_json::json!({
            "label": "normal",
            "records": [
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "latency_ms": "private-record-sentinel",
                    "jitter_ms": 1.0,
                    "packet_loss_rate": 0.0,
                    "retransmission_rate": 0.0,
                    "timeout_events": 0.0,
                    "retry_events": 0.0,
                    "throughput_mbps": 100.0,
                    "dns_failure_events": 0.0,
                    "tls_failure_events": 0.0,
                    "quic_blocked_ratio": 0.0
                }
            ]
        })
        .to_string(),
    )
    .expect("write dataset");

    let report = validate_dataset_jsonl(&dataset).expect("validation report");

    assert!(!report.passed);
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.contains("records are not valid TraceRecord[]")),
        "{:?}",
        report.failures
    );
    assert!(
        report
            .failures
            .iter()
            .all(|failure| !failure.contains("private-record-sentinel")),
        "{:?}",
        report.failures
    );
}

#[test]
fn dataset_validate_does_not_echo_an_unsupported_label() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    std::fs::write(
        &dataset,
        serde_json::json!({
            "label": "private-label-sentinel",
            "features": feature_payload(10.0)
        })
        .to_string(),
    )
    .expect("write dataset");

    let report = validate_dataset_jsonl(&dataset).expect("validation report");

    assert!(!report.passed);
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.contains("has an unsupported label")),
        "{:?}",
        report.failures
    );
    assert!(
        report
            .failures
            .iter()
            .all(|failure| !failure.contains("private-label-sentinel")),
        "{:?}",
        report.failures
    );
}

#[test]
fn dataset_streaming_summary_counts_rows_and_labels_without_retaining_lines() {
    let normal = serde_json::json!({
        "label": "normal",
        "features": feature_payload(10.0)
    });
    let congestion = serde_json::json!({
        "final_label": "congestion",
        "features": feature_payload(200.0)
    });
    let input = format!("\n{normal}\n \n{congestion}");

    let summary = read_dataset_summary_from_reader(
        Path::new("streaming-summary.jsonl"),
        std::io::Cursor::new(input.as_bytes()),
    )
    .expect("streaming summary");

    assert_eq!(summary.rows, 2);
    assert_eq!(
        summary.label_distribution,
        BTreeMap::from([("congestion".to_string(), 1), ("normal".to_string(), 1)])
    );
}
