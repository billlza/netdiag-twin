use super::*;
use crate::models::{DiagnosisEvent, EvidenceRecord, HilState, Severity, TimeWindow};
use chrono::Utc;
use std::fs;

#[test]
fn optional_events_distinguish_absence_from_corruption() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("diagnosis_events.json");
    let missing = read_rule_threshold_confidences(&path, false, "run-1", FaultLabel::Congestion)
        .expect("an explicitly absent optional artifact is allowed");
    assert!(missing.is_none());

    fs::write(&path, b"{broken-json").expect("corrupt events");
    let error = read_rule_threshold_confidences(&path, false, "run-1", FaultLabel::Congestion)
        .expect_err("a present corrupt optional artifact must fail closed");
    assert!(
        error.to_string().contains("diagnosis_events.json"),
        "{error}"
    );
}

#[test]
fn optional_events_are_bounded_before_deserialization() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("diagnosis_events.json");
    let file = fs::File::create(&path).expect("events file");
    file.set_len(MAX_DIAGNOSIS_EVENTS_BYTES + 1)
        .expect("oversized sparse events file");

    let error = read_rule_threshold_confidences(&path, false, "run-1", FaultLabel::Congestion)
        .expect_err("an oversized optional artifact must fail before parsing");
    assert!(error.to_string().contains("read limit"), "{error}");
}

#[test]
fn optional_valid_events_still_contribute_threshold_samples() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("diagnosis_events.json");
    let now = Utc::now();
    let event = DiagnosisEvent {
        event_id: "event-1".to_string(),
        evidence: EvidenceRecord {
            run_id: "run-1".to_string(),
            method: "rule".to_string(),
            symptom: FaultLabel::Congestion,
            severity: Severity::Low,
            confidence: 0.75,
            window: TimeWindow {
                start_ts: now,
                end_ts: now,
                bucket: "test".to_string(),
            },
            supporting_metrics: Vec::new(),
            raw_evidence_refs: Vec::new(),
            counter_evidence: Vec::new(),
            recommendation_need_approval: true,
            hil_state: HilState::Unreviewed,
            why: "test".to_string(),
        },
        source: "test".to_string(),
        model_probability: None,
    };
    fs::write(
        &path,
        serde_json::to_vec(&vec![event]).expect("serialize events"),
    )
    .expect("events file");

    let confidences =
        read_rule_threshold_confidences(&path, false, "run-1", FaultLabel::Congestion)
            .expect("valid optional events")
            .expect("present events");
    assert_eq!(confidences, vec![0.75]);
}
