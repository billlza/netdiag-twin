use super::*;

fn check(
    name: &str,
    status: ConnectorHealthStatus,
    reason_codes: Vec<ReliabilityReasonCode>,
    artifact: Option<&str>,
) -> ReliabilityCheck {
    ReliabilityCheck {
        name: name.to_string(),
        status,
        run_id: Some("run-1".to_string()),
        artifact: artifact.map(str::to_string),
        reason_codes,
        message: "test reliability check".to_string(),
    }
}

#[test]
fn rejects_an_unexpected_freshness_result_instead_of_hiding_it() {
    let error = remove_expected_pending_bundle_check(vec![check(
        "evidence bundle freshness",
        ConnectorHealthStatus::Ok,
        Vec::new(),
        Some("runs/run-1/evidence_bundle.json"),
    )])
    .expect_err("a non-pending freshness result must fail closed");

    assert!(
        error
            .to_string()
            .contains("unexpected evidence bundle check")
    );
}

#[test]
fn requires_exactly_one_pending_bundle_freshness_check() {
    let error = remove_expected_pending_bundle_check(vec![check(
        "required artifact exists",
        ConnectorHealthStatus::Ok,
        Vec::new(),
        Some("runs/run-1/report.json"),
    )])
    .expect_err("missing bundle freshness contract must fail closed");

    assert!(
        error
            .to_string()
            .contains("did not report the required pending")
    );
}
