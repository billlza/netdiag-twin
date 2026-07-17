use super::*;

fn index_entry(run_id: &str, scenario_path: &str) -> LabRunIndexEntry {
    LabRunIndexEntry {
        run_id: run_id.to_string(),
        scenario_id: "verification-policy".to_string(),
        scenario_name: "Verification policy".to_string(),
        created_at: Utc::now(),
        lab_run_dir: format!("lab-runs/verification-policy/{run_id}"),
        pipeline_run_dir: format!("lab-runs/verification-policy/{run_id}/runs/{run_id}"),
        acceptance_path: format!("lab-runs/verification-policy/{run_id}/acceptance.json"),
        comparison_path: format!("lab-runs/verification-policy/{run_id}/comparison.json"),
        scenario_path: scenario_path.to_string(),
        passed: false,
    }
}

fn write_index(root: &Path, entry: LabRunIndexEntry) {
    let index = LabRunIndex {
        schema: "netdiag-lab-run-index/v1".to_string(),
        generated_at: Utc::now(),
        runs: vec![entry],
    };
    std::fs::write(
        root.join("lab_run_index.json"),
        serde_json::to_vec_pretty(&index).expect("serialize lab index fixture"),
    )
    .expect("write lab index fixture");
}

#[test]
fn verification_policy_propagates_corrupt_lab_index() {
    let temp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        temp.path().join("lab_run_index.json"),
        b"{private-lab-index-sentinel}",
    )
    .expect("write corrupt lab index fixture");

    let error = verification_policy_for_run(temp.path(), "run-1")
        .expect_err("corrupt lab index must not become an absent verification policy");

    let NetdiagError::LabContextResolution {
        run_id,
        lab_resolution,
        context_resolution,
    } = &error
    else {
        panic!("expected both lookup failures to be retained, got: {error}");
    };
    assert_eq!(run_id, "run-1");
    assert!(
        lab_resolution
            .to_string()
            .contains("not syntactically valid JSON"),
        "unexpected lab-resolution error: {lab_resolution}"
    );
    assert!(
        context_resolution
            .to_string()
            .contains("not syntactically valid JSON"),
        "unexpected context-resolution error: {context_resolution}"
    );
    assert!(!error.to_string().contains("private-lab-index-sentinel"));
    assert!(
        std::error::Error::source(&error).is_some(),
        "the context-resolution failure must remain in the error source chain"
    );
}

#[test]
fn verification_policy_propagates_index_path_escape() {
    let temp = tempfile::tempdir().expect("tempdir");
    write_index(temp.path(), index_entry("run-1", "../outside.yaml"));

    let error = verification_policy_for_run(temp.path(), "run-1")
        .expect_err("escaping scenario path must not become an absent verification policy");

    assert!(
        error
            .to_string()
            .contains("stored artifact path escapes the artifact root"),
        "unexpected path-escape error: {error}"
    );
}

#[test]
fn verification_policy_is_absent_for_a_valid_non_lab_run() {
    let temp = tempfile::tempdir().expect("tempdir");
    let report_path = temp.path().join("runs/run-1/report.json");
    std::fs::create_dir_all(report_path.parent().expect("report parent"))
        .expect("create run fixture");
    std::fs::write(&report_path, b"{}").expect("write run marker");

    assert!(
        verification_policy_for_run(temp.path(), "run-1")
            .expect("valid non-lab run policy lookup")
            .is_none()
    );
}
