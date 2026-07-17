use super::*;

#[test]
fn model_promotion_options_reject_invalid_thresholds() {
    let result = evaluate_model_promotion(ModelPromotionOptions {
        model_dir: "missing/model".into(),
        benchmark_report: "missing/benchmark.json".into(),
        calibration_report: "missing/calibration.json".into(),
        min_rows_per_label: 1,
        min_accuracy: f64::NAN,
        min_macro_f1: 0.9,
        allow_missing_evaluation: true,
        max_ood_false_positive_rate: 0.05,
        max_ood_false_negative_rate: 0.05,
        max_rule_ml_disagreement_hotspot_rate: 0.10,
        max_calibration_age_days: 30,
        min_expected_ood_runs: 1,
    });

    let message = result.expect_err("invalid threshold").to_string();
    assert!(message.contains("min_accuracy"));

    let result = evaluate_model_promotion(ModelPromotionOptions {
        model_dir: "missing/model".into(),
        benchmark_report: "missing/benchmark.json".into(),
        calibration_report: "missing/calibration.json".into(),
        min_rows_per_label: 1,
        min_accuracy: 0.9,
        min_macro_f1: 0.9,
        allow_missing_evaluation: true,
        max_ood_false_positive_rate: 0.05,
        max_ood_false_negative_rate: 0.05,
        max_rule_ml_disagreement_hotspot_rate: 0.10,
        max_calibration_age_days: 3_651,
        min_expected_ood_runs: 1,
    });
    let message = result
        .expect_err("unbounded calibration age must fail")
        .to_string();
    assert!(message.contains("max_calibration_age_days"));
}

#[test]
fn model_promotion_gate_requires_evaluation_unless_explicitly_allowed() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let benchmark_report = temp.path().join("benchmark_report.json");
    let calibration_report = write_passing_calibration(&artifacts);
    write_passing_benchmark_for_model(&benchmark_report, &artifacts.join("model"));

    let strict = evaluate_model_promotion(ModelPromotionOptions {
        model_dir: artifacts.join("model"),
        benchmark_report: benchmark_report.clone(),
        calibration_report: calibration_report.clone(),
        min_rows_per_label: 1,
        min_accuracy: 0.9,
        min_macro_f1: 0.9,
        allow_missing_evaluation: false,
        max_ood_false_positive_rate: 0.05,
        max_ood_false_negative_rate: 0.05,
        max_rule_ml_disagreement_hotspot_rate: 0.10,
        max_calibration_age_days: 30,
        min_expected_ood_runs: 1,
    })
    .expect("strict gate");
    assert!(!strict.passed);
    assert!(
        strict
            .gates
            .iter()
            .any(|gate| gate.name == "evaluation_present" && !gate.passed)
    );

    let allowed = evaluate_model_promotion(ModelPromotionOptions {
        model_dir: artifacts.join("model"),
        benchmark_report,
        calibration_report,
        min_rows_per_label: 1,
        min_accuracy: 0.9,
        min_macro_f1: 0.9,
        allow_missing_evaluation: true,
        max_ood_false_positive_rate: 0.05,
        max_ood_false_negative_rate: 0.05,
        max_rule_ml_disagreement_hotspot_rate: 0.10,
        max_calibration_age_days: 30,
        min_expected_ood_runs: 1,
    })
    .expect("allowed gate");
    assert!(allowed.passed);
}

#[test]
fn model_promotion_gate_rejects_benchmark_without_candidate_model_hashes() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let benchmark_report = temp.path().join("benchmark_report.json");
    write_passing_benchmark(&benchmark_report);
    let calibration_report = write_passing_calibration(&artifacts);

    let report = evaluate_model_promotion(ModelPromotionOptions {
        model_dir: artifacts.join("model"),
        benchmark_report,
        calibration_report,
        min_rows_per_label: 1,
        min_accuracy: 0.9,
        min_macro_f1: 0.9,
        allow_missing_evaluation: true,
        max_ood_false_positive_rate: 0.05,
        max_ood_false_negative_rate: 0.05,
        max_rule_ml_disagreement_hotspot_rate: 0.10,
        max_calibration_age_days: 30,
        min_expected_ood_runs: 1,
    })
    .expect("promotion report");

    let benchmark_match = gate_by_name(&report.gates, "benchmark_model_match");
    assert!(!benchmark_match.passed);
    assert!(benchmark_match.message.contains("benchmark report"));
    assert!(!report.passed);
}

#[test]
fn model_promotion_rejects_unsupported_benchmark_schema() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let benchmark_report_path = temp.path().join("benchmark_report.json");
    let mut report = benchmark_report(vec![ood_section(ConnectorHealthStatus::Ok)], true);
    report.schema = "netdiag-benchmark-report/v0".to_string();
    save_json_atomic(&benchmark_report_path, &report).expect("benchmark report");
    let gate_path = artifacts.join("model").join(MODEL_PROMOTION_GATE_FILE_NAME);
    save_json_atomic(&gate_path, &serde_json::json!({"passed": true})).expect("existing gate");

    let error = evaluate_model_promotion(ModelPromotionOptions {
        model_dir: artifacts.join("model"),
        benchmark_report: benchmark_report_path,
        calibration_report: temp.path().join("unused-calibration.json"),
        min_rows_per_label: 1,
        min_accuracy: 0.9,
        min_macro_f1: 0.9,
        allow_missing_evaluation: true,
        max_ood_false_positive_rate: 0.05,
        max_ood_false_negative_rate: 0.05,
        max_rule_ml_disagreement_hotspot_rate: 0.10,
        max_calibration_age_days: 30,
        min_expected_ood_runs: 1,
    })
    .expect_err("unsupported benchmark schema must fail fast");

    assert!(error.to_string().contains("netdiag-benchmark-report/v0"));
    assert!(error.to_string().contains(BENCHMARK_SCHEMA));
    assert!(
        gate_path.is_file(),
        "benchmark input failure must not invalidate a current model's gate"
    );
}

#[test]
fn promotion_reads_a_regular_benchmark_report_within_the_bound() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("benchmark_report.json");
    write_passing_benchmark(&path);

    let report = read_benchmark_report(&path).expect("bounded benchmark report");

    assert_eq!(report.schema, BENCHMARK_SCHEMA);
    assert!(report.passed);
}

#[test]
fn promotion_reports_missing_or_invalid_benchmark_input_explicitly() {
    let temp = tempdir().expect("tempdir");
    let missing = temp.path().join("missing_benchmark_report.json");
    let missing_error = read_benchmark_report(&missing).expect_err("missing report must fail");
    assert!(
        missing_error
            .to_string()
            .contains("required benchmark report")
    );
    assert!(
        missing_error
            .to_string()
            .contains(&missing.display().to_string())
    );

    let invalid = temp.path().join("invalid_benchmark_report.json");
    std::fs::write(&invalid, b"{").expect("invalid benchmark fixture");
    let invalid_error = read_benchmark_report(&invalid).expect_err("invalid report must fail");
    assert!(invalid_error.to_string().contains("invalid JSON"));
    assert!(
        invalid_error
            .to_string()
            .contains(&invalid.display().to_string())
    );
}

#[test]
fn promotion_reports_invalid_calibration_json_explicitly() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("invalid_calibration_report.json");
    std::fs::write(&path, b"{").expect("invalid calibration fixture");

    let error = read_calibration_report(&path).expect_err("invalid calibration must fail");

    assert!(error.contains("invalid JSON"));
    assert!(error.contains(&path.display().to_string()));
}

#[test]
fn promotion_rejects_an_oversized_benchmark_report_before_parsing() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("benchmark_report.json");
    let file = std::fs::File::create(&path).expect("oversized benchmark fixture");
    file.set_len(super::super::input::MAX_BENCHMARK_REPORT_BYTES + 1)
        .expect("sparse oversized benchmark fixture");

    let error = read_benchmark_report(&path).expect_err("oversized report must fail closed");

    assert!(error.to_string().contains(&format!(
        "exceeds the {}-byte read limit",
        super::super::input::MAX_BENCHMARK_REPORT_BYTES
    )));
}

#[cfg(unix)]
#[test]
fn promotion_rejects_a_symlinked_calibration_report_without_following_it() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("actual_calibration_report.json");
    let link = temp.path().join("lab_calibration_report.json");
    save_json_atomic(&target, &calibration_report()).expect("calibration target");
    symlink(&target, &link).expect("calibration symlink");

    let error = read_calibration_report(&link).expect_err("symlink must fail closed");

    assert!(error.contains("regular, non-symlink"));
}

#[test]
fn model_promotion_gate_rejects_each_benchmark_candidate_hash_mismatch() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let calibration_report = write_passing_calibration(&artifacts);
    let model_dir = artifacts.join("model");

    for (field, expected_message) in [
        ("manifest", "benchmark report manifest hash mismatch"),
        ("model", "benchmark report model file hash mismatch"),
        ("dataset", "benchmark report dataset hash mismatch"),
    ] {
        let benchmark_report_path = temp.path().join(format!("{field}_benchmark_report.json"));
        let mut report = benchmark_report(vec![ood_section(ConnectorHealthStatus::Ok)], true);
        let snapshot = load_existing_model_bundle_snapshot(&model_dir).expect("model snapshot");
        report.candidate_model_manifest_hash_sha256 = Some(snapshot.model_manifest_hash_sha256);
        report.candidate_model_file_hash_sha256 = Some(snapshot.model_file_hash_sha256);
        report.candidate_dataset_hash_sha256 = snapshot.manifest.dataset_hash_sha256;

        match field {
            "manifest" => {
                report.candidate_model_manifest_hash_sha256 = Some("stale-manifest".to_string());
            }
            "model" => {
                report.candidate_model_file_hash_sha256 = Some("stale-model".to_string());
            }
            "dataset" => {
                report.candidate_dataset_hash_sha256 = Some("stale-dataset".to_string());
            }
            _ => unreachable!("covered fields"),
        }
        save_json_atomic(&benchmark_report_path, &report).expect("benchmark report");

        let promotion = evaluate_model_promotion(ModelPromotionOptions {
            model_dir: model_dir.clone(),
            benchmark_report: benchmark_report_path,
            calibration_report: calibration_report.clone(),
            min_rows_per_label: 1,
            min_accuracy: 0.9,
            min_macro_f1: 0.9,
            allow_missing_evaluation: true,
            max_ood_false_positive_rate: 0.05,
            max_ood_false_negative_rate: 0.05,
            max_rule_ml_disagreement_hotspot_rate: 0.10,
            max_calibration_age_days: 30,
            min_expected_ood_runs: 1,
        })
        .expect("promotion report");

        let benchmark_match = gate_by_name(&promotion.gates, "benchmark_model_match");
        assert!(!benchmark_match.passed, "{field} mismatch should fail");
        assert!(
            benchmark_match.message.contains(expected_message),
            "{field} mismatch message was {}",
            benchmark_match.message
        );
        assert!(!promotion.passed);
    }
}

#[test]
fn default_promotion_thresholds_are_release_grade() {
    assert_eq!(default_min_accuracy(), 0.90);
    assert_eq!(default_min_macro_f1(), 0.90);
    assert_eq!(default_max_ood_false_positive_rate(), 0.05);
    assert_eq!(default_max_ood_false_negative_rate(), 0.05);
    assert_eq!(default_max_rule_ml_disagreement_hotspot_rate(), 0.10);
    assert_eq!(default_max_calibration_age_days(), 30);
    assert_eq!(default_min_expected_ood_runs(), 1);
}

#[test]
fn promotion_report_is_not_persisted_after_bundle_identity_changes() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let model_dir = artifacts.join("model");
    let evaluated = load_existing_model_bundle_snapshot(&model_dir).expect("evaluated snapshot");
    rebuild_synthetic_model_bundle(&model_dir).expect("replacement bundle");
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("current snapshot");
    assert!(!evaluated.same_identity(&current));
    let report = ModelPromotionReport {
        schema: MODEL_PROMOTION_GATE_SCHEMA.to_string(),
        generated_at: Utc::now(),
        passed: true,
        model_dir: model_dir.display().to_string(),
        benchmark_report: "benchmark.json".to_string(),
        calibration_report: "calibration.json".to_string(),
        model_manifest_hash_sha256: Some(evaluated.model_manifest_hash_sha256.clone()),
        model_file_hash_sha256: Some(evaluated.model_file_hash_sha256.clone()),
        gates: vec![gate("test", true, "test")],
    };

    let error = persist_if_current(&model_dir, &evaluated, &report)
        .expect_err("stale promotion report must not be persisted");

    assert!(error.to_string().contains("changed while promotion gates"));
    assert!(!model_dir.join(MODEL_PROMOTION_GATE_FILE_NAME).exists());
}

#[test]
fn promotion_revalidates_same_generation_files_after_a_prior_read() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let model_dir = artifacts.join("model");
    let original = load_existing_model_bundle_snapshot(&model_dir).expect("original snapshot");
    let mut tampered_manifest = original.manifest.clone();
    tampered_manifest.training_source = "same-generation-tamper".to_string();
    save_json_atomic(&original.manifest_path, &tampered_manifest)
        .expect("tamper generation manifest");

    let reloaded = load_existing_model_bundle_snapshot(&model_dir).expect("reloaded snapshot");
    assert_eq!(reloaded.generation, original.generation);
    assert!(
        !reloaded.same_identity(&original),
        "a new operation must revalidate the current generation"
    );

    let report = ModelPromotionReport {
        schema: MODEL_PROMOTION_GATE_SCHEMA.to_string(),
        generated_at: Utc::now(),
        passed: true,
        model_dir: model_dir.display().to_string(),
        benchmark_report: "benchmark.json".to_string(),
        calibration_report: "calibration.json".to_string(),
        model_manifest_hash_sha256: Some(original.model_manifest_hash_sha256.clone()),
        model_file_hash_sha256: Some(original.model_file_hash_sha256.clone()),
        gates: vec![gate("test", true, "test")],
    };
    let gate_path = model_dir.join(MODEL_PROMOTION_GATE_FILE_NAME);
    save_json_atomic(&gate_path, &report).expect("existing passing gate");

    let error = persist_if_current(&model_dir, &original, &report)
        .expect_err("same-generation tampering must block promotion publication");

    assert!(error.to_string().contains("changed while promotion gates"));
    assert!(!gate_path.exists());
}

#[test]
fn corrupt_current_model_state_invalidates_an_existing_promotion_gate() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let model_dir = artifacts.join("model");
    let snapshot = load_existing_model_bundle_snapshot(&model_dir).expect("warm generation cache");
    let gate_path = model_dir.join(MODEL_PROMOTION_GATE_FILE_NAME);
    save_json_atomic(&gate_path, &serde_json::json!({"passed": true})).expect("existing gate");
    let mut corrupt = snapshot.manifest;
    corrupt.model_file_hash_sha256 = "0".repeat(64);
    save_json_atomic(&snapshot.manifest_path, &corrupt).expect("corrupt current manifest");

    let error = load_promotion_snapshot(&model_dir)
        .expect_err("corrupt current model state must fail promotion loading");

    assert!(error.to_string().contains("model bundle hash mismatch"));
    assert!(!gate_path.exists());
}

#[test]
fn current_failure_and_gate_invalidation_failure_are_both_reported() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let model_dir = artifacts.join("model");
    let snapshot = load_existing_model_bundle_snapshot(&model_dir).expect("current snapshot");
    let gate_path = model_dir.join(MODEL_PROMOTION_GATE_FILE_NAME);
    std::fs::create_dir(&gate_path).expect("non-removable gate path");
    let mut corrupt = snapshot.manifest;
    corrupt.model_file_hash_sha256 = "0".repeat(64);
    save_json_atomic(&snapshot.manifest_path, &corrupt).expect("corrupt current manifest");

    let error = load_promotion_snapshot(&model_dir)
        .expect_err("both current validation and gate invalidation must fail");
    let NetdiagError::CombinedFailure {
        primary_context,
        primary,
        secondary_context,
        secondary,
    } = error
    else {
        panic!("expected combined promotion-state failure");
    };
    assert_eq!(primary_context, "promotion model state failed");
    assert_eq!(
        secondary_context,
        "durable invalidation of the stale promotion gate also failed"
    );
    assert!(
        primary.to_string().contains("model bundle hash mismatch"),
        "{primary}"
    );
    let resolved_gate_path = model_dir
        .canonicalize()
        .expect("resolved model directory")
        .join(MODEL_PROMOTION_GATE_FILE_NAME);
    let expected_kind = if cfg!(target_os = "linux") {
        std::io::ErrorKind::IsADirectory
    } else {
        std::io::ErrorKind::PermissionDenied
    };
    assert!(
        matches!(
            secondary.as_ref(),
            NetdiagError::Io { path, source }
                if path == &resolved_gate_path && source.kind() == expected_kind
        ),
        "{secondary:?}"
    );
    assert!(gate_path.is_dir());
}
