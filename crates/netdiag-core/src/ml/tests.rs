use super::*;
use crate::storage::{read_json, save_json_atomic};
use std::path::PathBuf;

fn create_private_model_directory(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .expect("private model directory");
    }
    #[cfg(windows)]
    {
        netdiag_platform::open_or_create_trusted_directory_chain(path)
            .expect("private model directory");
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::create_dir_all(path).expect("private model directory");
    }
}

fn row(label: FaultLabel, value: f64) -> FeatureTrainingRow {
    FeatureTrainingRow {
        label,
        features: vec![value; FEATURES.len()],
    }
}

fn dataset_line(label: FaultLabel, value: f64) -> String {
    let features = FEATURES
        .iter()
        .map(|feature| ((*feature).to_string(), value))
        .collect::<BTreeMap<_, _>>();
    serde_json::json!({
        "label": label,
        "features": features,
    })
    .to_string()
}

fn write_feature_dataset(path: &Path, rows_per_label: usize) {
    let mut lines = Vec::new();
    for label in FaultLabel::ALL {
        for idx in 0..rows_per_label {
            lines.push(dataset_line(
                label,
                label.index() as f64 + idx as f64 * 0.01,
            ));
        }
    }
    std::fs::write(path, lines.join("\n")).expect("dataset");
}

fn bundle_manifest(model: &RustMlModel, dataset_hash: &str) -> ModelManifest {
    build_model_manifest(
        model,
        ModelManifestBuild {
            training_source: "test".to_string(),
            training_examples: 1,
            label_distribution: BTreeMap::new(),
            synthetic_fallback: false,
            dataset_hash_sha256: Some(dataset_hash.to_string()),
            training_config: None,
            uncertainty_thresholds: None,
        },
    )
    .expect("bundle manifest")
}

fn write_raw_bound_bundle<T: serde::Serialize>(
    model_dir: &Path,
    model: &T,
    mut manifest: ModelManifest,
) {
    create_private_model_directory(model_dir);
    let model_path = model_dir.join(MODEL_FILE_NAME);
    save_json_atomic(&model_path, model).expect("model json");
    manifest.model_file_hash_sha256 = sha256_file(&model_path).expect("model hash");
    save_json_atomic(model_dir.join(MODEL_MANIFEST_FILE_NAME), &manifest).expect("manifest json");
}

fn read_manifest(path: &Path) -> ModelManifest {
    serde_json::from_value(read_json(path).expect("manifest JSON")).expect("model manifest")
}

#[test]
fn optional_model_identity_missing_query_has_no_filesystem_side_effects() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let before = std::fs::read_dir(temp.path())
        .expect("read empty root")
        .collect::<std::io::Result<Vec<_>>>()
        .expect("empty root entries");

    let identity = load_existing_model_bundle_identity_if_present(&model_dir)
        .expect("missing optional model identity");

    assert!(identity.is_none());
    let after = std::fs::read_dir(temp.path())
        .expect("read root after query")
        .collect::<std::io::Result<Vec<_>>>()
        .expect("root entries after query");
    assert_eq!(after.len(), before.len());
    assert!(matches!(
        std::fs::symlink_metadata(&model_dir),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ));
}

#[test]
fn optional_model_identity_revalidates_tampered_generation_bytes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    rebuild_synthetic_model_bundle(&model_dir).expect("model bundle");
    load_existing_model_bundle_identity_if_present(&model_dir)
        .expect("initial identity")
        .expect("present identity");
    let model_path = current_generation_artifact(&model_dir, MODEL_FILE_NAME);
    std::fs::write(&model_path, b"{}").expect("tamper model generation");

    let error = load_existing_model_bundle_identity_if_present(&model_dir)
        .expect_err("tampered generation must remain visible after a prior load");

    assert!(
        error.to_string().contains("not a valid Rust ML model")
            || error.to_string().contains("hash mismatch"),
        "{error}"
    );
}

fn current_generation_artifact(model_dir: &Path, file_name: &str) -> PathBuf {
    let descriptor =
        read_json(model_dir.join(MODEL_CURRENT_FILE_NAME)).expect("current descriptor");
    let generation = descriptor
        .get("generation")
        .and_then(serde_json::Value::as_str)
        .expect("current generation");
    model_dir
        .join(MODEL_GENERATIONS_DIR_NAME)
        .join(generation)
        .join(file_name)
}

#[test]
fn ml_feature_quality_maps_quic_feature_to_quic_blocked_ratio() {
    let quality = feature_quality_map(&[MetricProvenance {
        field: "quic_blocked_ratio".to_string(),
        quality: MetricQuality::Fallback,
        source: "native_pcap".to_string(),
        reason: "pcap cannot prove QUIC policy blocking".to_string(),
    }]);

    assert_eq!(quality.get("quic"), Some(&MetricQuality::Fallback));
}

#[test]
fn ml_feature_quality_marks_unproven_metrics_missing() {
    let quality = feature_quality_map(&[]);

    assert_eq!(quality.len(), FEATURES.len());
    assert!(
        quality
            .values()
            .all(|quality| *quality == MetricQuality::Missing)
    );
}

#[test]
fn diagnosis_status_serializes_as_standalone_status() {
    assert_eq!(
        serde_json::to_string(&DiagnosisStatus::OutOfDistribution).expect("json"),
        "\"out_of_distribution\""
    );
}

#[test]
fn uncertainty_marks_confident_in_domain_prediction_known() {
    let assessment = assess_uncertainty(
        &[
            Prediction {
                label: FaultLabel::Congestion,
                prob: 0.91,
            },
            Prediction {
                label: FaultLabel::Normal,
                prob: 0.09,
            },
        ],
        &vec![1.0; FEATURES.len()],
        &vec![0.0; FEATURES.len()],
        &BTreeMap::new(),
        None,
    )
    .expect("valid uncertainty assessment");

    assert_eq!(assessment.status, DiagnosisStatus::Known);
}

#[test]
fn uncertainty_marks_low_confidence_prediction_uncertain() {
    let assessment = assess_uncertainty(
        &[
            Prediction {
                label: FaultLabel::Normal,
                prob: 0.32,
            },
            Prediction {
                label: FaultLabel::Congestion,
                prob: 0.30,
            },
            Prediction {
                label: FaultLabel::RandomLoss,
                prob: 0.38,
            },
        ],
        &vec![1.0; FEATURES.len()],
        &vec![0.0; FEATURES.len()],
        &BTreeMap::new(),
        None,
    )
    .expect("valid uncertainty assessment");

    assert_eq!(assessment.status, DiagnosisStatus::Uncertain);
    assert!(
        assessment
            .reason_codes
            .contains(&UncertaintyReasonCode::Ambiguous)
    );
    assert!(
        assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("max probability")),
        "{:?}",
        assessment.reasons
    );
}

#[test]
fn uncertainty_marks_extreme_feature_distance_ood() {
    let assessment = assess_uncertainty(
        &[
            Prediction {
                label: FaultLabel::Normal,
                prob: 0.99,
            },
            Prediction {
                label: FaultLabel::Congestion,
                prob: 0.01,
            },
        ],
        &vec![1.0; FEATURES.len()],
        &vec![9.0; FEATURES.len()],
        &BTreeMap::new(),
        None,
    )
    .expect("valid uncertainty assessment");

    assert_eq!(assessment.status, DiagnosisStatus::OutOfDistribution);
    assert!(
        assessment
            .reason_codes
            .contains(&UncertaintyReasonCode::ExtremeFeatureDistance)
    );
}

#[test]
fn uncertainty_marks_missing_feature_quality_as_insufficient_evidence() {
    let mut feature_quality = BTreeMap::new();
    feature_quality.insert("latency_p95".to_string(), MetricQuality::Missing);
    let assessment = assess_uncertainty(
        &[
            Prediction {
                label: FaultLabel::Congestion,
                prob: 0.99,
            },
            Prediction {
                label: FaultLabel::Normal,
                prob: 0.01,
            },
        ],
        &vec![1.0; FEATURES.len()],
        &vec![0.0; FEATURES.len()],
        &feature_quality,
        None,
    )
    .expect("valid uncertainty assessment");

    assert_eq!(assessment.status, DiagnosisStatus::Uncertain);
    assert!(
        assessment
            .reason_codes
            .contains(&UncertaintyReasonCode::InsufficientEvidence)
    );
}

#[test]
fn stratified_split_keeps_each_label_in_training() {
    let mut rows = Vec::new();
    for label in FaultLabel::ALL {
        rows.push(row(label, label.index() as f64));
        rows.push(row(label, label.index() as f64 + 0.5));
    }

    let (training, validation) = partition_training_rows(
        &rows,
        TrainingOptions {
            validation_split: 0.5,
            shuffle_seed: Some(2026),
            stratified: true,
            min_rows_per_label: 0,
        },
    );

    assert_eq!(training.len(), FaultLabel::ALL.len());
    assert_eq!(validation.len(), FaultLabel::ALL.len());
    for label in FaultLabel::ALL {
        assert!(training.iter().any(|row| row.label == label), "{label}");
        assert!(validation.iter().any(|row| row.label == label), "{label}");
    }
}

#[test]
fn evaluation_reports_dense_confusion_and_per_label_metrics() {
    let mut confusion = dense_confusion_matrix();
    *confusion
        .entry("congestion".to_string())
        .or_default()
        .entry("congestion".to_string())
        .or_default() = 2;
    *confusion
        .entry("congestion".to_string())
        .or_default()
        .entry("normal".to_string())
        .or_default() = 1;

    let metrics = label_metrics(FaultLabel::Congestion, &confusion);

    assert_eq!(confusion.len(), FaultLabel::ALL.len());
    assert_eq!(metrics.support, 3);
    assert_eq!(metrics.precision, 1.0);
    assert_eq!(metrics.recall, 0.6667);
    assert_eq!(metrics.f1, 0.8);
}

#[test]
fn evaluation_marks_missing_validation_labels_degraded() {
    let training = vec![
        row(FaultLabel::Normal, 10.0),
        row(FaultLabel::Congestion, 200.0),
    ];
    let model = train_model_from_feature_rows(&training).expect("model");
    let expected = [FaultLabel::Normal, FaultLabel::Congestion]
        .into_iter()
        .collect::<BTreeSet<_>>();

    let evaluation =
        evaluate_model(&model, &[row(FaultLabel::Normal, 12.0)], &expected).expect("eval");

    assert!(evaluation.degraded, "{:?}", evaluation.warnings);
    assert_eq!(evaluation.missing_validation_labels, vec!["congestion"]);
    assert!(
        evaluation
            .warnings
            .iter()
            .any(|warning| warning.contains("validation set has no congestion examples")),
        "{:?}",
        evaluation.warnings
    );
}

#[test]
fn training_gate_checks_training_split_distribution() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_feature_dataset(&dataset, 2);

    let err = train_model_from_jsonl_with_options(
        &dataset,
        temp.path().join("model"),
        TrainingOptions {
            validation_split: 0.5,
            shuffle_seed: Some(2026),
            stratified: true,
            min_rows_per_label: 2,
        },
    )
    .expect_err("training split should fail gate");

    assert!(
        err.to_string()
            .contains("training split label normal has 1 rows"),
        "{err}"
    );
}

#[test]
fn training_gate_passes_when_training_split_keeps_enough_rows() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_feature_dataset(&dataset, 3);

    let manifest = train_model_from_jsonl_with_options(
        &dataset,
        temp.path().join("model"),
        TrainingOptions {
            validation_split: 0.34,
            shuffle_seed: Some(2026),
            stratified: true,
            min_rows_per_label: 2,
        },
    )
    .expect("training should pass");

    let gate = manifest.training_gate.expect("gate");
    assert!(gate.passed, "{:?}", gate.failures);
    assert_eq!(gate.dataset_rows, FaultLabel::ALL.len() * 3);
    assert_eq!(gate.training_rows, FaultLabel::ALL.len() * 2);
    assert_eq!(gate.validation_rows, FaultLabel::ALL.len());
    assert!(manifest.uncertainty_thresholds.is_some());
}

#[test]
fn training_options_reject_invalid_validation_split_values() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_feature_dataset(&dataset, 2);

    for invalid_split in [f64::NAN, -0.1, 0.81, f64::INFINITY] {
        let err = train_model_from_jsonl_with_options(
            &dataset,
            temp.path().join(format!("model-{invalid_split:?}")),
            TrainingOptions {
                validation_split: invalid_split,
                shuffle_seed: Some(2026),
                stratified: true,
                min_rows_per_label: 1,
            },
        )
        .expect_err("invalid validation_split must fail fast");

        assert!(err.to_string().contains("validation_split"), "{err}");
    }
}

#[test]
fn cached_model_with_bad_scaler_dimensions_is_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    create_private_model_directory(&model_dir);
    let mut model = train_default_model().expect("model");
    let manifest = bundle_manifest(&model, "dataset");
    model.means.pop();
    write_raw_bound_bundle(&model_dir, &model, manifest);

    let err = load_or_train_model(&model_dir).expect_err("bad cache should fail");

    assert!(err.to_string().contains("stored model means"), "{err}");
}

#[test]
fn cached_model_manifest_must_match_model_shape() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    create_private_model_directory(&model_dir);
    let model = train_default_model().expect("model");
    let mut manifest = build_model_manifest(
        &model,
        ModelManifestBuild {
            training_source: "test".to_string(),
            training_examples: 1,
            label_distribution: BTreeMap::new(),
            synthetic_fallback: false,
            dataset_hash_sha256: None,
            training_config: None,
            uncertainty_thresholds: None,
        },
    )
    .expect("manifest");
    manifest.feature_count = FEATURES.len() + 1;
    write_raw_bound_bundle(&model_dir, &model, manifest);

    let err = load_or_train_model(&model_dir).expect_err("bad manifest should fail");

    assert!(
        err.to_string().contains("model manifest feature_count"),
        "{err}"
    );
}

#[test]
fn cached_model_with_bad_intercept_shape_is_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    create_private_model_directory(&model_dir);
    let model = train_default_model().expect("model");
    let manifest = bundle_manifest(&model, "dataset");
    let mut value = serde_json::to_value(&model).expect("model value");
    let intercept = value
        .get_mut("model")
        .and_then(|model| model.get_mut("intercept"))
        .expect("intercept");
    intercept["dim"] = serde_json::json!([FaultLabel::ALL.len() - 1]);
    intercept["data"]
        .as_array_mut()
        .expect("intercept data")
        .pop();
    write_raw_bound_bundle(&model_dir, &value, manifest);

    let err = load_or_train_model(&model_dir).expect_err("bad cache should fail");

    assert!(err.to_string().contains("stored model intercept"), "{err}");
}

#[test]
fn model_bundle_lock_is_reentrant_and_serializes_bundle_writes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let model_a = train_default_model().expect("model A");
    let manifest_a = bundle_manifest(&model_a, "dataset-a");
    write_model_bundle(&model_dir, &model_a, &manifest_a).expect("initial bundle");

    let mut model_b = model_a.clone();
    model_b.means[0] += 10.0;
    let manifest_b = bundle_manifest(&model_b, "dataset-b");
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    let writer = with_model_bundle_lock(&model_dir, || {
        with_model_bundle_lock(&model_dir, || load_existing_model(&model_dir).map(drop))?;

        let writer_model_dir = model_dir.clone();
        let writer = std::thread::spawn(move || {
            started_tx.send(()).expect("writer started signal");
            let result = write_model_bundle(&writer_model_dir, &model_b, &manifest_b);
            done_tx.send(()).expect("writer done signal");
            result
        });
        started_rx.recv().expect("writer started");
        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_millis(150))
                .is_err(),
            "bundle writer must wait for the active reader lock"
        );

        let current = load_existing_model_bundle_snapshot(&model_dir)?;
        assert_eq!(
            current.manifest.dataset_hash_sha256.as_deref(),
            Some("dataset-a")
        );
        assert_eq!(current.model.means[0], model_a.means[0]);
        Ok(writer)
    })
    .expect("locked read");

    writer
        .join()
        .expect("bundle writer thread")
        .expect("bundle write");
    done_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("writer completed after lock release");
    let final_snapshot = load_existing_model_bundle_snapshot(&model_dir).expect("final snapshot");
    assert_eq!(
        final_snapshot.manifest.dataset_hash_sha256.as_deref(),
        Some("dataset-b")
    );
    assert_eq!(final_snapshot.model.means[0], model_a.means[0] + 10.0);
}

#[test]
fn inference_rejects_missing_model_manifest() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let model = train_default_model().expect("model");
    write_model_bundle(&model_dir, &model, &bundle_manifest(&model, "dataset")).expect("bundle");
    let manifest_path = current_generation_artifact(&model_dir, MODEL_MANIFEST_FILE_NAME);
    std::fs::remove_file(&manifest_path).expect("remove manifest");

    let error =
        infer_with_quality_from_existing_model_dir(&[], "missing-manifest", &model_dir, &[])
            .expect_err("incomplete bundle must fail inference");

    assert!(error.to_string().contains("generation manifest"), "{error}");
    assert!(
        error
            .to_string()
            .contains(&manifest_path.display().to_string()),
        "{error}"
    );
}

#[test]
fn inference_rejects_corrupt_model_manifest() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let model = train_default_model().expect("model");
    write_model_bundle(&model_dir, &model, &bundle_manifest(&model, "dataset")).expect("bundle");
    let manifest_path = current_generation_artifact(&model_dir, MODEL_MANIFEST_FILE_NAME);
    std::fs::write(&manifest_path, b"{not-json").expect("corrupt manifest");

    let error =
        infer_with_quality_from_existing_model_dir(&[], "corrupt-manifest", &model_dir, &[])
            .expect_err("corrupt bundle must fail inference");

    assert!(
        error
            .to_string()
            .contains(&manifest_path.display().to_string())
    );
    assert!(error.to_string().contains("is invalid"), "{error}");
}

#[test]
fn model_bundle_manifest_binds_exact_model_bytes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let model = train_default_model().expect("model");
    let persisted = write_model_bundle(&model_dir, &model, &bundle_manifest(&model, "dataset"))
        .expect("bundle");

    assert_eq!(persisted.schema_version, MODEL_MANIFEST_SCHEMA);
    let snapshot = load_existing_model_bundle_snapshot(&model_dir).expect("bound bundle");
    assert_eq!(
        persisted.model_file_hash_sha256,
        sha256_file(&snapshot.manifest_path.with_file_name(MODEL_FILE_NAME)).expect("model hash")
    );
}

#[test]
fn legacy_v1_model_bundle_is_rejected_with_explicit_migration_boundary() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let model = train_default_model().expect("model");
    write_raw_bound_bundle(&model_dir, &model, bundle_manifest(&model, "dataset"));
    let manifest_path = model_dir.join(MODEL_MANIFEST_FILE_NAME);
    let mut manifest = read_manifest(&manifest_path);
    manifest.schema_version = "netdiag-model-manifest/v1".to_string();
    manifest.model_file_hash_sha256.clear();
    save_json_atomic(&manifest_path, &manifest).expect("legacy manifest");

    let error = load_existing_model_bundle_snapshot(&model_dir)
        .expect_err("legacy bundle must fail closed");

    assert!(
        error
            .to_string()
            .contains("unsupported model manifest schema")
    );
    assert!(error.to_string().contains(MODEL_MANIFEST_SCHEMA));
    assert!(error.to_string().contains("retrain or explicitly rebuild"));
}

#[test]
fn stale_top_level_files_are_not_treated_as_current_generation_truth() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let model_a = train_default_model().expect("model A");
    write_model_bundle(
        &model_dir,
        &model_a,
        &bundle_manifest(&model_a, "dataset-a"),
    )
    .expect("bundle A");
    let mut model_b = model_a.clone();
    model_b.means[0] += 7.0;

    save_json_atomic(model_dir.join(MODEL_FILE_NAME), &model_b).expect("stale top-level model");
    let snapshot = load_existing_model_bundle_snapshot(&model_dir).expect("current generation");
    assert_eq!(snapshot.model.means[0], model_a.means[0]);
}

#[test]
fn tampered_manifest_model_hash_is_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let model = train_default_model().expect("model");
    write_model_bundle(&model_dir, &model, &bundle_manifest(&model, "dataset")).expect("bundle");
    let manifest_path = current_generation_artifact(&model_dir, MODEL_MANIFEST_FILE_NAME);
    let mut manifest = read_manifest(&manifest_path);
    manifest.model_file_hash_sha256 = "0".repeat(64);
    save_json_atomic(&manifest_path, &manifest).expect("tampered manifest");

    let error = load_existing_model_bundle_snapshot(&model_dir)
        .expect_err("tampered manifest must fail closed");
    assert!(error.to_string().contains("model bundle hash mismatch"));
}

#[test]
fn incomplete_bundle_is_not_silently_repaired_by_fallback_loading() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let model = train_default_model().expect("model");
    create_private_model_directory(&model_dir);
    save_json_atomic(model_dir.join(MODEL_FILE_NAME), &model).expect("orphaned model");

    let error =
        load_or_train_model(&model_dir).expect_err("incomplete bundle must not be repaired");
    assert!(error.to_string().contains("model bundle is incomplete"));
    assert!(!model_dir.join(MODEL_MANIFEST_FILE_NAME).exists());
}

#[test]
fn concurrent_snapshot_reads_never_observe_mixed_bundle_generations() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let model_a = train_default_model().expect("model A");
    write_model_bundle(
        &model_dir,
        &model_a,
        &bundle_manifest(&model_a, "dataset-a"),
    )
    .expect("bundle A");
    let mut model_b = model_a.clone();
    model_b.means[0] += 11.0;
    let manifest_b = bundle_manifest(&model_b, "dataset-b");
    let writer_dir = model_dir.clone();
    let writer = std::thread::spawn(move || {
        for _ in 0..8 {
            write_model_bundle(&writer_dir, &model_b, &manifest_b).expect("bundle B");
            write_model_bundle(
                &writer_dir,
                &model_a,
                &bundle_manifest(&model_a, "dataset-a"),
            )
            .expect("bundle A");
        }
    });

    for _ in 0..32 {
        let snapshot = load_existing_model_bundle_snapshot(&model_dir).expect("snapshot");
        assert_eq!(
            snapshot.manifest.model_file_hash_sha256,
            snapshot.model_file_hash_sha256
        );
        assert!(matches!(
            snapshot.manifest.dataset_hash_sha256.as_deref(),
            Some("dataset-a" | "dataset-b")
        ));
    }
    writer.join().expect("writer");
}
