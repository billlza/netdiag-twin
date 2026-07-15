#![cfg(windows)]

use netdiag_core::benchmark::{BenchmarkOptions, run_benchmark};
use netdiag_core::dataset::{
    DatasetManifestMetadata, DatasetRegisterOptions, register_dataset_jsonl, split_dataset_jsonl,
};
use netdiag_core::error::{AtomicPublishPhase, NetdiagError};
use netdiag_core::lab::{LabRunOptions, run_lab_scenario};
use netdiag_core::ml::rebuild_synthetic_model_bundle;
use netdiag_core::perf_budget::run_perf_measurements;
use netdiag_core::pilot::{PilotOptions, run_pilot};
use netdiag_core::pipeline::diagnose_file;

#[test]
fn pipeline_run_publication_fails_before_input_or_artifact_io() {
    let root = tempfile::tempdir().expect("temporary root");
    let artifact_root = root.path().join("artifacts-that-must-not-exist");
    let missing_input = root.path().join("input-that-must-not-be-read.csv");

    let error = diagnose_file(&missing_input, &artifact_root, None)
        .expect_err("unsupported directory publication must fail closed first");

    let NetdiagError::AtomicPublish {
        path,
        phase,
        source,
    } = error
    else {
        panic!("expected typed atomic publication failure");
    };
    assert_eq!(path, artifact_root.join("runs").join("pending-run"));
    assert_eq!(phase, AtomicPublishPhase::NotPublished);
    assert!(matches!(
        source.as_ref(),
        NetdiagError::PlatformAtomicPublication { source, .. }
            if source.kind() == std::io::ErrorKind::Unsupported
    ));
    assert!(
        !artifact_root.exists(),
        "pipeline capability gate must not create artifact directories"
    );
}

#[test]
fn lab_run_gate_precedes_scenario_and_artifact_io() {
    let root = tempfile::tempdir().expect("temporary root");
    let artifact_root = root.path().join("lab-artifacts-that-must-not-exist");
    let error = run_lab_scenario(
        root.path().join("missing-scenario.yaml"),
        LabRunOptions {
            artifacts: artifact_root.clone(),
        },
    )
    .expect_err("lab run must fail at the publication capability gate");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert!(!artifact_root.exists());
}

#[test]
fn pilot_run_gate_precedes_manifest_and_artifact_io() {
    let root = tempfile::tempdir().expect("temporary root");
    let artifact_root = root.path().join("pilot-artifacts-that-must-not-exist");
    let error = run_pilot(
        root.path().join("missing-pilot.yaml"),
        PilotOptions {
            artifacts: artifact_root.clone(),
            allow_active: false,
            allow_adapter_execution: false,
        },
    )
    .expect_err("pilot run must fail at the publication capability gate");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert!(!artifact_root.exists());
}

#[test]
fn benchmark_gate_precedes_artifact_and_report_directory_creation() {
    let root = tempfile::tempdir().expect("temporary root");
    let artifacts = root.path().join("benchmark-artifacts-that-must-not-exist");
    let output = root.path().join("benchmark-output-that-must-not-exist");

    let error = run_benchmark(BenchmarkOptions {
        artifacts: artifacts.clone(),
        output: output.clone(),
        suite: None,
        model_dir: None,
    })
    .expect_err("benchmark must fail at the publication capability gate");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert!(!artifacts.exists());
    assert!(!output.exists());
}

#[test]
fn performance_gate_precedes_artifact_directory_creation() {
    let root = tempfile::tempdir().expect("temporary root");
    let artifacts = root.path().join("perf-artifacts-that-must-not-exist");

    let error = run_perf_measurements(&artifacts)
        .expect_err("performance measurement must fail at the publication capability gate");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert!(!artifacts.exists());
}

#[test]
fn model_rebuild_fails_before_creating_the_model_directory() {
    let root = tempfile::tempdir().expect("temporary root");
    let model_dir = root.path().join("model-that-must-not-exist");

    let error = rebuild_synthetic_model_bundle(&model_dir)
        .expect_err("model publication must fail closed before training or writes");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert!(!model_dir.exists());
}

#[test]
fn dataset_split_fails_before_reading_input_or_creating_output() {
    let root = tempfile::tempdir().expect("temporary root");
    let output_dir = root.path().join("split-output-that-must-not-exist");

    let error = split_dataset_jsonl(
        root.path().join("missing-input.jsonl"),
        &output_dir,
        true,
        2026,
        0.2,
        0.1,
    )
    .expect_err("dataset split publication must fail closed first");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert!(!output_dir.exists());
}

#[test]
fn dataset_registration_fails_before_reading_input_or_creating_artifacts() {
    let root = tempfile::tempdir().expect("temporary root");
    let artifacts = root
        .path()
        .join("registration-artifacts-that-must-not-exist");

    let error = register_dataset_jsonl(
        root.path().join("missing-input.jsonl"),
        DatasetRegisterOptions {
            artifacts: artifacts.clone(),
            metadata: DatasetManifestMetadata::default(),
        },
    )
    .expect_err("dataset registration publication must fail closed first");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert!(!artifacts.exists());
}
