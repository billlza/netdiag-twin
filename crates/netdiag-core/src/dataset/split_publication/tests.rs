use super::*;
use crate::error::{AtomicPublishPhase, NetdiagError};
use crate::models::FaultLabel;
use chrono::Utc;
use std::cell::Cell;
use std::collections::BTreeMap;

const STEM: &str = "receipt-first";
const SEED: u64 = 2026;

#[test]
fn existing_receipt_durability_failure_precedes_every_publication() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let output = temp.path().join("split");
    let train_rows = vec![dataset_row()];
    let validation_rows = Vec::new();
    let test_rows = Vec::new();
    let rows = SplitRows {
        train: &train_rows,
        validation: &validation_rows,
        test: &test_rows,
    };
    let manifest = manifest();
    let request = split_request();
    let public_paths = public_paths(&output);
    create_receipt_only_state(&output, rows, &manifest, request);

    let durability_calls = Cell::new(0_usize);
    let partition_publisher_calls = Cell::new(0_usize);
    let error = publish_with_operations(
        &output,
        STEM,
        rows,
        &manifest,
        request,
        |_, target| {
            durability_calls.set(durability_calls.get() + 1);
            Err(injected_sync_failure(target))
        },
        |_, _, _| {
            partition_publisher_calls.set(partition_publisher_calls.get() + 1);
            Err(NetdiagError::InvalidTrace(
                "partition publisher must not run before receipt durability is confirmed"
                    .to_string(),
            ))
        },
    )
    .err()
    .expect("receipt durability failure must stop recovery");

    assert_eq!(durability_calls.get(), 1);
    assert_eq!(partition_publisher_calls.get(), 0);
    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::PublishedButDurabilityUncertain)
    );
    assert!(
        error
            .to_string()
            .contains("injected receipt directory sync failure"),
        "{error}"
    );
    for path in public_paths {
        assert_absent(&path);
    }
    assert!(
        output.join(plan::RECEIPT_FILE_NAME).is_file(),
        "compatible receipt must remain visible for a later retry"
    );
}

#[test]
fn committed_manifest_durability_failure_remains_uncertain() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let output = temp.path().join("split");
    let train_rows = vec![dataset_row()];
    let empty = Vec::new();
    let rows = SplitRows {
        train: &train_rows,
        validation: &empty,
        test: &empty,
    };
    let manifest = manifest();
    let request = split_request();
    publish(
        &output,
        STEM,
        &train_rows,
        &empty,
        &empty,
        &manifest,
        request,
    )
    .expect("initial committed split");

    let durability_calls = Cell::new(0_usize);
    let partition_publisher_calls = Cell::new(0_usize);
    let error = publish_with_operations(
        &output,
        STEM,
        rows,
        &manifest,
        request,
        |_, target| {
            durability_calls.set(durability_calls.get() + 1);
            if target.resolved_path().ends_with(plan::MANIFEST_FILE_NAME) {
                Err(NetdiagError::AtomicPublish {
                    path: target.resolved_path().to_path_buf(),
                    phase: AtomicPublishPhase::PublishedButDurabilityUncertain,
                    source: Box::new(NetdiagError::Io {
                        path: target
                            .resolved_path()
                            .parent()
                            .expect("manifest path has a parent")
                            .to_path_buf(),
                        source: std::io::Error::other(
                            "injected committed manifest directory sync failure",
                        ),
                    }),
                })
            } else {
                Ok(())
            }
        },
        |_, _, _| {
            partition_publisher_calls.set(partition_publisher_calls.get() + 1);
            Err(NetdiagError::InvalidTrace(
                "committed verification must not republish partitions".to_string(),
            ))
        },
    )
    .err()
    .expect("manifest durability failure must remain uncertain");

    assert_eq!(durability_calls.get(), 2);
    assert_eq!(partition_publisher_calls.get(), 0);
    let NetdiagError::AtomicPublish {
        path,
        phase,
        source,
    } = &error
    else {
        panic!("expected manifest publication state: {error}");
    };
    assert_eq!(
        path,
        &output
            .canonicalize()
            .expect("canonical split root")
            .join(plan::MANIFEST_FILE_NAME)
    );
    assert_eq!(*phase, AtomicPublishPhase::PublishedButDurabilityUncertain);
    assert!(matches!(source.as_ref(), NetdiagError::Io { source, .. }
        if source.to_string() == "injected committed manifest directory sync failure"));
}

fn create_receipt_only_state(
    output: &Path,
    rows: SplitRows<'_>,
    manifest: &DatasetManifest,
    request: SplitRequest,
) {
    let root = TrustedDatasetRoot::open(output).expect("trusted split root");
    let targets = SplitTargets::new(&root, STEM, rows.train, rows.validation, rows.test)
        .expect("split targets");
    let receipt = SplitReceipt::new(
        manifest,
        request,
        &targets.train,
        &targets.validation,
        targets.test.as_ref(),
    );

    let claim = recovery::claim(&root, &targets.receipt, &targets.public_targets(), &receipt)
        .expect("create receipt-only transaction state");
    assert!(!claim.was_existing);
    root.finish(Ok(())).expect("validate receipt-only state");
    assert!(targets.receipt.resolved_path().is_file());
    for target in targets.public_targets() {
        assert_absent(target.resolved_path());
    }
}

fn dataset_row() -> DatasetRow {
    DatasetRow {
        line_number: 1,
        line: concat!(
            r#"{"label":"normal","features":{"latency_mean":0.0,"latency_p95":0.0,"#,
            r#""jitter_std":0.0,"loss_rate":0.0,"retrans_rate":0.0,"timeout":0.0,"#,
            r#""retry":0.0,"throughput":0.0,"dns_events":0.0,"tls_events":0.0,"quic":0.0}}"#
        )
        .to_string(),
        label: FaultLabel::Normal,
    }
}

#[cfg(unix)]
#[test]
fn split_publication_stays_on_retained_root_after_parent_replacement() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let output = temp.path().join("split");
    let displaced = temp.path().join("split-displaced");
    let train_rows = vec![dataset_row()];
    let empty = Vec::new();
    let rows = SplitRows {
        train: &train_rows,
        validation: &empty,
        test: &empty,
    };
    let manifest = manifest();
    let request = split_request();
    let replaced = Cell::new(false);

    let error = publish_with_operations(
        &output,
        STEM,
        rows,
        &manifest,
        request,
        |root, target| root.confirm_publication_durability(target),
        |root, plan, partition_rows| {
            if !replaced.replace(true) {
                replace_root_with_sentinels(&output, &displaced);
            }
            recovery::recover_or_publish(root, plan, partition_rows)
        },
    )
    .err()
    .expect("final root identity validation must reject the replacement");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::Published)
    );
    assert_replacement_sentinels(&output);
    assert!(displaced.join(format!("{STEM}-train.jsonl")).is_file());
    assert!(displaced.join("dataset_manifest.json").is_file());

    let retried = publish(
        &displaced,
        STEM,
        &train_rows,
        &empty,
        &empty,
        &manifest,
        request,
    )
    .expect("the retained-root publication must verify from its displaced path");
    assert_eq!(
        Path::new(&retried.output_dir)
            .canonicalize()
            .expect("reported retained root"),
        displaced.canonicalize().expect("displaced retained root")
    );
    assert_replacement_sentinels(&output);
}

#[cfg(unix)]
#[test]
fn committed_split_verification_ignores_replacement_directory_sentinels() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let output = temp.path().join("split");
    let displaced = temp.path().join("split-displaced");
    let train_rows = vec![dataset_row()];
    let empty = Vec::new();
    let rows = SplitRows {
        train: &train_rows,
        validation: &empty,
        test: &empty,
    };
    let manifest = manifest();
    let request = split_request();
    publish(
        &output,
        STEM,
        &train_rows,
        &empty,
        &empty,
        &manifest,
        request,
    )
    .expect("initial committed split");
    let replaced = Cell::new(false);

    let error = publish_with_operations(
        &output,
        STEM,
        rows,
        &manifest,
        request,
        |_, _| {
            if !replaced.replace(true) {
                replace_root_with_sentinels(&output, &displaced);
            }
            Ok(())
        },
        |_, _, _| {
            Err(NetdiagError::InvalidTrace(
                "committed verification must not republish partitions".to_string(),
            ))
        },
    )
    .err()
    .expect("final root identity validation must reject the replacement");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::Published)
    );
    assert_replacement_sentinels(&output);
    publish(
        &displaced,
        STEM,
        &train_rows,
        &empty,
        &empty,
        &manifest,
        request,
    )
    .expect("committed files in the retained root must remain verifiable");
}

#[cfg(unix)]
fn replace_root_with_sentinels(output: &Path, displaced: &Path) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::rename(output, displaced).expect("displace retained root");
    std::fs::create_dir(output).expect("replacement directory");
    std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o700))
        .expect("private replacement directory");
    std::fs::write(
        output.join(format!("{STEM}-train.jsonl")),
        b"train sentinel",
    )
    .expect("train sentinel");
    std::fs::write(output.join("dataset_manifest.json"), b"manifest sentinel")
        .expect("manifest sentinel");
}

#[cfg(unix)]
fn assert_replacement_sentinels(output: &Path) {
    assert_eq!(
        std::fs::read(output.join(format!("{STEM}-train.jsonl"))).expect("train sentinel"),
        b"train sentinel"
    );
    assert_eq!(
        std::fs::read(output.join("dataset_manifest.json")).expect("manifest sentinel"),
        b"manifest sentinel"
    );
}

fn manifest() -> DatasetManifest {
    DatasetManifest {
        schema: "netdiag-dataset/v1".to_string(),
        dataset_id: "receipt-first-test".to_string(),
        hash_sha256: "a".repeat(64),
        rows: 1,
        label_distribution: BTreeMap::from([("normal".to_string(), 1)]),
        sources: vec![format!("split_seed:{SEED}")],
        source_runs: Vec::new(),
        scenario_ids: Vec::new(),
        operator: None,
        label_policy: None,
        min_rows_per_label: None,
        created_at: Utc::now(),
        notes: None,
    }
}

fn split_request() -> SplitRequest {
    SplitRequest {
        seed: SEED,
        stratified: false,
        validation_ratio: 0.0,
        test_ratio: 0.0,
    }
}

fn public_paths(output: &Path) -> [PathBuf; 4] {
    [
        output.join(format!("{STEM}-train.jsonl")),
        output.join(format!("{STEM}-validation.jsonl")),
        output.join(format!("{STEM}-test.jsonl")),
        output.join("dataset_manifest.json"),
    ]
}

fn injected_sync_failure(target: &BoundAtomicFileTarget) -> NetdiagError {
    NetdiagError::AtomicPublish {
        path: target.resolved_path().to_path_buf(),
        phase: AtomicPublishPhase::PublishedButDurabilityUncertain,
        source: Box::new(NetdiagError::Io {
            path: target
                .resolved_path()
                .parent()
                .expect("receipt path has a parent")
                .to_path_buf(),
            source: std::io::Error::other("injected receipt directory sync failure"),
        }),
    }
}

fn assert_absent(path: &Path) {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => panic!("unexpected public output: {}", path.display()),
        Err(error) => panic!("failed to inspect {}: {error}", path.display()),
    }
}
