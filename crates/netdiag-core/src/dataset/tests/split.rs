use super::super::*;
use super::feature_payload;

#[test]
fn stratified_split_warns_when_validation_lacks_label() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("small-feedback.jsonl");
    std::fs::write(
        &dataset,
        [
            serde_json::json!({
                "label": "normal",
                "features": feature_payload(10.0)
            })
            .to_string(),
            serde_json::json!({
                "label": "normal",
                "features": feature_payload(11.0)
            })
            .to_string(),
            serde_json::json!({
                "label": "tls_failure",
                "features": feature_payload(80.0)
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write dataset");

    let report = split_dataset_jsonl(&dataset, temp.path().join("splits"), true, 2026, 0.5, 0.0)
        .expect("split");

    assert!(
        report
            .split_warnings
            .iter()
            .any(|warning| warning.contains("tls_failure") && warning.contains("validation")),
        "{:?}",
        report.split_warnings
    );
}

#[test]
fn dataset_split_rejects_invalid_ratios_without_creating_outputs() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    std::fs::write(
        &dataset,
        [
            serde_json::json!({
                "label": "normal",
                "features": feature_payload(10.0)
            })
            .to_string(),
            serde_json::json!({
                "label": "congestion",
                "features": feature_payload(200.0)
            })
            .to_string(),
        ]
        .join("\n"),
    )
    .expect("write dataset");

    for (validation_ratio, test_ratio) in [
        (f64::NAN, 0.0),
        (f64::INFINITY, 0.0),
        (f64::NEG_INFINITY, 0.0),
        (-0.01, 0.0),
        (1.0, 0.0),
        (1.01, 0.0),
        (0.0, f64::NAN),
        (0.0, f64::INFINITY),
        (0.0, -0.01),
        (0.0, 1.0),
        (0.0, 1.01),
        (0.4, 0.6),
        (0.8, 0.3),
    ] {
        let output = temp
            .path()
            .join(format!("invalid-{validation_ratio:?}-{test_ratio:?}"));
        let error =
            split_dataset_jsonl(&dataset, &output, false, 2026, validation_ratio, test_ratio)
                .expect_err("invalid ratios must fail closed");
        assert!(error.to_string().contains("dataset split"), "{error}");
        assert!(!output.exists(), "invalid ratios created output directory");
    }
}

#[test]
fn dataset_split_accepts_zero_and_high_valid_ratio_boundaries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    std::fs::write(
        &dataset,
        (0..10)
            .map(|index| {
                serde_json::json!({
                    "label": "normal",
                    "features": feature_payload(10.0 + f64::from(index))
                })
                .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .expect("write dataset");

    let zero = split_dataset_jsonl(&dataset, temp.path().join("zero"), false, 2026, 0.0, 0.0)
        .expect("zero ratios");
    assert_eq!(zero.train.rows, 10);
    assert_eq!(zero.validation.rows, 0);
    assert!(zero.test.is_none());

    let high = split_dataset_jsonl(&dataset, temp.path().join("high"), false, 2026, 0.79, 0.1)
        .expect("high but valid combined ratio");
    assert_eq!(
        high.train.rows + high.validation.rows + high.test.unwrap().rows,
        10
    );
}

#[test]
fn dataset_split_refuses_overwrite_and_hashes_published_bytes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_split_fixture(&dataset, 8);
    let output = temp.path().join("split");
    let report =
        split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25).expect("initial split");
    let published = [
        (PathBuf::from(&report.train.path), report.train.hash_sha256),
        (
            PathBuf::from(&report.validation.path),
            report.validation.hash_sha256,
        ),
        {
            let test = report.test.expect("test partition");
            (PathBuf::from(test.path), test.hash_sha256)
        },
    ];
    let original = published
        .iter()
        .map(|(path, _)| std::fs::read(path).expect("partition bytes"))
        .collect::<Vec<_>>();
    for (path, expected) in &published {
        let actual = crate::storage::sha256_stable_regular_file_bounded(path, 128 * 1024 * 1024)
            .expect("stable hash")
            .expect("partition exists");
        assert_eq!(&actual, expected);
    }

    let error = split_dataset_jsonl(&dataset, &output, false, 2027, 0.25, 0.25)
        .expect_err("existing split must not be replaced");
    assert!(error.to_string().contains("receipt conflicts"), "{error}");
    for ((path, _), bytes) in published.iter().zip(original) {
        assert_eq!(std::fs::read(path).expect("preserved partition"), bytes);
    }
}

#[test]
fn concurrent_dataset_split_has_one_complete_winner() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_split_fixture(&dataset, 8);
    let output = temp.path().join("concurrent-split");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles = [2026_u64, 2027_u64].map(|seed| {
        let dataset = dataset.clone();
        let output = output.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            split_dataset_jsonl(dataset, output, false, seed, 0.25, 0.25)
        })
    });
    let results = handles.map(|handle| handle.join().expect("split thread"));

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let winner = results.into_iter().find_map(Result::ok).expect("winner");
    assert!(Path::new(&winner.train.path).is_file());
    assert!(Path::new(&winner.validation.path).is_file());
    assert!(Path::new(&winner.test.expect("test partition").path).is_file());
    assert!(Path::new(&winner.manifest_path).is_file());
}

#[test]
fn dataset_split_recovers_every_manifest_last_crash_window() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_split_fixture(&dataset, 8);

    for retained_partitions in 0..=3 {
        let output = temp.path().join(format!("crash-{retained_partitions}"));
        let first =
            split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25).expect("initial split");
        let partitions = [
            PathBuf::from(&first.train.path),
            PathBuf::from(&first.validation.path),
            PathBuf::from(&first.test.expect("test partition").path),
        ];
        let expected = partitions
            .iter()
            .map(|path| std::fs::read(path).expect("initial partition bytes"))
            .collect::<Vec<_>>();

        std::fs::remove_file(&first.manifest_path).expect("simulate pre-manifest crash");
        for path in partitions.iter().skip(retained_partitions) {
            std::fs::remove_file(path).expect("remove unpublished partition");
        }

        let recovered = split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25)
            .expect("matching transaction must recover");

        assert!(Path::new(&recovered.manifest_path).is_file());
        assert!(output.join(".dataset-split-transaction.json").is_file());
        for (path, expected) in partitions.iter().zip(&expected) {
            assert_eq!(
                std::fs::read(path).expect("recovered partition bytes"),
                *expected
            );
        }
    }
}

#[test]
fn committed_manifest_response_loss_or_durability_uncertainty_is_idempotent() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_split_fixture(&dataset, 8);
    let output = temp.path().join("committed-retry");
    let first =
        split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25).expect("initial split");
    let original_manifest_bytes =
        std::fs::read(&first.manifest_path).expect("committed manifest bytes");
    std::thread::sleep(std::time::Duration::from_millis(2));

    let recovered = split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25)
        .expect("committed response-loss state must be idempotent");

    assert_eq!(recovered.manifest, first.manifest);
    assert_eq!(
        std::fs::read(&recovered.manifest_path).expect("manifest after retry"),
        original_manifest_bytes
    );
    assert_eq!(recovered.train.hash_sha256, first.train.hash_sha256);
    assert_eq!(
        recovered.validation.hash_sha256,
        first.validation.hash_sha256
    );
    assert_eq!(
        recovered.test.expect("recovered test").hash_sha256,
        first.test.expect("initial test").hash_sha256
    );
}

#[test]
fn committed_manifest_never_repairs_a_missing_partition() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_split_fixture(&dataset, 8);
    let output = temp.path().join("missing-committed-partition");
    let first =
        split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25).expect("initial split");
    let missing = PathBuf::from(first.validation.path);
    std::fs::remove_file(&missing).expect("remove committed partition");

    let error = split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25)
        .expect_err("committed state must not be repaired");

    assert!(
        error.to_string().contains("partition is missing"),
        "{error}"
    );
    assert!(!missing.exists(), "retry recreated a committed partition");
}

#[test]
fn tampered_or_corrupt_committed_manifest_is_preserved_and_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_split_fixture(&dataset, 8);

    for corrupt in [false, true] {
        let output = temp.path().join(format!("bad-manifest-{corrupt}"));
        let first =
            split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25).expect("initial split");
        let replacement = if corrupt {
            b"{not-json".to_vec()
        } else {
            let mut manifest = first.manifest.clone();
            manifest.notes = Some("tampered committed manifest".to_string());
            serde_json::to_vec_pretty(&manifest).expect("tampered manifest")
        };
        std::fs::write(&first.manifest_path, &replacement).expect("replace manifest");

        split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25)
            .expect_err("bad committed manifest must fail closed");

        assert_eq!(
            std::fs::read(&first.manifest_path).expect("preserved bad manifest"),
            replacement
        );
    }
}

#[test]
fn committed_manifest_with_unknown_fields_is_preserved_and_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_split_fixture(&dataset, 8);
    let output = temp.path().join("unknown-manifest-field");
    let first =
        split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25).expect("initial split");
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&first.manifest_path).expect("committed manifest bytes"),
    )
    .expect("valid committed manifest");
    manifest
        .as_object_mut()
        .expect("manifest object")
        .insert("unsupported_extension".to_string(), serde_json::json!(true));
    let replacement = serde_json::to_vec_pretty(&manifest).expect("extended manifest");
    std::fs::write(&first.manifest_path, &replacement).expect("replace manifest");

    let error = split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25)
        .expect_err("unknown committed manifest fields must fail closed");

    let message = error.to_string();
    assert!(
        message.contains("does not match the required JSON schema"),
        "{message}"
    );
    assert!(!message.contains("unsupported_extension"), "{message}");
    assert_eq!(
        std::fs::read(&first.manifest_path).expect("preserved manifest"),
        replacement
    );
}

#[test]
fn receiptless_existing_manifest_is_never_adopted() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_split_fixture(&dataset, 8);
    let output = temp.path().join("receiptless-manifest");
    std::fs::create_dir(&output).expect("output directory");
    let manifest = output.join("dataset_manifest.json");
    let original = b"user-owned-manifest";
    std::fs::write(&manifest, original).expect("user manifest");

    let error = split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25)
        .expect_err("receiptless manifest must remain unowned");

    assert!(
        error.to_string().contains("unowned existing output"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(manifest).expect("preserved manifest"),
        original
    );
    assert!(!output.join(".dataset-split-transaction.json").exists());
}

#[test]
fn forged_split_receipt_fails_closed_without_touching_owned_partitions() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_split_fixture(&dataset, 8);
    let output = temp.path().join("forged-receipt");
    let first =
        split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25).expect("initial split");
    let partition_paths = [
        PathBuf::from(&first.train.path),
        PathBuf::from(&first.validation.path),
        PathBuf::from(&first.test.expect("test partition").path),
    ];
    let original = partition_paths
        .iter()
        .map(|path| std::fs::read(path).expect("partition bytes"))
        .collect::<Vec<_>>();
    std::fs::remove_file(&first.manifest_path).expect("simulate crash");
    let receipt_path = output.join(".dataset-split-transaction.json");
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).expect("receipt"))
            .expect("valid receipt JSON");
    receipt["request"]["seed"] = serde_json::json!(2027);
    std::fs::write(
        &receipt_path,
        serde_json::to_vec_pretty(&receipt).expect("forged receipt JSON"),
    )
    .expect("forge receipt");

    let error = split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25)
        .expect_err("forged receipt must fail closed");

    assert!(error.to_string().contains("receipt is invalid"), "{error}");
    assert!(!Path::new(&first.manifest_path).exists());
    for (path, expected) in partition_paths.iter().zip(&original) {
        assert_eq!(
            std::fs::read(path).expect("partition after conflict"),
            *expected,
            "partition changed: {}",
            path.display()
        );
    }
}

#[test]
fn split_receipt_manifest_with_unknown_fields_is_preserved_and_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_split_fixture(&dataset, 8);
    let output = temp.path().join("unknown-receipt-manifest-field");
    let first =
        split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25).expect("initial split");
    let partition_paths = [
        PathBuf::from(&first.train.path),
        PathBuf::from(&first.validation.path),
        PathBuf::from(&first.test.expect("test partition").path),
    ];
    let original_partitions = partition_paths
        .iter()
        .map(|path| std::fs::read(path).expect("partition bytes"))
        .collect::<Vec<_>>();
    std::fs::remove_file(&first.manifest_path).expect("simulate pre-manifest crash");
    let receipt_path = output.join(".dataset-split-transaction.json");
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).expect("receipt"))
            .expect("valid receipt");
    receipt["manifest"]
        .as_object_mut()
        .expect("receipt manifest object")
        .insert("unsupported_extension".to_string(), serde_json::json!(true));
    let replacement = serde_json::to_vec_pretty(&receipt).expect("extended receipt");
    std::fs::write(&receipt_path, &replacement).expect("replace receipt");

    let error = split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25)
        .expect_err("unknown receipt manifest fields must fail closed");

    let message = error.to_string();
    assert!(
        message.contains("does not match the required JSON schema"),
        "{message}"
    );
    assert!(!message.contains("unsupported_extension"), "{message}");
    assert_eq!(
        std::fs::read(&receipt_path).expect("preserved receipt"),
        replacement
    );
    assert!(!Path::new(&first.manifest_path).exists());
    for (path, expected) in partition_paths.iter().zip(original_partitions) {
        assert_eq!(std::fs::read(path).expect("preserved partition"), expected);
    }
}

#[test]
fn tampered_owned_partition_is_never_replaced_during_recovery() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_split_fixture(&dataset, 8);
    let output = temp.path().join("tampered-partition");
    let first =
        split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25).expect("initial split");
    std::fs::remove_file(&first.manifest_path).expect("simulate crash");
    let train_path = PathBuf::from(first.train.path);
    let tampered = b"{\"label\":\"normal\",\"features\":{}}\n";
    std::fs::write(&train_path, tampered).expect("tamper partition");

    let error = split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25)
        .expect_err("tampered owned partition must fail closed");

    assert!(
        error
            .to_string()
            .contains("does not match its transaction receipt"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(train_path).expect("tampered bytes preserved"),
        tampered
    );
    assert!(!Path::new(&first.manifest_path).exists());
}

#[test]
fn malformed_or_oversized_split_receipt_creates_no_public_outputs() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_split_fixture(&dataset, 8);

    for (name, oversized) in [("malformed", false), ("oversized", true)] {
        let output = temp.path().join(name);
        std::fs::create_dir(&output).expect("output directory");
        let receipt = output.join(".dataset-split-transaction.json");
        if oversized {
            let file = std::fs::File::create(&receipt).expect("oversized receipt");
            file.set_len(256 * 1024 + 1).expect("extend receipt");
        } else {
            std::fs::write(&receipt, b"{not-json").expect("malformed receipt");
        }

        split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25)
            .expect_err("invalid receipt must fail closed");

        assert_no_public_split_outputs(&output, "feedback");
    }
}

#[cfg(unix)]
#[test]
fn symlinked_split_receipt_creates_no_public_outputs() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_split_fixture(&dataset, 8);
    let output = temp.path().join("symlinked-receipt");
    std::fs::create_dir(&output).expect("output directory");
    let outside = temp.path().join("outside.json");
    std::fs::write(&outside, b"{}").expect("outside receipt");
    symlink(&outside, output.join(".dataset-split-transaction.json")).expect("receipt symlink");

    split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25)
        .expect_err("symlink receipt must fail closed");

    assert_no_public_split_outputs(&output, "feedback");
}

#[test]
fn unowned_partition_is_never_claimed_even_when_its_bytes_match() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    write_split_fixture(&dataset, 8);
    let reference_output = temp.path().join("reference");
    let reference = split_dataset_jsonl(&dataset, &reference_output, false, 2026, 0.25, 0.25)
        .expect("reference split");
    let output = temp.path().join("unowned");
    std::fs::create_dir(&output).expect("output directory");
    let unowned = output.join("feedback-train.jsonl");
    std::fs::copy(&reference.train.path, &unowned).expect("matching unowned bytes");
    let original = std::fs::read(&unowned).expect("unowned bytes");

    let error = split_dataset_jsonl(&dataset, &output, false, 2026, 0.25, 0.25)
        .expect_err("receipt-less output must not be claimed");

    assert!(
        error.to_string().contains("unowned existing output"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(unowned).expect("preserved unowned file"),
        original
    );
    assert!(!output.join(".dataset-split-transaction.json").exists());
    assert_no_public_split_outputs_except_train(&output, "feedback");
}

#[test]
fn malformed_split_input_creates_no_output_directory() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("malformed.jsonl");
    std::fs::write(&dataset, b"{not-json}\n").expect("malformed dataset");
    let output = temp.path().join("must-not-exist");

    split_dataset_jsonl(&dataset, &output, false, 2026, 0.2, 0.0).expect_err("malformed input");

    assert!(!output.exists());
}

fn assert_no_public_split_outputs(output: &Path, stem: &str) {
    for suffix in ["train.jsonl", "validation.jsonl", "test.jsonl"] {
        assert!(!output.join(format!("{stem}-{suffix}")).exists());
    }
    assert!(!output.join("dataset_manifest.json").exists());
}

fn assert_no_public_split_outputs_except_train(output: &Path, stem: &str) {
    for suffix in ["validation.jsonl", "test.jsonl"] {
        assert!(!output.join(format!("{stem}-{suffix}")).exists());
    }
    assert!(!output.join("dataset_manifest.json").exists());
}

fn write_split_fixture(path: &Path, rows: usize) {
    let lines = (0..rows)
        .map(|index| {
            let index = u32::try_from(index).expect("test row index fits u32");
            serde_json::json!({
                "label": if index % 2 == 0 { "normal" } else { "congestion" },
                "features": feature_payload(10.0 + f64::from(index))
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(path, lines).expect("split fixture");
}
