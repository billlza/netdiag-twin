use super::*;
use std::collections::BTreeSet;
use std::sync::{Arc, Barrier};
use std::thread;

const UPDATE_COUNT: usize = 16;

fn lab_run_index_entry(run_id: &str, passed: bool) -> LabRunIndexEntry {
    LabRunIndexEntry {
        run_id: run_id.to_string(),
        scenario_id: "concurrent-scenario".to_string(),
        scenario_name: "Concurrent scenario".to_string(),
        created_at: Utc::now(),
        lab_run_dir: format!("lab-runs/concurrent-scenario/{run_id}"),
        pipeline_run_dir: format!("lab-runs/concurrent-scenario/{run_id}/runs/{run_id}"),
        acceptance_path: format!("lab-runs/concurrent-scenario/{run_id}/acceptance.json"),
        comparison_path: format!("lab-runs/concurrent-scenario/{run_id}/comparison.json"),
        scenario_path: format!("lab-runs/concurrent-scenario/{run_id}/scenario.yaml"),
        passed,
    }
}

#[test]
fn load_lab_scenario_rejects_non_portable_scenario_ids() {
    let temp = tempfile::tempdir().expect("tempdir");
    let scenario_path = temp.path().join("scenario.yaml");

    for unsafe_id in [
        "../escape",
        "nested/path",
        r"nested\path",
        ".hidden",
        "unicode-中文",
    ] {
        let encoded_id = serde_json::to_string(unsafe_id).expect("JSON-encoded YAML scalar");
        let raw = format!(
            r#"schema: netdiag-lab-scenario/v1
id: {encoded_id}
name: Unsafe scenario identifier
data_sources:
  - role: primary
    kind: trace-file
    endpoint: trace.csv
"#
        );
        std::fs::write(&scenario_path, raw).expect("scenario file");

        let error =
            load_lab_scenario(&scenario_path).expect_err("unsafe scenario id must fail validation");
        assert!(
            error.to_string().contains("lab scenario id"),
            "unexpected error for {unsafe_id:?}: {error}"
        );
    }
}

#[test]
fn concurrent_lab_run_index_updates_preserve_all_entries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let artifact_root = Arc::new(temp.path().to_path_buf());
    let barrier = Arc::new(Barrier::new(UPDATE_COUNT));
    let mut workers = Vec::with_capacity(UPDATE_COUNT);

    for index in 0..UPDATE_COUNT {
        let artifact_root = Arc::clone(&artifact_root);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            let run_id = format!("concurrent-run-{index:02}");
            barrier.wait();
            update_lab_run_index(&artifact_root, lab_run_index_entry(&run_id, false))
                .expect("concurrent index update");
        }));
    }
    for worker in workers {
        worker.join().expect("index update worker");
    }

    let index = read_lab_run_index(&artifact_root)
        .expect("read lab run index")
        .expect("lab run index");
    let run_ids = index
        .runs
        .iter()
        .map(|entry| entry.run_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(index.runs.len(), UPDATE_COUNT);
    assert_eq!(run_ids.len(), UPDATE_COUNT);
    for index in 0..UPDATE_COUNT {
        assert!(run_ids.contains(format!("concurrent-run-{index:02}").as_str()));
    }
}

#[test]
fn concurrent_lab_run_pass_updates_preserve_all_changes() {
    let temp = tempfile::tempdir().expect("tempdir");
    for index in 0..UPDATE_COUNT {
        let run_id = format!("concurrent-pass-run-{index:02}");
        update_lab_run_index(temp.path(), lab_run_index_entry(&run_id, false))
            .expect("initial index update");
    }

    let artifact_root = Arc::new(temp.path().to_path_buf());
    let barrier = Arc::new(Barrier::new(UPDATE_COUNT));
    let mut workers = Vec::with_capacity(UPDATE_COUNT);
    for index in 0..UPDATE_COUNT {
        let artifact_root = Arc::clone(&artifact_root);
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            let run_id = format!("concurrent-pass-run-{index:02}");
            barrier.wait();
            update_lab_run_index_passed(&artifact_root, &run_id, true)
                .expect("concurrent pass update");
        }));
    }
    for worker in workers {
        worker.join().expect("pass update worker");
    }

    let index = read_lab_run_index(&artifact_root)
        .expect("read lab run index")
        .expect("lab run index");
    assert_eq!(index.runs.len(), UPDATE_COUNT);
    assert!(index.runs.iter().all(|entry| entry.passed));
}

#[test]
fn lab_run_pass_update_rejects_missing_index_and_run() {
    let missing = tempfile::tempdir().expect("tempdir");
    let error = update_lab_run_index_passed(missing.path(), "run-1", true)
        .expect_err("missing index must fail");
    assert!(error.to_string().contains("lab run index is missing"));

    let absent = tempfile::tempdir().expect("tempdir");
    update_lab_run_index(absent.path(), lab_run_index_entry("different-run", false))
        .expect("initial index");
    let error = update_lab_run_index_passed(absent.path(), "run-1", true)
        .expect_err("absent run must fail");
    assert!(error.to_string().contains("run run-1 is absent"));
}

#[test]
fn lab_run_index_rejects_unsupported_schema_without_rewriting_it() {
    let temp = tempfile::tempdir().expect("tempdir");
    let index_path = temp.path().join("lab_run_index.json");
    save_json(
        &index_path,
        &LabRunIndex {
            schema: "netdiag-lab-run-index/v2".to_string(),
            generated_at: Utc::now(),
            runs: Vec::new(),
        },
    )
    .expect("unsupported index fixture");
    let original = std::fs::read(&index_path).expect("original index");

    let read_error = read_lab_run_index(temp.path()).expect_err("unsupported schema must fail");
    assert!(
        read_error
            .to_string()
            .contains("unsupported lab run index schema")
    );
    let location_error = crate::storage::resolve_run_location(temp.path(), "run-1")
        .expect_err("location lookup must reject unsupported schema");
    assert!(
        location_error
            .to_string()
            .contains("unsupported lab run index schema")
    );
    let update_error = update_lab_run_index(temp.path(), lab_run_index_entry("run-1", false))
        .expect_err("update must not normalize unsupported schema");
    assert!(
        update_error
            .to_string()
            .contains("unsupported lab run index schema")
    );
    assert_eq!(
        std::fs::read(&index_path).expect("preserved index"),
        original
    );
}

#[test]
fn lab_run_index_enforces_byte_and_entry_limits() {
    use crate::storage::typed_json::{MAX_LAB_RUN_INDEX_BYTES, MAX_LAB_RUN_INDEX_ENTRIES};

    let oversized = tempfile::tempdir().expect("oversized root");
    std::fs::File::create(oversized.path().join("lab_run_index.json"))
        .expect("index")
        .set_len(MAX_LAB_RUN_INDEX_BYTES + 1)
        .expect("oversized index");
    let error = read_lab_run_index(oversized.path()).expect_err("oversized index must fail");
    assert!(error.to_string().contains("read limit"), "{error}");

    let too_many = tempfile::tempdir().expect("entry root");
    let index = LabRunIndex {
        schema: "netdiag-lab-run-index/v1".to_string(),
        generated_at: Utc::now(),
        runs: (0..=MAX_LAB_RUN_INDEX_ENTRIES)
            .map(|entry| lab_run_index_entry(&format!("run-{entry}"), false))
            .collect(),
    };
    save_json(too_many.path().join("lab_run_index.json"), &index).expect("index fixture");
    let error = read_lab_run_index(too_many.path()).expect_err("entry overage must fail");
    assert!(error.to_string().contains("201 entries"), "{error}");
    let location_error = crate::storage::resolve_run_location(too_many.path(), "missing-run")
        .expect_err("location index overage must fail");
    assert!(
        location_error.to_string().contains("201 entries"),
        "{location_error}"
    );
}

#[cfg(unix)]
#[test]
fn lab_run_index_symbolic_link_is_rejected_by_all_readers() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("outside-index.json");
    save_json(
        &target,
        &LabRunIndex {
            schema: "netdiag-lab-run-index/v1".to_string(),
            generated_at: Utc::now(),
            runs: Vec::new(),
        },
    )
    .expect("target index");
    symlink(&target, temp.path().join("lab_run_index.json")).expect("index symlink");

    let read_error = read_lab_run_index(temp.path()).expect_err("index symlink must fail");
    assert!(
        read_error.to_string().contains("regular, non-symlink"),
        "{read_error}"
    );
    let location_error = crate::storage::resolve_run_location(temp.path(), "run-1")
        .expect_err("location lookup must reject index symlink");
    assert!(
        location_error.to_string().contains("regular, non-symlink"),
        "{location_error}"
    );
}
