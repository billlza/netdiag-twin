use super::super::MAX_ADAPTER_FILE_BYTES;
use super::stage::{stage_adapter, stage_adapter_with_hooks};
use super::trusted_root::TrustedRoot;
use super::*;
use crate::pilot::PilotManifest;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{PermissionsExt, symlink};
#[cfg(target_os = "macos")]
use std::process::Command;

fn trusted_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("netdiag-staging-test-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("trusted tempdir")
}

fn open_trusted_root(path: &Path) -> TrustedRoot {
    let canonical = path.canonicalize().expect("canonical trusted root");
    TrustedRoot::open(&canonical, "trusted").expect("trusted root")
}

fn adapter_manifest(endpoint: &str) -> PilotManifest {
    serde_yaml::from_str(&format!(
        r#"schema: netdiag-pilot/v1
id: staging-cleanup
name: Staging cleanup
sources:
  - name: adapter
    kind: adapter_sample
    endpoint: {endpoint}
    role: primary
"#
    ))
    .expect("adapter manifest fixture")
}

#[test]
fn source_growth_during_staging_is_bounded_and_partial_file_is_removed() {
    let temp = trusted_tempdir();
    let trusted = temp.path().join("trusted");
    let staging = temp.path().join("staging");
    fs::create_dir(&trusted).expect("trusted directory");
    fs::create_dir(&staging).expect("staging directory");
    let source = trusted.join("adapter.py");
    fs::write(&source, b"x").expect("initial adapter");
    let trusted = open_trusted_root(&trusted);

    let error = stage_adapter_with_hooks(
        temp.path(),
        &trusted,
        &staging,
        "adapter",
        "trusted/adapter.py",
        (
            |_| {},
            |path| {
                let file = OpenOptions::new()
                    .append(true)
                    .open(path)
                    .expect("reopen adapter for deterministic growth");
                file.set_len(MAX_ADAPTER_FILE_BYTES + 1)
                    .expect("grow adapter beyond limit");
            },
            |_| {},
        ),
    )
    .expect_err("growth after metadata inspection must fail closed");

    assert!(error.to_string().contains("exceeded"), "{error}");
    assert!(
        !staging.join("adapter.py").exists(),
        "incomplete staged adapter was not removed"
    );
}

#[test]
fn same_length_source_mutation_after_copy_is_rejected_and_cleaned() {
    let temp = trusted_tempdir();
    let trusted = temp.path().join("trusted");
    let staging = temp.path().join("staging");
    fs::create_dir(&trusted).expect("trusted directory");
    fs::create_dir(&staging).expect("staging directory");
    let source = trusted.join("adapter.py");
    fs::write(&source, b"print('a')\n").expect("initial adapter");
    let trusted = open_trusted_root(&trusted);

    let error = stage_adapter_with_hooks(
        temp.path(),
        &trusted,
        &staging,
        "adapter",
        "trusted/adapter.py",
        (
            |_| {},
            |_| {},
            |path| {
                fs::write(path, b"print('b')\n").expect("same-length source mutation");
            },
        ),
    )
    .expect_err("same-length mutation after copy must fail closed");

    assert!(error.to_string().contains("changed"), "{error}");
    assert!(!staging.join("adapter.py").exists());
}

#[test]
fn source_shrink_and_path_replacement_are_rejected_and_cleaned() {
    for replacement in [false, true] {
        let temp = trusted_tempdir();
        let trusted = temp.path().join("trusted");
        let staging = temp.path().join("staging");
        fs::create_dir(&trusted).expect("trusted directory");
        fs::create_dir(&staging).expect("staging directory");
        let source = trusted.join("adapter.py");
        fs::write(&source, b"print('original')\n").expect("initial adapter");
        let trusted = open_trusted_root(&trusted);

        let error = stage_adapter_with_hooks(
            temp.path(),
            &trusted,
            &staging,
            "adapter",
            "trusted/adapter.py",
            (
                |_| {},
                move |path| {
                    if replacement {
                        fs::rename(path, path.with_extension("old"))
                            .expect("move inspected source");
                        fs::write(path, b"print('replacement')\n").expect("replacement source");
                    } else {
                        OpenOptions::new()
                            .write(true)
                            .open(path)
                            .expect("open source for shrink")
                            .set_len(1)
                            .expect("shrink source");
                    }
                },
                |_| {},
            ),
        )
        .expect_err("source identity or size changes must fail closed");

        assert!(error.to_string().contains("changed"), "{error}");
        assert!(!staging.join("adapter.py").exists());
    }
}

#[test]
fn exact_size_limit_is_staged_without_truncation() {
    let temp = trusted_tempdir();
    let trusted = temp.path().join("trusted");
    let staging = temp.path().join("staging");
    fs::create_dir(&trusted).expect("trusted directory");
    fs::create_dir(&staging).expect("staging directory");
    let source = trusted.join("adapter.py");
    let file = File::create(&source).expect("adapter");
    file.set_len(MAX_ADAPTER_FILE_BYTES)
        .expect("exact-size adapter");
    let trusted = open_trusted_root(&trusted);

    let staged = stage_adapter(
        temp.path(),
        &trusted,
        &staging,
        "adapter",
        "trusted/adapter.py",
    )
    .expect("exact limit must remain valid");

    assert_eq!(
        staged
            .staged_path
            .metadata()
            .expect("staged metadata")
            .len(),
        MAX_ADAPTER_FILE_BYTES
    );
}

#[test]
fn staging_accessors_fail_explicitly_for_unknown_sources() {
    let manifest = PilotManifest {
        schema: "netdiag-pilot/v1".to_string(),
        id: "empty".to_string(),
        name: "Empty".to_string(),
        operator: None,
        safety: Default::default(),
        sources: Vec::new(),
        gates: Default::default(),
    };
    let temp = trusted_tempdir();
    let staged = StagedAdapters::prepare(&manifest, temp.path(), temp.path(), ".")
        .expect("empty staging boundary");

    for result in [
        staged.staged_path("missing").map(|_| ()),
        staged.original_path("missing").map(|_| ()),
        staged.identity("missing").map(|_| ()),
    ] {
        let error = result.expect_err("unknown source must fail");
        assert!(error.to_string().contains("prepared adapter is missing"));
    }
    let staging_path = staged.directory.path().to_path_buf();
    staged
        .finish(Ok(()))
        .expect("finish empty staging boundary");
    assert!(!staging_path.exists());
}

#[test]
fn staging_failure_explicitly_removes_the_private_directory() {
    let temp = trusted_tempdir();
    let trusted = temp.path().join("trusted");
    fs::create_dir(&trusted).expect("trusted directory");
    let manifest = adapter_manifest("trusted/missing.py");
    let mut staging_path = None;

    let error = StagedAdapters::prepare_unix_with_directory_hook(
        &manifest,
        temp.path(),
        &trusted.canonicalize().expect("canonical trusted root"),
        "trusted",
        |path| staging_path = Some(path.to_path_buf()),
    )
    .expect_err("missing source must fail staging");

    assert!(error.to_string().contains("does not exist"), "{error}");
    assert!(
        !staging_path.expect("staging path").exists(),
        "staging failure must explicitly remove its private directory"
    );
}

#[test]
fn staging_preserves_operation_and_cleanup_failures() {
    let temp = trusted_tempdir();
    let trusted = temp.path().join("trusted");
    fs::create_dir(&trusted).expect("trusted directory");
    let manifest = adapter_manifest("trusted/missing.py");
    let mut staging_path = None;
    let mut displaced_path = None;

    let error = StagedAdapters::prepare_unix_with_directory_hook(
        &manifest,
        temp.path(),
        &trusted.canonicalize().expect("canonical trusted root"),
        "trusted",
        |path| {
            staging_path = Some(path.to_path_buf());
            let displaced = path.with_extension("displaced");
            displaced_path = Some(displaced.clone());
            fs::rename(path, &displaced).expect("displace staging directory");
            fs::create_dir(path).expect("replacement staging directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("replacement mode");
        },
    )
    .expect_err("staging and cleanup failures must both remain observable");
    let path = staging_path.expect("staging path");
    fs::remove_dir_all(&path).expect("remove replacement fixture");
    fs::remove_dir_all(displaced_path.expect("displaced path")).expect("remove displaced fixture");

    let (operation, cleanup) = match error {
        NetdiagError::TrustedTemporaryDirectoryOperationAndCleanup {
            operation, cleanup, ..
        } => (operation, cleanup),
        other => panic!("expected structured staging and cleanup failure: {other}"),
    };
    assert!(
        operation.to_string().contains("does not exist"),
        "{operation}"
    );
    assert!(!cleanup.to_string().is_empty());
}

#[test]
fn staging_rejects_directories_as_adapter_files() {
    let temp = trusted_tempdir();
    let trusted = temp.path().join("trusted");
    let staging = temp.path().join("staging");
    fs::create_dir(&trusted).expect("trusted directory");
    fs::create_dir(&staging).expect("staging directory");
    fs::create_dir(trusted.join("adapter.py")).expect("directory endpoint");
    let trusted = open_trusted_root(&trusted);

    let error = stage_adapter(
        temp.path(),
        &trusted,
        &staging,
        "adapter",
        "trusted/adapter.py",
    )
    .expect_err("directory endpoint must fail");
    assert!(error.to_string().contains("not a regular file"));
}

#[test]
fn path_replacement_with_symlink_before_open_is_rejected_without_output() {
    let temp = trusted_tempdir();
    let trusted_path = temp.path().join("trusted");
    let staging = temp.path().join("staging");
    fs::create_dir(&trusted_path).expect("trusted directory");
    fs::create_dir(&staging).expect("staging directory");
    fs::write(trusted_path.join("adapter.py"), b"print('original')\n").expect("initial adapter");
    let trusted = open_trusted_root(&trusted_path);

    let error = stage_adapter_with_hooks(
        temp.path(),
        &trusted,
        &staging,
        "adapter",
        "trusted/adapter.py",
        (
            |path| {
                let original = path.with_extension("old");
                fs::rename(path, &original).expect("move original adapter");
                symlink(&original, path).expect("replace adapter with symlink");
            },
            |_| {},
            |_| {},
        ),
    )
    .expect_err("no-follow open must reject a raced symlink");

    assert!(error.to_string().contains("symbolic links"), "{error}");
    assert!(!staging.join("adapter.py").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn staging_rejects_adapter_write_acl_hidden_by_read_only_mode() {
    let temp = trusted_tempdir();
    let trusted_path = temp.path().join("trusted");
    let staging = temp.path().join("staging");
    fs::create_dir(&trusted_path).expect("trusted directory");
    fs::create_dir(&staging).expect("staging directory");
    let source = trusted_path.join("adapter.py");
    fs::write(&source, b"print('original')\n").expect("adapter source");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o444)).expect("read-only mode");
    let status = Command::new("/bin/chmod")
        .args(["+a", "user:nobody allow write,append,writesecurity,chown"])
        .arg(&source)
        .status()
        .expect("set adapter ACL fixture");
    assert!(status.success());
    let trusted = open_trusted_root(&trusted_path);

    let result = stage_adapter(
        temp.path(),
        &trusted,
        &staging,
        "adapter",
        "trusted/adapter.py",
    );
    let status = Command::new("/bin/chmod")
        .arg("-N")
        .arg(&source)
        .status()
        .expect("clear adapter ACL fixture");
    assert!(status.success());
    let error = result.expect_err("adapter write ACL must fail closed");
    assert!(error.to_string().contains("unsafe ACL"), "{error}");
    assert!(!staging.join("adapter.py").exists());
}
