use super::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

fn trusted_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("netdiag-trust-test-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("trusted tempdir")
}

fn open_root(path: &Path, configured: &str) -> TrustedRoot {
    let canonical = path.canonicalize().expect("canonical trusted root");
    TrustedRoot::open(&canonical, configured).expect("trusted root")
}

#[test]
fn rejects_world_writable_root_and_source_file() {
    let temp = trusted_tempdir();
    let root_path = temp.path().join("trusted");
    fs::create_dir(&root_path).expect("trusted root");
    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o777))
        .expect("world-writable root mode");
    let error = TrustedRoot::open(
        &root_path.canonicalize().expect("canonical root"),
        "trusted",
    )
    .err()
    .expect("world-writable root must fail closed");
    assert!(error.to_string().contains("group/world-writable"));

    fs::set_permissions(&root_path, fs::Permissions::from_mode(0o700)).expect("restore root mode");
    let source = root_path.join("adapter.py");
    fs::write(&source, b"print('unsafe')\n").expect("source");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o666))
        .expect("world-writable source mode");
    let root = open_root(&root_path, "trusted");
    let error = root
        .open_source("trusted/adapter.py")
        .err()
        .expect("world-writable source must fail closed");
    assert!(error.to_string().contains("group/world-writable"));
}

#[test]
fn no_follow_open_rejects_final_and_intermediate_symlinks() {
    let temp = trusted_tempdir();
    let root_path = temp.path().join("trusted");
    let real_directory = root_path.join("real");
    fs::create_dir_all(&real_directory).expect("real directory");
    fs::write(real_directory.join("adapter.py"), b"print('real')\n").expect("real source");
    symlink(
        real_directory.join("adapter.py"),
        root_path.join("final.py"),
    )
    .expect("final symlink");
    symlink(&real_directory, root_path.join("linked-directory")).expect("directory symlink");
    let root = open_root(&root_path, "trusted");

    let final_error = root
        .open_source("trusted/final.py")
        .err()
        .expect("final symlink must fail");
    assert!(final_error.to_string().contains("symbolic links"));
    root.open_source("trusted/linked-directory/adapter.py")
        .err()
        .expect("intermediate symlink must fail");
}

#[test]
fn root_path_replacement_is_detected_after_descriptor_open() {
    let temp = trusted_tempdir();
    let root_path = temp.path().join("trusted");
    fs::create_dir(&root_path).expect("trusted root");
    let canonical = root_path.canonicalize().expect("canonical root");
    let root = TrustedRoot::open(&canonical, "trusted").expect("trusted root");

    let original = temp.path().join("trusted-original");
    fs::rename(&canonical, &original).expect("move original root");
    fs::create_dir(&canonical).expect("replacement root");
    let error = root
        .verify_unchanged()
        .expect_err("root replacement must fail closed");

    assert!(error.to_string().contains("root changed"));
}
