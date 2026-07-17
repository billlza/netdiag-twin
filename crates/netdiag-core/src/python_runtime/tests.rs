use super::*;

#[cfg(unix)]
pub(super) fn trusted_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("netdiag-interpreter-test-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("trusted interpreter test directory")
}

#[cfg(unix)]
#[test]
fn trusted_runtime_preserves_the_configured_copy_and_sanitized_path() {
    use std::os::unix::fs::PermissionsExt;

    let platform = resolve_python_interpreter(None)
        .expect("test environment should expose a trusted Python interpreter");
    let temp = trusted_tempdir();
    let bin = temp.path().join("venv/bin");
    std::fs::create_dir_all(&bin).expect("create venv bin directory");
    let configured = bin.join("python");
    std::fs::copy(platform.path(), &configured).expect("copy configured interpreter");
    std::fs::set_permissions(&configured, std::fs::Permissions::from_mode(0o755))
        .expect("make configured interpreter executable");

    let runtime = resolve_trusted_python_runtime(&configured).expect("trusted Python runtime");

    assert_eq!(
        runtime.executable(),
        configured
            .canonicalize()
            .expect("canonical configured path")
    );
    assert_eq!(runtime.runtime_path(), platform.runtime_path());
}

#[cfg(unix)]
#[test]
fn trusted_runtime_rejects_non_unicode_paths() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let path = PathBuf::from(OsString::from_vec(vec![b'/', 0xff]));
    let error = resolve_trusted_python_runtime(&path)
        .expect_err("non-Unicode interpreter paths must fail closed");

    assert!(error.to_string().contains("not valid Unicode"));
}

#[cfg(unix)]
#[test]
fn configured_resolution_and_rejection_bounds_are_exercised() {
    let executable = std::env::current_exe().expect("current test executable");
    let resolved = resolve_python_interpreter(Some(
        executable
            .to_str()
            .expect("test executable path must be Unicode"),
    ))
    .expect("trusted configured executable");
    assert_eq!(
        resolved.path(),
        executable.canonicalize().expect("canonical exe")
    );
    assert!(!resolved.runtime_path().is_empty());

    let mut rejections = Vec::new();
    record_rejection(&mut rejections, "x".repeat(MAX_REJECTION_DETAIL_CHARS + 8));
    assert!(rejections[0].ends_with("..."));
    for index in 1..=MAX_REJECTION_DETAILS + 2 {
        record_rejection(&mut rejections, format!("rejection-{index}"));
    }
    assert_eq!(rejections.len(), MAX_REJECTION_DETAILS);
}

#[cfg(not(unix))]
#[test]
fn configured_paths_are_rejected_before_platform_path_inspection() {
    let error = resolve_python_interpreter(Some(r"\\server\share\python.exe"))
        .expect_err("non-Unix adapter execution must fail before path inspection");

    assert_eq!(
        error.to_string(),
        "connector error: Python adapter execution is disabled on this platform because interpreter and ancestor ACL trust cannot yet be proven"
    );
}

#[cfg(unix)]
#[test]
fn sanitized_runtime_path_rejects_separator_and_non_unicode_entries() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let separator = PathBuf::from("contains:path-separator");
    let separator_error = joined_runtime_path([&separator])
        .expect_err("PATH entries containing separators must fail");
    assert!(separator_error.to_string().contains("construct sanitized"));

    let non_unicode = PathBuf::from(OsString::from_vec(vec![0xff]));
    let unicode_error =
        joined_runtime_path([&non_unicode]).expect_err("non-Unicode sanitized PATH must fail");
    assert!(unicode_error.to_string().contains("not valid Unicode"));
}
