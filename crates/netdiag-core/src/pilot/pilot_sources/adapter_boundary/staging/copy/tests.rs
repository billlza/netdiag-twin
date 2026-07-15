use super::*;

#[test]
fn cleanup_distinguishes_absent_and_unremovable_paths() {
    let temp = tempfile::tempdir().expect("tempdir");
    let original = NetdiagError::InvalidTrace("copy failed".to_string());
    let absent = clean_up_failed_stage(&temp.path().join("absent.py"), original);
    assert_eq!(absent.to_string(), "invalid trace: copy failed");

    let directory = temp.path().join("not-a-file.py");
    fs::create_dir(&directory).expect("directory");
    let cleanup_error = clean_up_failed_stage(
        &directory,
        NetdiagError::InvalidTrace("copy failed".to_string()),
    );
    let NetdiagError::CombinedFailure {
        primary_context,
        primary,
        secondary_context,
        secondary,
    } = cleanup_error
    else {
        panic!("expected combined staging failure");
    };
    assert_eq!(primary_context, "adapter staging failed");
    assert_eq!(
        secondary_context,
        "cleanup of the incomplete staged adapter also failed"
    );
    assert!(matches!(
        primary.as_ref(),
        NetdiagError::InvalidTrace(message) if message == "copy failed"
    ));
    let NetdiagError::Io { path, source } = secondary.as_ref() else {
        panic!("expected typed cleanup I/O error");
    };
    assert_eq!(path, &directory);
    let expected_kind = if cfg!(target_os = "linux") {
        io::ErrorKind::IsADirectory
    } else {
        io::ErrorKind::PermissionDenied
    };
    assert_eq!(source.kind(), expected_kind);
}
