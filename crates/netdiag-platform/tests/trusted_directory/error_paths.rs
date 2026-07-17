use netdiag_platform::{
    DirectoryTrustError, open_or_create_trusted_subdirectory, open_trusted_directory_chain,
};
use std::ffi::OsStr;
use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};

#[test]
fn public_subdirectory_contract_classifies_symlinks_files_and_write_denial() {
    let root = tempfile::tempdir().expect("tempdir");
    let parent = open_trusted_directory_chain(root.path()).expect("trusted parent");

    let regular = root.path().join("regular");
    std::fs::write(&regular, b"fixture").expect("regular file");
    let shape_error = open_or_create_trusted_subdirectory(&parent, OsStr::new("regular"))
        .expect_err("regular file must not pass as a directory");
    assert!(matches!(
        shape_error,
        DirectoryTrustError::NotDirectory { path }
            if path == parent.resolved_path().join("regular")
    ));

    let external = tempfile::tempdir().expect("external target");
    let linked = root.path().join("linked");
    symlink(external.path(), &linked).expect("symlink fixture");
    let symlink_error = open_or_create_trusted_subdirectory(&parent, OsStr::new("linked"))
        .expect_err("symlink child must fail closed");
    assert!(matches!(
        symlink_error,
        DirectoryTrustError::UntrustedSymlink { path, detail }
            if path == parent.resolved_path().join("linked")
                && detail == "trusted subdirectories cannot be symbolic links"
    ));

    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o500))
        .expect("restrict parent writes");
    let blocked = parent.resolved_path().join("blocked");
    let denied_error = open_or_create_trusted_subdirectory(&parent, OsStr::new("blocked"))
        .expect_err("child creation without parent write permission must fail");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("restore parent permissions");
    assert!(matches!(
        denied_error,
        DirectoryTrustError::Inspect { path, source }
            if path == blocked && source.kind() == io::ErrorKind::PermissionDenied
    ));
    assert!(
        !root.path().join("blocked").exists(),
        "failed creation must not leave an entry"
    );
}
