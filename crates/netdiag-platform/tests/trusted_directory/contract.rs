use netdiag_platform::{
    DirectoryTrustError, open_or_create_durable_trusted_subdirectory,
    open_or_create_trusted_subdirectory, open_trusted_directory_chain,
};
use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;

#[test]
fn public_subdirectory_contract_covers_creation_reopen_and_invalid_names() {
    let root = tempfile::tempdir().expect("tempdir");
    let parent = open_trusted_directory_chain(root.path()).expect("trusted parent");

    let child =
        open_or_create_trusted_subdirectory(&parent, OsStr::new("child")).expect("create child");
    let reopened =
        open_or_create_trusted_subdirectory(&parent, OsStr::new("child")).expect("reopen child");
    assert_eq!(
        child.coordination_identity().expect("created identity"),
        reopened.coordination_identity().expect("reopened identity")
    );
    assert_eq!(
        child
            .as_file()
            .metadata()
            .expect("child metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );

    open_or_create_durable_trusted_subdirectory(&parent, OsStr::new("durable"))
        .expect("create durable child")
        .validate_identity()
        .expect("durable child identity remains stable");

    for open_child in [
        open_or_create_trusted_subdirectory,
        open_or_create_durable_trusted_subdirectory,
    ] {
        let error = open_child(&parent, OsStr::new("../escape"))
            .expect_err("multi-component child name must fail closed");
        assert!(matches!(
            error,
            DirectoryTrustError::InvalidComponent { path }
                if path == parent.resolved_path().join("../escape")
        ));
    }
}
