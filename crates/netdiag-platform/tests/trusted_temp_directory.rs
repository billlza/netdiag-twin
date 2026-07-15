use netdiag_platform::TrustedTempDirectory;

#[test]
fn public_boundary_creates_validates_and_explicitly_removes_a_private_directory() {
    let directory = TrustedTempDirectory::create("netdiag-platform-integration-")
        .expect("trusted temporary directory");
    let path = directory.path().to_path_buf();
    std::fs::write(path.join("payload"), b"fixture").expect("temporary payload");
    directory
        .validate_identity()
        .expect("stable temporary identity");
    directory.close().expect("explicit temporary cleanup");
    assert!(!path.exists());
}
