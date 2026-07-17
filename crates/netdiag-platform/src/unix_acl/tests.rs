use super::UnixAclTrustError;
use std::error::Error;
use std::io;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn inspection_error_preserves_operation_and_source() {
    let error = UnixAclTrustError::inspection(
        "acl_fixture_operation",
        io::Error::new(io::ErrorKind::PermissionDenied, "fixture denied"),
    );

    assert_eq!(
        error.to_string(),
        "failed to inspect opened-object ACL (acl_fixture_operation): fixture denied"
    );
    let source = error.source().expect("inspection source");
    assert_eq!(source.to_string(), "fixture denied");
    assert_eq!(
        source
            .downcast_ref::<io::Error>()
            .expect("io error source")
            .kind(),
        io::ErrorKind::PermissionDenied
    );
}

#[test]
fn policy_errors_have_precise_messages_without_sources() {
    let cases = [
        (
            UnixAclTrustError::UntrustedAllow {
                principal: "group fixture".to_string(),
            },
            "ACL grants write, replacement, ownership, or ACL control to untrusted group fixture",
        ),
        (
            UnixAclTrustError::UnsupportedAcl {
                detail: "fixture semantics".to_string(),
            },
            "ACL semantics cannot be proven safe: fixture semantics",
        ),
        (
            UnixAclTrustError::UnsupportedPlatform,
            "opened-object ACL trust validation is not implemented on this Unix platform",
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
        assert!(error.source().is_none());
    }
}
