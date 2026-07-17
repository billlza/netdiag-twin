use super::*;

#[test]
fn relative_paths_support_declared_parent_roots_but_reject_escapes() {
    assert_eq!(
        relative_adapter_path("../adapters", "../adapters/probe/adapter.py")
            .expect("declared parent root"),
        PathBuf::from("probe/adapter.py")
    );
    assert_eq!(
        relative_adapter_path(".", "adapter.py").expect("current directory root"),
        PathBuf::from("adapter.py")
    );
    for endpoint in ["../outside.py", "../adapters/../outside.py", "../adapters"] {
        relative_adapter_path("../adapters", endpoint)
            .expect_err("escape or root directory endpoint must fail");
    }
}

#[test]
fn absolute_paths_are_rejected_without_filesystem_access() {
    let error = relative_adapter_path("trusted", "/outside/adapter.py")
        .expect_err("absolute endpoint must fail");
    assert!(error.to_string().contains("must be relative"));
}
