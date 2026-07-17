use netdiag_platform::{
    open_or_create_durable_trusted_directory_chain, open_or_create_trusted_directory_chain,
};

#[test]
fn public_chain_contract_creates_non_durable_and_durable_paths() {
    let root = tempfile::tempdir().expect("tempdir");
    let non_durable_chain = root.path().join("chains").join("non-durable");
    let opened_non_durable = open_or_create_trusted_directory_chain(&non_durable_chain)
        .expect("create non-durable chain");
    assert_eq!(
        opened_non_durable.resolved_path(),
        std::fs::canonicalize(&non_durable_chain)
            .expect("canonical non-durable chain")
            .as_path()
    );

    let durable_chain = root.path().join("chains").join("durable");
    open_or_create_durable_trusted_directory_chain(&durable_chain)
        .expect("create durable chain")
        .validate_identity()
        .expect("durable chain identity remains stable");
}
