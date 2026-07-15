use crate::storage::hil_transaction::{journal_path, load_journal};

#[test]
fn hil_journal_rejects_nested_duplicate_keys_without_echoing_input() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = journal_path(temp.path());
    std::fs::write(
        &path,
        br#"{"schema":"netdiag-hil-review-transaction/v1","targets":[{"result":{"private-key":"first","private-key":"second"}}]}"#,
    )
    .expect("duplicate-key journal fixture");

    let error = load_journal(temp.path(), "run-1").expect_err("duplicate key must fail");
    let message = error.to_string();
    assert!(message.contains("duplicate key"), "{message}");
    for private_input in ["private-key", "first", "second"] {
        assert!(!message.contains(private_input), "{message}");
    }
}
