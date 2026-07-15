use super::*;
use std::io::{Cursor, sink};

#[test]
fn total_budget_rejects_the_chunk_that_would_cross_the_limit() {
    let mut budget = BundleBudget {
        bytes: MAX_BUNDLE_BYTES - 1,
    };
    let error = match budget.copy_source(
        &mut Cursor::new([1_u8, 2]),
        Path::new("second-source.bin"),
        &mut sink(),
    ) {
        Ok(_) => panic!("total bundle limit must be enforced while streaming"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("total uncompressed bundle byte limit")
    );
    assert_eq!(budget.bytes, MAX_BUNDLE_BYTES - 1);
}
