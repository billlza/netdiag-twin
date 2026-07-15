use super::*;
use std::io::Seek;

#[test]
fn bounded_hash_stops_after_reading_limit_plus_one_byte() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("source.jsonl");
    std::fs::write(&path, b"12345678").expect("source bytes");
    let mut source = File::open(&path).expect("source file");

    let error = read_and_hash_with_limit(&path, &mut source, 3, |_| Ok(()))
        .expect_err("source beyond the limit must fail closed");

    assert!(error.to_string().contains("exceeds 3 bytes"), "{error}");
    assert_eq!(
        source.stream_position().expect("source position"),
        4,
        "bounded hashing read beyond max_bytes + 1"
    );
}
