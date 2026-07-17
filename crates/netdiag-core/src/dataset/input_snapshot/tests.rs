use super::DatasetInputSnapshot;
use crate::error::NetdiagError;
use std::fs;
use std::io::Read;

#[test]
fn snapshot_read_is_immutable_after_the_source_changes() {
    let root = tempfile::tempdir().expect("tempdir");
    let source = root.path().join("dataset.jsonl");
    let original = b"first generation\n";
    fs::write(&source, original).expect("source");
    let snapshot = DatasetInputSnapshot::capture(&source).expect("capture");
    let captured_hash = snapshot.hash_sha256().to_string();

    fs::write(&source, b"second generation\n").expect("replace source bytes");
    let read_path = source.clone();
    let read_result = snapshot.read(move |mut reader| {
        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .map_err(|source| crate::error::NetdiagError::Io {
                path: read_path,
                source,
            })?;
        Ok(bytes)
    });
    let captured = snapshot
        .finish(read_result)
        .expect("read and cleanup snapshot");

    assert_eq!(captured, original);
    assert_eq!(captured_hash.len(), 64);
}

#[test]
fn capture_failure_explicitly_removes_staging() {
    let root = tempfile::tempdir().expect("tempdir");
    let missing = root.path().join("missing.jsonl");
    let mut staging_path = None;
    let captured = DatasetInputSnapshot::capture_with_staging_observer(&missing, |path| {
        staging_path = Some(path.to_path_buf());
    });
    let error = match captured {
        Ok(snapshot) => {
            snapshot
                .finish(Ok(()))
                .expect("remove unexpectedly successful snapshot");
            panic!("missing source must fail after staging creation");
        }
        Err(error) => error,
    };

    assert!(matches!(
        error,
        NetdiagError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound
    ));
    assert!(
        !staging_path.expect("staging path").exists(),
        "capture failure must explicitly remove dataset staging"
    );
}
