use super::*;
use crate::open_trusted_directory_chain;
use std::error::Error;
use std::io;
#[cfg(unix)]
use std::io::Write;

#[test]
fn atomic_publication_error_preserves_its_primary_io_source() {
    let root = tempfile::tempdir().expect("temporary root");
    let directory = open_trusted_directory_chain(root.path()).expect("trusted parent");

    let error = publish_file_replace_at(
        &directory,
        OsStr::new("../invalid"),
        OsStr::new("state.json"),
    )
    .expect_err("invalid leaf must fail");

    assert_eq!(error.state(), AtomicPublicationState::NotPublished);
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.classification().is_none());
    let primary = Error::source(&error)
        .and_then(|source| source.downcast_ref::<io::Error>())
        .expect("primary I/O source");
    assert!(std::ptr::eq(primary, error.primary_io_error()));
}

#[test]
fn private_file_creation_rejects_non_leaf_names_with_a_typed_io_error() {
    let root = tempfile::tempdir().expect("temporary root");
    let directory = open_trusted_directory_chain(root.path()).expect("trusted parent");

    let error = create_new_private_file_at(&directory, OsStr::new("../escape"))
        .expect_err("non-leaf name must fail closed");

    assert!(matches!(
        error,
        PrivateFileCreationError::Io { ref source }
            if source.kind() == io::ErrorKind::InvalidInput
    ));
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn private_file_creation_preserves_collision_kind_and_existing_contents() {
    let root = tempfile::tempdir().expect("temporary root");
    let directory = open_trusted_directory_chain(root.path()).expect("trusted parent");
    let path = root.path().join("state.tmp");
    std::fs::write(&path, b"existing").expect("existing fixture");

    let error = create_new_private_file_at(&directory, OsStr::new("state.tmp"))
        .expect_err("collision must fail closed");

    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(
        std::fs::read(path).expect("preserved contents"),
        b"existing"
    );
}

#[cfg(unix)]
#[test]
fn unix_bound_open_rejects_symlinks_and_preserves_the_kernel_error() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary root");
    let directory = open_trusted_directory_chain(root.path()).expect("trusted parent");
    std::fs::write(root.path().join("source.json"), b"source").expect("source fixture");
    symlink("source.json", root.path().join("state.json")).expect("symlink fixture");

    let error = open_file_read_only_at(&directory, OsStr::new("state.json"))
        .expect_err("bound open must reject symlinks");

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("symlink/reparse point"));
    let kernel = Error::source(&error)
        .and_then(|source| source.downcast_ref::<io::Error>())
        .expect("kernel I/O source");
    assert_eq!(
        kernel.raw_os_error(),
        io::Error::from(rustix::io::Errno::LOOP).raw_os_error()
    );
}

#[cfg(unix)]
#[test]
fn unix_publication_remains_bound_after_parent_path_replacement() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary root");
    let parent = root.path().join("output");
    let protected = root.path().join("protected");
    std::fs::create_dir(&parent).expect("output parent");
    std::fs::create_dir(&protected).expect("protected parent");
    std::fs::write(protected.join("state.json"), b"protected").expect("protected target");
    let directory = open_trusted_directory_chain(&parent).expect("trusted output parent");
    let mut temporary =
        create_new_private_file_at(&directory, OsStr::new("state.tmp")).expect("temporary file");
    temporary.write_all(b"published").expect("temporary bytes");
    temporary.sync_all().expect("temporary sync");
    drop(temporary);

    let displaced = root.path().join("displaced");
    std::fs::rename(&parent, &displaced).expect("displace output parent");
    symlink(&protected, &parent).expect("replace path with protected alias");
    publish_file_replace_at(
        &directory,
        OsStr::new("state.tmp"),
        OsStr::new("state.json"),
    )
    .expect("handle-bound publish");

    assert_eq!(
        std::fs::read(displaced.join("state.json")).expect("published target"),
        b"published"
    );
    assert_eq!(
        std::fs::read(protected.join("state.json")).expect("protected target"),
        b"protected"
    );
    assert!(!displaced.join("state.tmp").exists());
}

#[cfg(unix)]
#[test]
fn unix_cleanup_remains_bound_after_parent_path_replacement() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary root");
    let parent = root.path().join("output");
    let protected = root.path().join("protected");
    std::fs::create_dir(&parent).expect("output parent");
    std::fs::create_dir(&protected).expect("protected parent");
    std::fs::write(protected.join("state.tmp"), b"protected").expect("protected temporary");
    let directory = open_trusted_directory_chain(&parent).expect("trusted output parent");
    create_new_private_file_at(&directory, OsStr::new("state.tmp")).expect("temporary file");
    let displaced = root.path().join("displaced");
    std::fs::rename(&parent, &displaced).expect("displace output parent");
    symlink(&protected, &parent).expect("replace path with protected alias");

    remove_file_at(&directory, OsStr::new("state.tmp")).expect("handle-bound cleanup");

    assert!(!displaced.join("state.tmp").exists());
    assert_eq!(
        std::fs::read(protected.join("state.tmp")).expect("protected temporary"),
        b"protected"
    );
}

#[cfg(windows)]
#[test]
fn windows_open_chain_blocks_parent_replacement_until_publication() {
    let root = tempfile::tempdir().expect("temporary root");
    let container = root.path().join("container");
    let parent = container.join("output");
    std::fs::create_dir_all(&parent).expect("output parent");
    let directory = open_trusted_directory_chain(&parent).expect("trusted output parent");
    let mut temporary =
        create_new_private_file_at(&directory, OsStr::new("state.tmp")).expect("temporary file");
    temporary.write_all(b"published").expect("temporary bytes");
    temporary.sync_all().expect("temporary sync");
    drop(temporary);

    std::fs::rename(&container, root.path().join("displaced"))
        .expect_err("an opened ancestor without delete sharing must remain pinned");
    publish_file_replace_at(
        &directory,
        OsStr::new("state.tmp"),
        OsStr::new("state.json"),
    )
    .expect("write-through publication");

    assert_eq!(
        std::fs::read(parent.join("state.json")).expect("published target"),
        b"published"
    );
}
