use super::super::DirectoryTrustError;
use super::components::{normal_components, normal_components_allow_relative};
#[cfg(target_os = "macos")]
use super::identity::resolved_path_inspection_error;
use super::security::{mode_is_trusted, owner_is_trusted, validate_owner};
use super::symlink::read_trusted_system_symlink;
use super::*;
use std::ffi::OsStr;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

fn strict_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("netdiag-strict-platform-trust-test-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("trusted tempdir")
}

#[test]
fn strict_policy_rejects_sticky_root_accepted_for_system_paths() {
    let system_temp = std::fs::canonicalize("/tmp").expect("canonical system temp");
    open(&system_temp, false).expect("system policy accepts root-owned sticky temp");
    let error =
        open_strict(&system_temp).expect_err("strict code path must reject writable sticky temp");
    assert!(matches!(error, DirectoryTrustError::Writable { .. }));
}

#[test]
fn strict_policy_helpers_reject_untrusted_owners_and_writable_modes() {
    assert!(owner_is_trusted(0, 501));
    assert!(owner_is_trusted(501, 501));
    assert!(!owner_is_trusted(502, 501));
    assert!(mode_is_trusted(
        0o755,
        501,
        DirectoryTrustPolicy::StrictNoFollow
    ));
    assert!(!mode_is_trusted(
        0o1777,
        0,
        DirectoryTrustPolicy::StrictNoFollow
    ));
    assert!(mode_is_trusted(
        0o1777,
        0,
        DirectoryTrustPolicy::TrustedSystemPath
    ));

    let effective_uid = rustix::process::geteuid().as_raw();
    let foreign_uid = if effective_uid == 1 { 2 } else { 1 };
    let path = Path::new("/fixture/foreign-owner");
    let error = validate_owner(path, foreign_uid, effective_uid)
        .expect_err("foreign owner must fail closed");
    assert!(matches!(
        error,
        DirectoryTrustError::UntrustedOwner {
            path: error_path,
            owner,
        } if error_path == path && owner == format!("uid {foreign_uid}")
    ));
}

#[test]
fn entrypoints_and_component_parsers_reject_unsafe_paths() {
    let relative = Path::new("relative/path");
    assert!(matches!(
        open(relative, false),
        Err(DirectoryTrustError::NotAbsolute { path }) if path == relative
    ));
    assert!(matches!(
        open_strict_regular_file(relative),
        Err(DirectoryTrustError::NotAbsolute { path }) if path == relative
    ));
    assert!(matches!(
        normal_components(relative),
        Err(DirectoryTrustError::NotAbsolute { path }) if path == relative
    ));

    let escaping = Path::new("../escape");
    assert!(matches!(
        normal_components_allow_relative(escaping),
        Err(DirectoryTrustError::InvalidComponent { path }) if path == escaping
    ));
    assert!(matches!(
        open_strict_regular_file(Path::new("/")),
        Err(DirectoryTrustError::InvalidComponent { path }) if path == Path::new("/")
    ));
    assert!(matches!(
        open_strict_regular_file(Path::new("/fixture/..")),
        Err(DirectoryTrustError::InvalidComponent { path }) if path == Path::new("/fixture/..")
    ));
}

#[test]
fn strict_regular_file_open_rejects_symlinks_writable_files_and_wrong_shapes() {
    let root = strict_tempdir();
    let regular = root.path().join("regular");
    std::fs::write(&regular, b"fixture").expect("regular file");
    open_strict_regular_file(&regular).expect("strict regular file");

    let linked = root.path().join("linked");
    symlink(&regular, &linked).expect("file symlink");
    let symlink_error =
        open_strict_regular_file(&linked).expect_err("final symlink must fail closed");
    assert!(matches!(
        symlink_error,
        DirectoryTrustError::UntrustedSymlink { .. }
    ));

    std::fs::set_permissions(&regular, std::fs::Permissions::from_mode(0o666))
        .expect("writable file mode");
    let writable_error =
        open_strict_regular_file(&regular).expect_err("writable regular file must fail closed");
    assert!(matches!(
        writable_error,
        DirectoryTrustError::Writable { .. }
    ));

    let shape_error = open_strict_regular_file(root.path())
        .expect_err("directory must not pass as a regular file");
    assert!(matches!(
        shape_error,
        DirectoryTrustError::NotRegularFile { .. }
    ));
}

#[test]
fn strict_relative_primitives_validate_components_and_opened_shapes() {
    let root = strict_tempdir();
    let parent = std::fs::File::open(root.path()).expect("opened parent");
    let invalid = open_strict_directory_at(
        &parent,
        std::ffi::OsStr::new("../escape"),
        &root.path().join("../escape"),
    )
    .expect_err("multi-component name must fail closed");
    assert!(matches!(
        invalid,
        DirectoryTrustError::InvalidComponent { .. }
    ));

    let regular = root.path().join("regular");
    std::fs::write(&regular, b"fixture").expect("regular file");
    let regular_file = std::fs::File::open(&regular).expect("opened regular file");
    let public_metadata = crate::validate_opened_strict_regular_file(&regular, &regular_file)
        .expect("public handle validation");
    assert_eq!(
        public_metadata.ino(),
        regular_file.metadata().expect("regular metadata").ino()
    );

    let relative_directory_shape =
        open_strict_directory_at(&parent, OsStr::new("regular"), &regular)
            .expect_err("regular child must not open as a strict directory");
    assert!(matches!(
        relative_directory_shape,
        DirectoryTrustError::NotDirectory { .. }
    ));

    let trusted_directory_shape = validate_directory(
        &regular,
        &regular_file,
        DirectoryTrustPolicy::TrustedSystemPath,
    )
    .expect_err("regular file must not validate as a trusted directory");
    assert!(matches!(
        trusted_directory_shape,
        DirectoryTrustError::NotDirectory { .. }
    ));

    let directory_shape = validate_opened_strict_directory(&regular, &regular_file)
        .expect_err("regular file must not pass as a directory");
    assert!(matches!(
        directory_shape,
        DirectoryTrustError::NotDirectory { .. }
    ));
    let file_shape = validate_opened_strict_regular_file(root.path(), &parent)
        .expect_err("directory must not pass as a regular file");
    assert!(matches!(
        file_shape,
        DirectoryTrustError::NotRegularFile { .. }
    ));
}

#[test]
fn strict_directory_chain_rejects_final_symlink() {
    let root = strict_tempdir();
    let real = root.path().join("real");
    std::fs::create_dir(&real).expect("real directory");
    let linked = root.path().join("linked");
    symlink("real", &linked).expect("directory symlink");

    let error = open_strict(&linked).expect_err("strict directory chain must not follow symlink");
    assert!(matches!(
        error,
        DirectoryTrustError::UntrustedSymlink { path, detail }
            if path == linked && detail == "strict directory chains do not follow symlinks"
    ));
}

#[test]
fn system_symlink_validation_preserves_policy_and_io_errors() {
    let untrusted_parent = tempfile::tempdir().expect("untrusted parent fixture");
    std::fs::set_permissions(
        untrusted_parent.path(),
        std::fs::Permissions::from_mode(0o770),
    )
    .expect("make parent group-writable");
    let untrusted_parent_file =
        std::fs::File::open(untrusted_parent.path()).expect("opened untrusted parent");
    let untrusted_candidate = untrusted_parent.path().join("linked");
    let policy_error = read_trusted_system_symlink(
        &untrusted_parent_file,
        untrusted_parent.path(),
        &untrusted_candidate,
        OsStr::new("linked"),
        0,
    )
    .expect_err("root-owned symlink under writable parent must fail closed");
    assert!(matches!(
        policy_error,
        DirectoryTrustError::UntrustedSymlink { path, detail }
            if path == untrusted_candidate
                && detail == "root-owned symlink is not under a root-owned non-writable parent"
    ));

    let root = std::fs::File::open("/").expect("opened root");
    let missing_name = format!("netdiag-missing-system-symlink-{}", std::process::id());
    let missing_candidate = Path::new("/").join(&missing_name);
    assert!(!missing_candidate.exists(), "fixture name must be absent");
    let read_error = read_trusted_system_symlink(
        &root,
        Path::new("/"),
        &missing_candidate,
        OsStr::new(&missing_name),
        0,
    )
    .expect_err("missing symlink must preserve readlink failure");
    match read_error {
        DirectoryTrustError::Inspect { path, source } => {
            assert_eq!(path, missing_candidate);
            assert_eq!(source.kind(), io::ErrorKind::NotFound);
        }
        other => panic!("expected structured readlink inspection error: {other}"),
    }
}

#[cfg(target_os = "macos")]
#[test]
fn handle_path_error_mapping_preserves_reported_path_and_source() {
    let reported = Path::new("/fixture/reported-path").to_path_buf();
    let expected_source: io::Error = rustix::io::Errno::BADF.into();
    let error = resolved_path_inspection_error(reported.clone(), rustix::io::Errno::BADF);

    match error {
        DirectoryTrustError::Inspect { path, source } => {
            assert_eq!(path, reported);
            assert_eq!(source.raw_os_error(), expected_source.raw_os_error());
        }
        other => panic!("expected structured handle-path inspection error: {other}"),
    }
}

#[test]
fn user_owned_ancestor_symlink_is_rejected() {
    let root = tempfile::tempdir().expect("tempdir");
    let real = root.path().join("real");
    std::fs::create_dir(&real).expect("real directory");
    let linked = root.path().join("linked");
    symlink("real", &linked).expect("user symlink");

    let error = match open(&linked, false) {
        Err(error) => error,
        Ok(_) => panic!("user symlink must fail closed"),
    };
    assert!(matches!(
        error,
        DirectoryTrustError::UntrustedSymlink { .. }
    ));
}

#[test]
fn trusted_system_temp_chain_can_be_opened() {
    let directory = open(Path::new("/tmp"), false).expect("trusted /tmp chain");
    assert!(directory.resolved_path().is_absolute());
    directory.validate_identity().expect("stable /tmp identity");
}

#[test]
fn non_sticky_group_or_world_writable_directory_is_rejected() {
    let root = tempfile::tempdir().expect("tempdir");
    let writable = root.path().join("writable");
    std::fs::create_dir(&writable).expect("writable directory");
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777))
        .expect("writable mode");

    let error = match open(&writable, false) {
        Err(error) => error,
        Ok(_) => panic!("untrusted writable directory must fail closed"),
    };
    assert!(matches!(error, DirectoryTrustError::Writable { .. }));
}

#[test]
fn create_missing_uses_private_mode() {
    let root = tempfile::tempdir().expect("tempdir");
    let missing = root.path().join("new").join("nested");

    let directory = open(&missing, true).expect("create trusted chain");

    assert_eq!(
        directory
            .as_file()
            .metadata()
            .expect("created metadata")
            .mode()
            & 0o7777,
        0o700
    );
}

#[test]
fn trusted_subdirectory_rejects_a_symlink_without_touching_its_target() {
    let root = tempfile::tempdir().expect("tempdir");
    let external = tempfile::tempdir().expect("external tempdir");
    let sentinel = external.path().join("sentinel");
    std::fs::write(&sentinel, b"unchanged").expect("sentinel");
    symlink(external.path(), root.path().join("linked")).expect("directory symlink");
    let parent = open(root.path(), false).expect("trusted parent");

    let error = super::open_or_create_child(&parent, OsStr::new("linked"), true)
        .expect_err("symlink child must fail closed");

    assert!(matches!(
        error,
        DirectoryTrustError::UntrustedSymlink { .. }
    ));
    assert_eq!(
        std::fs::read(&sentinel).expect("sentinel bytes"),
        b"unchanged"
    );
}

#[test]
fn public_subdirectory_entrypoints_create_reopen_and_validate_names() {
    let root = tempfile::tempdir().expect("tempdir");
    let parent = open(root.path(), false).expect("trusted parent");

    let child = crate::open_or_create_trusted_subdirectory(&parent, OsStr::new("child"))
        .expect("create non-durable child");
    assert_eq!(
        child.resolved_path(),
        std::fs::canonicalize(root.path().join("child"))
            .expect("canonical child")
            .as_path()
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
    let reopened = crate::open_or_create_trusted_subdirectory(&parent, OsStr::new("child"))
        .expect("reopen non-durable child");
    assert_eq!(
        reopened.coordination_identity().expect("reopened identity"),
        child.coordination_identity().expect("created identity")
    );

    let durable =
        crate::open_or_create_durable_trusted_subdirectory(&parent, OsStr::new("durable"))
            .expect("create durable child");
    durable
        .validate_identity()
        .expect("durable child identity remains stable");

    for open_child in [
        crate::open_or_create_trusted_subdirectory,
        crate::open_or_create_durable_trusted_subdirectory,
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

#[test]
fn missing_subdirectory_reports_parent_write_denial_without_creating_an_entry() {
    let root = tempfile::tempdir().expect("tempdir");
    let parent = open(root.path(), false).expect("trusted parent");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o500))
        .expect("restrict parent writes");

    let candidate = parent.resolved_path().join("blocked");
    let error = crate::open_or_create_trusted_subdirectory(&parent, OsStr::new("blocked"))
        .expect_err("child creation without parent write permission must fail");

    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("restore parent permissions");
    assert!(matches!(
        error,
        DirectoryTrustError::Inspect { path, source }
            if path == candidate && source.kind() == io::ErrorKind::PermissionDenied
    ));
    assert!(
        !candidate.exists(),
        "failed creation must not leave an entry"
    );
}

#[test]
fn nofollow_error_classification_preserves_shape_and_io_failures() {
    let root = tempfile::tempdir().expect("tempdir");
    let parent = std::fs::File::open(root.path()).expect("opened parent");
    let missing = root.path().join("missing");

    let missing_error = classify_nofollow_directory_error(
        &parent,
        OsStr::new("missing"),
        &missing,
        Errno::NOTDIR,
        "fixture symlink detail",
    );
    assert!(matches!(
        missing_error,
        DirectoryTrustError::Inspect { path, source }
            if path == missing && source.kind() == io::ErrorKind::NotFound
    ));

    let denied_candidate = root.path().join("denied");
    let denied_error = classify_nofollow_directory_error(
        &parent,
        OsStr::new("denied"),
        &denied_candidate,
        Errno::ACCESS,
        "fixture symlink detail",
    );
    let expected_denied: io::Error = Errno::ACCESS.into();
    assert!(matches!(
        denied_error,
        DirectoryTrustError::Inspect { path, source }
            if path == denied_candidate
                && source.raw_os_error() == expected_denied.raw_os_error()
    ));

    let regular = root.path().join("regular");
    std::fs::write(&regular, b"fixture").expect("regular file");
    let shape_error = open_nofollow_directory(
        &parent,
        OsStr::new("regular"),
        &regular,
        "fixture symlink detail",
    )
    .expect_err("regular file must not open as a directory");
    assert!(matches!(
        shape_error,
        DirectoryTrustError::NotDirectory { path } if path == regular
    ));

    let loop_error = classify_nofollow_directory_error(
        &parent,
        OsStr::new("regular"),
        &regular,
        Errno::LOOP,
        "fixture symlink detail",
    );
    let expected_loop: io::Error = Errno::LOOP.into();
    assert!(matches!(
        loop_error,
        DirectoryTrustError::Inspect { path, source }
            if path == regular && source.raw_os_error() == expected_loop.raw_os_error()
    ));
}

#[test]
fn durable_open_accepts_existing_chains_and_creates_missing_suffixes() {
    let root = tempfile::tempdir().expect("tempdir");
    open_durable(root.path()).expect("persist existing chain");

    let missing = root.path().join("durable").join("nested");
    let directory = open_durable(&missing).expect("create durable chain");

    assert_eq!(
        directory.resolved_path(),
        std::fs::canonicalize(&missing)
            .expect("canonical durable path")
            .as_path()
    );
}

#[test]
fn directory_identity_replacement_is_detected() {
    let root = tempfile::tempdir().expect("tempdir");
    let watched = root.path().join("watched");
    std::fs::create_dir(&watched).expect("watched directory");
    let directory = open(&watched, false).expect("open watched directory");
    let displaced = root.path().join("displaced");
    std::fs::rename(&watched, &displaced).expect("displace watched directory");
    std::fs::create_dir(&watched).expect("replacement directory");
    std::fs::set_permissions(&watched, std::fs::Permissions::from_mode(0o700))
        .expect("replacement mode");

    let error = directory
        .validate_identity()
        .expect_err("replacement must change identity");
    assert!(matches!(error, DirectoryTrustError::IdentityChanged { .. }));
}

#[cfg(target_os = "macos")]
#[test]
fn handle_path_normalizes_case_aliases() {
    let users = open(Path::new("/Users"), false).expect("canonical Users directory");
    let alias = open(Path::new("/users"), false).expect("case alias Users directory");

    assert_eq!(users.resolved_path(), alias.resolved_path());
}

#[cfg(target_os = "macos")]
#[test]
fn handle_path_normalizes_unicode_aliases_when_the_volume_does() {
    let root = tempfile::tempdir().expect("tempdir");
    let composed = root.path().join("caf\u{e9}");
    let decomposed = root.path().join("cafe\u{301}");
    std::fs::create_dir(&composed).expect("composed directory");
    if !decomposed.exists() {
        return;
    }

    let stored = open(&composed, false).expect("stored Unicode directory");
    let alias = open(&decomposed, false).expect("normalized Unicode alias");
    assert_eq!(stored.resolved_path(), alias.resolved_path());
}
