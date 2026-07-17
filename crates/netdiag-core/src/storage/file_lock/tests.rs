use super::{
    exclusive_bound_file_lock_path, exclusive_file_lock_path, prepare_lock_set,
    with_exclusive_file_lock, with_exclusive_file_lock_in_namespace, with_exclusive_file_locks,
};
#[cfg(unix)]
use super::{exclusive_file_lock_path_in_namespace, with_exclusive_bound_file_lock};
use crate::error::{IoContext, NetdiagError};
#[cfg(windows)]
use sha2::{Digest, Sha256};
use std::error::Error;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;

const CHILD_TARGET_ENV: &str = "NETDIAG_LOCK_TEST_TARGET";
const CHILD_NAMESPACE_ENV: &str = "NETDIAG_LOCK_TEST_NAMESPACE";
const CHILD_STARTED_ENV: &str = "NETDIAG_LOCK_TEST_STARTED";
const CHILD_ENTERED_ENV: &str = "NETDIAG_LOCK_TEST_ENTERED";
#[cfg(windows)]
const CHILD_RELEASE_ENV: &str = "NETDIAG_LOCK_TEST_RELEASE";
#[cfg(windows)]
const CHILD_LOCK_DIGEST_ENV: &str = "NETDIAG_LOCK_TEST_DIGEST";

#[test]
fn bound_and_path_writers_share_the_same_coordination_stripe() {
    let root = tempfile::tempdir().expect("tempdir");
    let target = root.path().join("state.json");
    let bound = crate::storage::BoundAtomicFileTarget::bind(&target).expect("bound target");

    assert_eq!(
        exclusive_bound_file_lock_path(&bound).expect("bound lock path"),
        exclusive_file_lock_path(&target).expect("path lock path")
    );
}

#[cfg(unix)]
#[test]
fn bound_publication_preserves_phase_when_parent_moves_after_commit() {
    let root = tempfile::tempdir().expect("tempdir");
    let parent = root.path().join("output");
    std::fs::create_dir(&parent).expect("output parent");
    let target = parent.join("state.json");
    let bound = crate::storage::BoundAtomicFileTarget::bind(&target).expect("bound target");
    let displaced = root.path().join("displaced-output");

    let error = with_exclusive_bound_file_lock(&bound, || {
        crate::storage::write_file_atomically_to_bound(&bound, &target, "json", |file| {
            use std::io::Write;
            file.write_all(b"published").with_path(&target)
        })?;
        std::fs::rename(&parent, &displaced).with_path(&parent)
    })
    .expect_err("post-commit parent identity change must be explicit");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(crate::error::AtomicPublishPhase::Published)
    );
    assert_eq!(
        std::fs::read(displaced.join("state.json")).expect("published bytes"),
        b"published"
    );
}

#[test]
fn real_second_writer_waits_for_the_first_writer() {
    let temp = tempfile::tempdir().expect("tempdir");
    let target = Arc::new(temp.path().join("state.json"));
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let holder_target = Arc::clone(&target);
    let holder = std::thread::spawn(move || {
        with_exclusive_file_lock(&holder_target, || {
            held_tx.send(()).expect("signal held lock");
            release_rx.recv().expect("release held lock");
            Ok(())
        })
    });
    held_rx.recv().expect("holder reached action");

    let (waiter_tx, waiter_rx) = mpsc::channel();
    let waiter_target = Arc::clone(&target);
    let waiter = std::thread::spawn(move || {
        waiter_tx
            .send(with_exclusive_file_lock(&waiter_target, || Ok(())))
            .expect("send waiter result");
    });
    let early_result = waiter_rx.recv_timeout(Duration::from_millis(100));
    let waited = matches!(&early_result, Err(mpsc::RecvTimeoutError::Timeout));
    release_tx.send(()).expect("release holder");
    holder.join().expect("holder thread").expect("holder lock");
    let waiter_result = match early_result {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => waiter_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("waiter completed after release"),
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("waiter disconnected"),
    };
    waiter.join().expect("waiter thread");
    assert!(
        waited,
        "second writer entered before the first released the lock"
    );
    waiter_result.expect("waiter lock");
}

#[cfg(unix)]
#[test]
fn replacement_during_action_does_not_split_same_process_writers() {
    use std::os::unix::fs::OpenOptionsExt;

    let root = tempfile::tempdir().expect("tempdir");
    let namespace = private_namespace(root.path());
    let target_parent = root.path().join("targets");
    std::fs::create_dir(&target_parent).expect("target parent");
    let target = target_parent.join("state.json");
    let lock_path =
        exclusive_file_lock_path_in_namespace(&target, &namespace).expect("isolated lock path");
    let displaced = namespace.join("displaced.lock");
    let mut waiter = None;
    let mut waiter_rx = None;

    with_exclusive_file_lock_in_namespace(&target, &namespace, || {
        let original = crate::file_identity::open_file(&lock_path)?;
        std::fs::rename(&lock_path, &displaced).with_path(&lock_path)?;
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&lock_path)
            .with_path(&lock_path)?;

        let (result_tx, result_rx) = mpsc::channel();
        let waiter_target = target.clone();
        let waiter_namespace = namespace.clone();
        waiter = Some(std::thread::spawn(move || {
            result_tx
                .send(with_exclusive_file_lock_in_namespace(
                    &waiter_target,
                    &waiter_namespace,
                    || Ok(()),
                ))
                .expect("send waiter result");
        }));
        let early = result_rx.recv_timeout(Duration::from_millis(100));
        std::fs::remove_file(&lock_path).with_path(&lock_path)?;
        std::fs::rename(&displaced, &lock_path).with_path(&lock_path)?;
        let restored = crate::file_identity::open_file(&lock_path)?;
        assert!(crate::file_identity::same_file(
            &original, &restored, &lock_path
        )?);
        assert!(
            matches!(early, Err(mpsc::RecvTimeoutError::Timeout)),
            "second writer entered a replacement stripe while the first action was active"
        );
        waiter_rx = Some(result_rx);
        Ok(())
    })
    .expect("outer isolated lock");

    waiter_rx
        .expect("waiter receiver")
        .recv_timeout(Duration::from_secs(2))
        .expect("waiter completed after original stripe restoration")
        .expect("waiter lock");
    waiter
        .expect("waiter handle")
        .join()
        .expect("waiter thread");
}

#[test]
fn operating_system_lock_blocks_a_second_process() {
    let root = tempfile::tempdir().expect("tempdir");
    let namespace = private_namespace(root.path());
    let target_parent = root.path().join("targets");
    std::fs::create_dir(&target_parent).expect("target parent");
    let target = target_parent.join("state.json");
    let started = root.path().join("child-started");
    let entered = root.path().join("child-entered");
    let mut child = None;

    with_exclusive_file_lock_in_namespace(&target, &namespace, || {
        child = Some(
            Command::new(std::env::current_exe().expect("current test executable"))
                .args([
                    "--exact",
                    "storage::file_lock::tests::subprocess_lock_waiter_helper",
                    "--nocapture",
                ])
                .env(CHILD_TARGET_ENV, &target)
                .env(CHILD_NAMESPACE_ENV, &namespace)
                .env(CHILD_STARTED_ENV, &started)
                .env(CHILD_ENTERED_ENV, &entered)
                .spawn()
                .expect("spawn lock waiter process"),
        );
        wait_for_path(&started, Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !entered.exists(),
            "child process entered while the parent held the OS lock"
        );
        Ok(())
    })
    .expect("parent process lock");

    let status = wait_for_child(
        child.as_mut().expect("child process"),
        Duration::from_secs(2),
    );
    assert!(status.success(), "child waiter failed: {status}");
    assert!(entered.exists(), "child never entered after lock release");
}

#[test]
fn subprocess_lock_waiter_helper() {
    let Some(target) = std::env::var_os(CHILD_TARGET_ENV).map(PathBuf::from) else {
        return;
    };
    let started = required_child_path(CHILD_STARTED_ENV);
    let entered = required_child_path(CHILD_ENTERED_ENV);
    std::fs::write(&started, b"started").expect("write child-started marker");
    let enter = || {
        std::fs::write(&entered, b"entered").with_path(&entered)?;
        Ok(())
    };
    match std::env::var_os(CHILD_NAMESPACE_ENV).map(PathBuf::from) {
        Some(namespace) => with_exclusive_file_lock_in_namespace(&target, &namespace, enter),
        None => {
            #[cfg(windows)]
            write_default_lock_path_digest_if_requested(&target);
            with_exclusive_file_lock(&target, enter)
        }
    }
    .expect("child process lock");
}

#[cfg(windows)]
#[test]
fn default_namespace_is_stable_across_distinct_process_temp_roots() {
    let root = tempfile::tempdir().expect("test root");
    let target_parent = root.path().join("targets");
    netdiag_platform::open_or_create_trusted_directory_chain(&target_parent)
        .expect("private target parent");
    let target = target_parent.join("state.json");
    let first_temp = root.path().join("first-temp");
    let second_temp = root.path().join("second-temp");
    std::fs::create_dir(&first_temp).expect("first process temp root");
    std::fs::create_dir(&second_temp).expect("second process temp root");
    let holder_started = root.path().join("holder-started");
    let waiter_started = root.path().join("waiter-started");
    let waiter_entered = root.path().join("waiter-entered");
    let holder_digest = root.path().join("holder-lock-digest");
    let waiter_digest = root.path().join("waiter-lock-digest");
    let release = root.path().join("release-holder");

    let mut holder = child_test_command("subprocess_default_lock_holder_helper")
        .env(CHILD_TARGET_ENV, &target)
        .env(CHILD_STARTED_ENV, &holder_started)
        .env(CHILD_RELEASE_ENV, &release)
        .env(CHILD_LOCK_DIGEST_ENV, &holder_digest)
        .env_remove(CHILD_NAMESPACE_ENV)
        .env("TEMP", &first_temp)
        .env("TMP", &first_temp)
        .spawn()
        .expect("spawn default-namespace holder");
    wait_for_path(&holder_started, Duration::from_secs(5));

    let mut waiter = child_test_command("subprocess_lock_waiter_helper")
        .env(CHILD_TARGET_ENV, &target)
        .env(CHILD_STARTED_ENV, &waiter_started)
        .env(CHILD_ENTERED_ENV, &waiter_entered)
        .env(CHILD_LOCK_DIGEST_ENV, &waiter_digest)
        .env_remove(CHILD_NAMESPACE_ENV)
        .env("TEMP", &second_temp)
        .env("TMP", &second_temp)
        .spawn()
        .expect("spawn default-namespace waiter");
    wait_for_path(&waiter_started, Duration::from_secs(5));
    wait_for_path(&holder_digest, Duration::from_secs(5));
    wait_for_path(&waiter_digest, Duration::from_secs(5));
    let namespace_is_stable = std::fs::read(&holder_digest).expect("holder lock digest")
        == std::fs::read(&waiter_digest).expect("waiter lock digest");
    std::thread::sleep(Duration::from_millis(150));
    let waiter_was_blocked = !waiter_entered.exists();
    std::fs::write(&release, b"release").expect("release holder process");

    let holder_status = wait_for_child(&mut holder, Duration::from_secs(5));
    let waiter_status = wait_for_child(&mut waiter, Duration::from_secs(5));
    assert!(holder_status.success(), "holder failed: {holder_status}");
    assert!(waiter_status.success(), "waiter failed: {waiter_status}");
    assert!(
        namespace_is_stable,
        "different TEMP/TMP values produced different default lock paths"
    );
    assert!(
        waiter_was_blocked,
        "different TEMP/TMP values split the default coordination namespace"
    );
    assert!(
        waiter_entered.exists(),
        "waiter never entered after release"
    );
}

#[cfg(windows)]
#[test]
fn subprocess_default_lock_holder_helper() {
    let Some(target) = std::env::var_os(CHILD_TARGET_ENV).map(PathBuf::from) else {
        return;
    };
    let started = required_child_path(CHILD_STARTED_ENV);
    let release = required_child_path(CHILD_RELEASE_ENV);
    write_default_lock_path_digest_if_requested(&target);
    with_exclusive_file_lock(&target, || {
        std::fs::write(&started, b"started").with_path(&started)?;
        wait_for_path(&release, Duration::from_secs(10));
        Ok(())
    })
    .expect("holder process lock");
}

#[cfg(unix)]
#[test]
fn coordination_root_mapping_preserves_resolution_context_and_source_chain() {
    let path = PathBuf::from("/missing-coordination-root");
    let platform_error = netdiag_platform::SystemTemporaryRootError::Resolution {
        path: path.clone(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing fixture"),
    };
    let error = super::key::coordination_system_temporary_root_error(platform_error);

    assert!(matches!(
        &error,
        NetdiagError::CoordinationSystemTemporaryRoot { context, source }
            if *context == "coordination lock namespace"
                && matches!(source, netdiag_platform::SystemTemporaryRootError::Resolution { path: source_path, .. } if source_path == &path)
    ));
    let platform_source = error.source().expect("platform source");
    assert!(
        platform_source.source().is_some(),
        "I/O source must remain chained"
    );
}

#[cfg(unix)]
#[test]
fn coordination_root_mapping_preserves_unsupported_platform_semantics() {
    let error = super::key::coordination_system_temporary_root_error(
        netdiag_platform::SystemTemporaryRootError::UnsupportedPlatform,
    );
    assert!(matches!(
        error,
        NetdiagError::CoordinationSystemTemporaryRoot {
            source: netdiag_platform::SystemTemporaryRootError::UnsupportedPlatform,
            ..
        }
    ));
}

#[test]
fn combined_lock_failures_preserve_both_typed_errors() {
    let primary = NetdiagError::InvalidTrace("primary fixture".to_string());
    let secondary = NetdiagError::Io {
        path: PathBuf::from("secondary.fixture"),
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "secondary fixture"),
    };
    let error = super::errors::combine_action_and_identity::<()>(Err(primary), Err(secondary))
        .expect_err("dual failure must remain structured");

    assert!(matches!(
        &error,
        NetdiagError::CombinedFailure {
            primary_context: "locked update failed",
            primary,
            secondary_context: "coordination lock identity validation also failed",
            secondary,
        } if matches!(primary.as_ref(), NetdiagError::InvalidTrace(message) if message == "primary fixture")
            && matches!(secondary.as_ref(), NetdiagError::Io { path, .. } if path == &PathBuf::from("secondary.fixture"))
    ));
    assert_eq!(
        error.source().map(ToString::to_string),
        Some("invalid trace: primary fixture".to_string())
    );
}

#[test]
fn coordination_trust_mapping_preserves_platform_and_io_sources() {
    let path = PathBuf::from("trust.fixture");
    let platform_error = netdiag_platform::DirectoryTrustError::Inspect {
        path: path.clone(),
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "trust fixture"),
    };
    let error = super::errors::trust_error(platform_error);

    assert!(matches!(
        &error,
        NetdiagError::FilesystemTrust { context, source }
            if *context == "coordination directory"
                && matches!(source, netdiag_platform::DirectoryTrustError::Inspect { path: source_path, .. } if source_path == &path)
    ));
    let platform_source = error.source().expect("directory trust source");
    assert!(
        platform_source.source().is_some(),
        "underlying I/O source must remain chained"
    );
}

#[test]
fn atomic_publication_dual_failure_keeps_phase_and_both_causes() {
    let target = PathBuf::from("published.fixture");
    let primary = NetdiagError::AtomicPublish {
        path: target.clone(),
        phase: crate::error::AtomicPublishPhase::NotPublished,
        source: Box::new(NetdiagError::InvalidTrace(
            "publication fixture".to_string(),
        )),
    };
    let completion = NetdiagError::Io {
        path: target.clone(),
        source: std::io::Error::other("completion fixture"),
    };
    let error = super::errors::combine_publication_completion::<()>(
        Err(primary),
        Err(completion),
        &target,
        "lock release also failed",
    )
    .expect_err("publication and completion failure must both survive");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(crate::error::AtomicPublishPhase::NotPublished)
    );
    assert!(matches!(
        error,
        NetdiagError::AtomicPublish { source, .. }
            if matches!(source.as_ref(), NetdiagError::CombinedFailure {
                primary: combined_primary,
                secondary: combined_secondary,
                ..
            } if matches!(combined_primary.as_ref(), NetdiagError::InvalidTrace(message) if message == "publication fixture")
                && matches!(combined_secondary.as_ref(), NetdiagError::Io { path, .. } if path == &target))
    ));
}

#[cfg(unix)]
#[test]
fn target_parent_chain_rejects_user_owned_symlink() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let real_parent = temp.path().join("real");
    std::fs::create_dir(&real_parent).expect("real parent");
    let linked_parent = temp.path().join("linked");
    symlink("real", &linked_parent).expect("linked parent");
    let called = AtomicBool::new(false);

    let error = with_exclusive_file_lock(&linked_parent.join("state.json"), || {
        called.store(true, Ordering::Relaxed);
        Ok(())
    })
    .expect_err("user-owned ancestor symlink must fail closed");

    assert!(!called.load(Ordering::Relaxed));
    assert!(error.to_string().contains("untrusted symlink"), "{error}");
}

#[test]
fn relative_alias_is_reentrant_with_the_absolute_target() {
    let current = std::env::current_dir().expect("current directory");
    let temp = tempfile::Builder::new()
        .prefix("netdiag-lock-alias-")
        .tempdir_in(&current)
        .expect("workspace tempdir");
    let absolute = temp.path().join("state.json");
    let relative = PathBuf::from(".").join(
        absolute
            .strip_prefix(&current)
            .expect("target inside current directory"),
    );
    assert_eq!(
        exclusive_file_lock_path(&absolute).expect("absolute lock path"),
        exclusive_file_lock_path(&relative).expect("relative lock path")
    );

    with_exclusive_file_lock(&absolute, || {
        with_exclusive_file_lock(&relative, || {
            std::fs::write(&absolute, b"nested").with_path(&absolute)?;
            Ok(())
        })
    })
    .expect("relative alias reentrancy");
    assert_eq!(std::fs::read(&absolute).expect("nested result"), b"nested");
}

#[cfg(target_os = "macos")]
#[test]
fn macos_case_aliases_share_a_coordination_stripe() {
    let temp = tempfile::tempdir().expect("tempdir");
    let upper = temp.path().join("STATE.json");
    let lower = temp.path().join("state.json");

    assert_eq!(
        exclusive_file_lock_path(&upper).expect("upper lock path"),
        exclusive_file_lock_path(&lower).expect("lower lock path")
    );
}

#[test]
fn lock_sets_are_acquired_in_physical_stripe_order() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut targets = (0..64)
        .map(|index| temp.path().join(format!("target-{index}.json")))
        .collect::<Vec<_>>();
    targets.reverse();
    let prepared = prepare_lock_set(&targets).expect("prepared lock set");
    let ordered = prepared
        .windows(2)
        .all(|pair| pair[0].key() <= pair[1].key());

    assert!(ordered, "physical stripe keys must have one global order");
    with_exclusive_file_locks(&targets, || Ok(())).expect("ordered lock set");
}

#[test]
fn physical_stripe_collisions_keep_every_target_validation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (first, second) = colliding_targets(temp.path());
    let prepared = prepare_lock_set(&[first, second]).expect("colliding lock set");

    assert_eq!(prepared.len(), 2);
    assert_eq!(prepared[0].key(), prepared[1].key());
    assert_ne!(prepared[0].target(), prepared[1].target());
}

#[test]
fn distinct_stripes_allow_parallel_actions_from_different_parents() {
    let temp = tempfile::tempdir().expect("tempdir");
    let first = temp.path().join("first").join("state.json");
    let first_lock = exclusive_file_lock_path(&first).expect("first lock path");
    let second = different_stripe_target(temp.path(), &first_lock);
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let (entered_tx, entered_rx) = mpsc::channel();
    let handles = [first, second]
        .into_iter()
        .map(|target| {
            let entered_tx = entered_tx.clone();
            let release = Arc::clone(&release);
            std::thread::spawn(move || {
                with_exclusive_file_lock(&target, || {
                    entered_tx.send(()).expect("signal entered action");
                    let (released, condition) = &*release;
                    let mut released = released.lock().expect("release state");
                    while !*released {
                        released = condition.wait(released).expect("release wait");
                    }
                    Ok(())
                })
            })
        })
        .collect::<Vec<_>>();
    drop(entered_tx);

    let first_entered = entered_rx.recv_timeout(Duration::from_secs(2));
    let second_entered = entered_rx.recv_timeout(Duration::from_secs(2));
    let (released, condition) = &*release;
    *released.lock().expect("release state") = true;
    condition.notify_all();
    for handle in handles {
        handle.join().expect("writer thread").expect("writer lock");
    }
    first_entered.expect("first action entered");
    second_entered.expect("distinct stripe action entered concurrently");
}

#[test]
fn namespace_targets_and_parent_components_fail_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let safe_target = temp.path().join("safe.json");
    let namespace = exclusive_file_lock_path(&safe_target)
        .expect("safe lock path")
        .parent()
        .expect("lock namespace")
        .to_path_buf();
    let called = AtomicBool::new(false);
    let error = with_exclusive_file_lock(&namespace.join("business.json"), || {
        called.store(true, Ordering::Relaxed);
        Ok(())
    })
    .expect_err("namespace target must fail closed");
    assert!(!called.load(Ordering::Relaxed));
    assert!(
        error.to_string().contains("private lock namespace"),
        "{error}"
    );

    let error = exclusive_file_lock_path(Path::new("../state.json"))
        .expect_err("parent component must not get a fallback lock path");
    assert!(error.to_string().contains("parent component"), "{error}");
}

#[test]
fn nested_namespace_target_is_rejected_before_parent_creation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let namespace = private_namespace(temp.path());
    let forbidden = namespace.join("new").join("deep").join("state.json");
    let called = AtomicBool::new(false);

    let error = with_exclusive_file_lock_in_namespace(&forbidden, &namespace, || {
        called.store(true, Ordering::Relaxed);
        Ok(())
    })
    .expect_err("nested namespace target must fail before directory creation");

    assert!(!called.load(Ordering::Relaxed));
    assert!(
        error.to_string().contains("private lock namespace"),
        "{error}"
    );
    assert!(!namespace.join("new").exists());
}

#[cfg(unix)]
#[test]
fn unsafe_namespace_mode_is_rejected_before_the_action() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let namespace = private_namespace(temp.path());
    std::fs::set_permissions(&namespace, std::fs::Permissions::from_mode(0o770))
        .expect("unsafe namespace mode");
    let called = AtomicBool::new(false);

    let error = with_exclusive_file_lock_in_namespace(
        &temp.path().join("target/state.json"),
        &namespace,
        || {
            called.store(true, Ordering::Relaxed);
            Ok(())
        },
    )
    .expect_err("unsafe namespace must fail closed");

    assert!(!called.load(Ordering::Relaxed));
    assert!(
        error
            .to_string()
            .contains("group/world-writable or writable by an untrusted principal"),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn public_coordination_file_is_rejected_before_the_action() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let namespace = private_namespace(temp.path());
    let target = temp.path().join("target/state.json");
    let lock_path = exclusive_file_lock_path_in_namespace(&target, &namespace).expect("lock path");
    std::fs::write(&lock_path, b"").expect("lock file");
    std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o644))
        .expect("public lock mode");
    let called = AtomicBool::new(false);

    let error = with_exclusive_file_lock_in_namespace(&target, &namespace, || {
        called.store(true, Ordering::Relaxed);
        Ok(())
    })
    .expect_err("public lock file must fail closed");

    assert!(!called.load(Ordering::Relaxed));
    assert!(error.to_string().contains("private 0600"), "{error}");
}

#[cfg(unix)]
#[test]
fn hard_linked_coordination_file_is_rejected_before_the_action() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let namespace = private_namespace(temp.path());
    let target = temp.path().join("target/state.json");
    let lock_path = exclusive_file_lock_path_in_namespace(&target, &namespace).expect("lock path");
    std::fs::write(&lock_path, b"").expect("lock file");
    std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))
        .expect("private lock mode");
    std::fs::hard_link(&lock_path, namespace.join("unexpected-link")).expect("extra hard link");
    let called = AtomicBool::new(false);

    let error = with_exclusive_file_lock_in_namespace(&target, &namespace, || {
        called.store(true, Ordering::Relaxed);
        Ok(())
    })
    .expect_err("hard-linked lock file must fail closed");

    assert!(!called.load(Ordering::Relaxed));
    assert!(error.to_string().contains("one link"), "{error}");
}

fn different_stripe_target(root: &Path, first_lock: &Path) -> PathBuf {
    (0..4096)
        .map(|index| root.join(format!("other-{index}")).join("state.json"))
        .find(|target| {
            exclusive_file_lock_path(target).is_ok_and(|candidate| candidate != first_lock)
        })
        .expect("a distinct stripe within the bounded namespace")
}

fn colliding_targets(root: &Path) -> (PathBuf, PathBuf) {
    let mut stripes = std::collections::HashMap::new();
    for index in 0..=4096 {
        let target = root.join(format!("collision-{index}.json"));
        let stripe = exclusive_file_lock_path(&target).expect("candidate stripe");
        if let Some(previous) = stripes.insert(stripe, target.clone()) {
            return (previous, target);
        }
    }
    panic!("4097 targets must collide in a 4096-stripe namespace");
}

fn private_namespace(root: &Path) -> PathBuf {
    let namespace = root.join("coordination");
    std::fs::create_dir(&namespace).expect("create isolated namespace");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&namespace, std::fs::Permissions::from_mode(0o700))
            .expect("private namespace mode");
    }
    namespace
}

fn required_child_path(name: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("missing child environment variable {name}"))
}

#[cfg(windows)]
fn child_test_command(test_name: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    command
        .arg("--exact")
        .arg(format!("storage::file_lock::tests::{test_name}"))
        .arg("--nocapture");
    command
}

#[cfg(windows)]
fn write_default_lock_path_digest_if_requested(target: &Path) {
    let Some(marker) = std::env::var_os(CHILD_LOCK_DIGEST_ENV).map(PathBuf::from) else {
        return;
    };
    let lock_path = exclusive_file_lock_path(target).expect("default lock path");
    let mut hasher = Sha256::new();
    for unit in lock_path.as_os_str().encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
    std::fs::write(marker, format!("{:x}", hasher.finalize()))
        .expect("write default lock path digest");
}

fn wait_for_path(path: &Path, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    while !path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("inspect child status") {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().expect("kill timed-out child");
            let _ = child.wait();
            panic!("timed out waiting for child lock process");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
