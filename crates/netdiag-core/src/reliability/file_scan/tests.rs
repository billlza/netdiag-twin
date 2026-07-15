use super::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn scan_limits_file_count_without_silently_truncating() {
    let temp = tempdir().expect("tempdir");
    fs::write(temp.path().join("one.json"), "{}").expect("first file");
    fs::write(temp.path().join("two.json"), "{}").expect("second file");

    let scan = scan(
        temp.path(),
        &["json"],
        true,
        ScanLimits {
            max_entries: 4,
            max_files: 1,
            max_file_bytes: 64,
            ..ScanLimits::default()
        },
    );

    assert_eq!(scan.files.len(), 1);
    assert!(
        scan.issues
            .iter()
            .any(|issue| issue.message.contains("file limit"))
    );
}

#[test]
fn scan_rejects_oversized_files() {
    let temp = tempdir().expect("tempdir");
    fs::write(temp.path().join("large.json"), "12345").expect("large file");

    let scan = scan(
        temp.path(),
        &["json"],
        true,
        ScanLimits {
            max_entries: 2,
            max_files: 2,
            max_file_bytes: 4,
            ..ScanLimits::default()
        },
    );

    assert!(scan.files.is_empty());
    assert!(
        scan.issues
            .iter()
            .any(|issue| issue.message.contains("scan limit"))
    );
}

#[test]
fn scan_total_byte_budget_accepts_the_exact_boundary() {
    let temp = tempdir().expect("tempdir");
    fs::write(temp.path().join("a.json"), "12").expect("first file");
    fs::write(temp.path().join("b.json"), "34").expect("second file");

    let scan = scan(
        temp.path(),
        &["json"],
        true,
        ScanLimits {
            max_entries: 4,
            max_files: 4,
            max_selected_files: 4,
            max_file_bytes: 4,
            max_total_file_bytes: 4,
        },
    );

    assert!(scan.issues.is_empty());
    assert_eq!(scan.files.len(), 2);
    let bodies = scan
        .files
        .into_iter()
        .map(ScannedFile::read_text)
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("read files at exact budget");
    assert_eq!(bodies, ["12", "34"]);
}

#[test]
fn scan_total_byte_budget_rejects_one_byte_over_without_hashing_it() {
    let temp = tempdir().expect("tempdir");
    fs::write(temp.path().join("a.json"), "12").expect("first file");
    fs::write(temp.path().join("b.json"), "345").expect("second file");

    let scan = scan(
        temp.path(),
        &["json"],
        true,
        ScanLimits {
            max_entries: 4,
            max_files: 4,
            max_selected_files: 4,
            max_file_bytes: 4,
            max_total_file_bytes: 4,
        },
    );

    assert_eq!(scan.files.len(), 1);
    assert!(scan.issues.iter().any(|issue| {
        issue.message.contains("total scanned file size 5 bytes")
            && issue.message.contains("4-byte scan limit")
    }));
}

#[test]
fn strict_named_scan_does_not_charge_unrelated_payload_bytes() {
    let temp = tempdir().expect("tempdir");
    fs::write(temp.path().join("unrelated.json"), "12345678").expect("unrelated file");
    fs::write(temp.path().join("telemetry_summary.json"), "{}").expect("summary");

    let files = scan_named_files_strict(
        temp.path(),
        std::ffi::OsStr::new("telemetry_summary.json"),
        StrictNamedScanLimits {
            max_entries: 2,
            max_files: 2,
            max_matches: 1,
            max_file_bytes: 2,
            max_total_file_bytes: 2,
        },
    )
    .expect("only matching payload bytes count toward the budget");

    assert_eq!(files.len(), 1);
    assert_eq!(
        files
            .into_iter()
            .next()
            .expect("summary")
            .read_text()
            .expect("read"),
        "{}"
    );
}

#[test]
fn strict_named_scan_rejects_match_limit_instead_of_truncating() {
    let temp = tempdir().expect("tempdir");
    for directory in ["a", "b"] {
        let run = temp.path().join(directory);
        fs::create_dir(&run).expect("run directory");
        fs::write(run.join("telemetry_summary.json"), "{}").expect("summary");
    }

    let error = scan_named_files_strict(
        temp.path(),
        std::ffi::OsStr::new("telemetry_summary.json"),
        StrictNamedScanLimits {
            max_entries: 4,
            max_files: 2,
            max_matches: 1,
            max_file_bytes: 2,
            max_total_file_bytes: 4,
        },
    )
    .expect_err("matching-file overflow must fail the complete scan");

    assert!(error.to_string().contains("selected-file limit"), "{error}");
}

#[test]
fn scanned_file_rejects_same_path_replacement_before_read() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("report.json");
    fs::write(&path, "{\"trusted\":true}").expect("trusted file");
    let scan = scan_recursive(temp.path(), &["json"]);
    assert!(scan.issues.is_empty());
    let scanned = scan.files.into_iter().next().expect("scanned file");

    fs::rename(&path, temp.path().join("original.json")).expect("move original");
    fs::write(&path, "{\"secret\":\"replacement\"}").expect("replacement");

    let issue = scanned
        .read_text()
        .expect_err("replacement must not be read");
    assert_eq!(issue.reason, ReliabilityReasonCode::PathEscapesArtifactRoot);
    assert!(issue.message.contains("changed identity"));
}

#[test]
fn scanned_file_rejects_in_place_mutation_before_read() {
    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("report.json");
    fs::write(&path, "{}").expect("trusted file");
    let scan = scan_recursive(temp.path(), &["json"]);
    assert!(scan.issues.is_empty());
    let scanned = scan.files.into_iter().next().expect("scanned file");

    fs::write(&path, "{\"changed\":true}").expect("mutate file");

    let issue = scanned.read_text().expect_err("mutation must not be read");
    assert_eq!(issue.reason, ReliabilityReasonCode::PathEscapesArtifactRoot);
    assert!(issue.message.contains("changed identity or confinement"));
}

#[test]
fn content_digest_rejects_same_inode_same_length_with_restored_mtime() {
    use crate::file_identity::{identity, open_file};
    use std::fs::{FileTimes, OpenOptions};
    use std::io::{Seek, SeekFrom, Write};

    let temp = tempdir().expect("tempdir");
    let path = temp.path().join("report.json");
    fs::write(&path, "AAAA").expect("trusted file");
    let original = open_file(&path).expect("open original");
    let original_identity = identity(&original, &path).expect("original identity");
    let original_mtime = original
        .metadata()
        .expect("metadata")
        .modified()
        .expect("mtime");
    let scan = scan_recursive(temp.path(), &["json"]);
    assert!(scan.issues.is_empty());
    let scanned = scan.files.into_iter().next().expect("scanned file");

    let mut mutated = OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open for in-place mutation");
    mutated.seek(SeekFrom::Start(0)).expect("seek");
    mutated.write_all(b"BBBB").expect("same-length mutation");
    mutated.sync_all().expect("persist mutation");
    mutated
        .set_times(FileTimes::new().set_modified(original_mtime))
        .expect("restore mtime");
    let current = open_file(&path).expect("reopen mutation");
    assert_eq!(
        identity(&current, &path).expect("current identity"),
        original_identity
    );
    assert_eq!(current.metadata().expect("metadata").len(), 4);
    assert_eq!(
        confined_modified_time(temp.path(), &path).expect("safe mtime read"),
        original_mtime,
        "mtime is an ordering hint, not content identity"
    );

    let issue = scanned
        .read_text()
        .expect_err("bound content digest must reject mutation");
    assert_eq!(issue.reason, ReliabilityReasonCode::PathEscapesArtifactRoot);
    assert!(issue.message.contains("content digest changed"));
}

#[test]
fn scanned_file_rejects_scan_root_replacement_before_read() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("root");
    let original_root = temp.path().join("original-root");
    fs::create_dir(&root).expect("root");
    fs::write(root.join("report.json"), "{}").expect("trusted file");
    let scan = scan_recursive(&root, &["json"]);
    assert!(scan.issues.is_empty());
    let scanned = scan.files.into_iter().next().expect("scanned file");

    fs::rename(&root, &original_root).expect("move original root");
    fs::create_dir(&root).expect("replacement root");
    fs::write(root.join("report.json"), "{\"replacement\":true}").expect("replacement file");

    let issue = scanned
        .read_text()
        .expect_err("replacement root must not be read");
    assert_eq!(issue.reason, ReliabilityReasonCode::PathEscapesArtifactRoot);
}

#[cfg(unix)]
#[test]
fn scan_rejects_symlink_outside_root() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("root");
    fs::create_dir(&root).expect("root");
    let outside = temp.path().join("outside.json");
    fs::write(&outside, "{}").expect("outside");
    symlink(&outside, root.join("linked.json")).expect("symlink");

    let scan = scan_recursive(&root, &["json"]);

    assert!(scan.files.is_empty());
    assert!(
        scan.issues
            .iter()
            .any(|issue| { issue.reason == ReliabilityReasonCode::PathEscapesArtifactRoot })
    );
}

#[cfg(unix)]
#[test]
fn strict_named_scan_rejects_symlink_root() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let target = temp.path().join("target");
    fs::create_dir(&target).expect("target");
    fs::write(target.join("telemetry_summary.json"), "{}").expect("summary");
    let root_link = temp.path().join("root-link");
    symlink(&target, &root_link).expect("root symlink");

    let error = scan_named_files_strict(
        &root_link,
        std::ffi::OsStr::new("telemetry_summary.json"),
        StrictNamedScanLimits {
            max_entries: 1,
            max_files: 1,
            max_matches: 1,
            max_file_bytes: 2,
            max_total_file_bytes: 2,
        },
    )
    .expect_err("scan root links must not be followed");

    assert!(error.to_string().contains("symbolic link"), "{error}");
}

#[cfg(unix)]
#[test]
fn scanned_file_rejects_symlink_replacement_before_read() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("root");
    fs::create_dir(&root).expect("root");
    let path = root.join("report.json");
    fs::write(&path, "{}").expect("trusted file");
    let scan = scan_recursive(&root, &["json"]);
    assert!(scan.issues.is_empty());
    let scanned = scan.files.into_iter().next().expect("scanned file");
    let outside = temp.path().join("outside.json");
    fs::write(&outside, "{\"secret\":true}").expect("outside");

    fs::remove_file(&path).expect("remove trusted file");
    symlink(&outside, &path).expect("replacement symlink");

    let issue = scanned
        .read_text()
        .expect_err("symlink replacement must not be read");
    assert_eq!(issue.reason, ReliabilityReasonCode::PathEscapesArtifactRoot);
    assert!(issue.message.contains("symbolic link"));
}

#[cfg(unix)]
#[test]
fn confined_access_rejects_symlink_even_when_target_is_inside_root() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("root");
    fs::create_dir(&root).expect("root");
    let target = root.join("target.json");
    let link = root.join("link.json");
    fs::write(&target, "{}").expect("target");
    symlink(&target, &link).expect("symlink");

    let read_issue = read_confined_text(&root, &link).expect_err("link read must fail");
    let mtime_issue =
        confined_modified_time(&root, &link).expect_err("link metadata read must fail");

    assert_eq!(
        read_issue.reason,
        ReliabilityReasonCode::PathEscapesArtifactRoot
    );
    assert_eq!(
        mtime_issue.reason,
        ReliabilityReasonCode::PathEscapesArtifactRoot
    );
}
