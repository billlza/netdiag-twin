use super::*;

#[test]
fn drain_outcomes_preserve_each_cleanup_failure_category() {
    use crate::bounded_process::capture::OutputLimit;

    let mut details = Vec::new();
    append_drain_outcome(&mut details, DrainOutcome::Complete);
    assert!(details.is_empty());

    append_drain_outcome(&mut details, DrainOutcome::DeadlineExceeded);
    append_drain_outcome(
        &mut details,
        DrainOutcome::OutputLimit(OutputLimit {
            stream_name: "stderr",
            limit: 17,
        }),
    );

    assert_eq!(details[0], "process_output_drain_error=deadline_exceeded");
    assert_eq!(
        details[1],
        "process_output_drain_error=limit_exceeded, stream=stderr, limit_bytes=17"
    );
}

#[test]
fn kill_errors_ignore_only_already_gone_process_states() {
    let mut failures = Vec::new();
    append_kill_error(
        &mut failures,
        io::Error::new(io::ErrorKind::InvalidInput, "already reaped"),
    );
    append_kill_error(
        &mut failures,
        io::Error::new(io::ErrorKind::NotFound, "already gone"),
    );
    assert!(failures.is_empty());

    append_kill_error(
        &mut failures,
        io::Error::new(io::ErrorKind::PermissionDenied, "kill denied"),
    );
    assert_eq!(failures.len(), 1);
    assert!(failures[0].contains("process_tree_kill_error"));
}
