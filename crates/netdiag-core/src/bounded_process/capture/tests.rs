use super::*;
use rustix::event::PollFlags;
use rustix::fs::{OFlags, fcntl_getfl};
use std::io::Write;
use std::os::unix::net::UnixStream;

fn socket_capture(
    stdout_limit: usize,
    stderr_limit: usize,
) -> (CapturePair<UnixStream, UnixStream>, UnixStream, UnixStream) {
    let (stdout_reader, stdout_writer) = UnixStream::pair().expect("stdout socket pair");
    let (stderr_reader, stderr_writer) = UnixStream::pair().expect("stderr socket pair");
    let capture = CapturePair::new(stdout_reader, stderr_reader, stdout_limit, stderr_limit)
        .expect("capture setup");
    (capture, stdout_writer, stderr_writer)
}

#[test]
fn capture_marks_both_pipes_nonblocking() {
    let (capture, _stdout_writer, _stderr_writer) = socket_capture(16, 16);

    let stdout_flags =
        fcntl_getfl(capture.stdout.reader.as_ref().expect("stdout open")).expect("stdout flags");
    let stderr_flags =
        fcntl_getfl(capture.stderr.reader.as_ref().expect("stderr open")).expect("stderr flags");

    assert!(stdout_flags.contains(OFlags::NONBLOCK));
    assert!(stderr_flags.contains(OFlags::NONBLOCK));
}

#[test]
fn poll_drains_both_ready_streams_and_observes_eof() {
    let (mut capture, mut stdout_writer, mut stderr_writer) = socket_capture(16, 16);
    stdout_writer.write_all(b"out").expect("stdout write");
    stderr_writer.write_all(b"err").expect("stderr write");
    drop(stdout_writer);
    drop(stderr_writer);

    assert!(capture.poll_once(Duration::from_secs(1)).unwrap().is_none());
    assert_eq!(capture.stdout.bytes, b"out");
    assert_eq!(capture.stderr.bytes, b"err");
    assert!(capture.is_complete());
}

#[test]
fn output_limit_retains_only_the_bounded_prefix() {
    let (mut capture, mut stdout_writer, _stderr_writer) = socket_capture(3, 16);
    stdout_writer.write_all(b"abcdef").expect("stdout write");

    let limit = capture
        .poll_once(Duration::from_secs(1))
        .expect("capture poll")
        .expect("output limit");

    assert_eq!(limit.stream_name, "stdout");
    assert_eq!(limit.limit, 3);
    assert_eq!(capture.stdout.bytes, b"abc");
    assert!(capture.stdout.reader.is_none());
}

#[test]
fn silent_open_writers_hit_the_drain_deadline() {
    let (mut capture, _stdout_writer, _stderr_writer) = socket_capture(16, 16);
    let started = Instant::now();

    let outcome = capture.drain_until(started + Duration::from_millis(30));

    assert!(matches!(outcome, DrainOutcome::DeadlineExceeded));
    assert!(started.elapsed() < Duration::from_millis(250));
    assert!(capture.is_complete());
}

#[test]
fn invalid_poll_event_closes_the_stream_and_fails_explicitly() {
    let (mut capture, _stdout_writer, _stderr_writer) = socket_capture(16, 16);

    let error = capture
        .stdout
        .drain_ready(PollFlags::NVAL)
        .expect_err("invalid descriptor event");

    assert!(error.to_string().contains("invalid file descriptor"));
    assert!(capture.stdout.reader.is_none());
}
