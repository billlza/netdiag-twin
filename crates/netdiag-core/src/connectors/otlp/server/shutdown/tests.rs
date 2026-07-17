use super::*;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

const TEST_DEADLINE: Duration = Duration::from_millis(1);

#[test]
fn completion_signal_does_not_authorize_joining_an_unfinished_worker() {
    let (mut controller, release, exited) = signalled_but_blocked_controller();

    let error = controller
        .stop()
        .expect_err("an unfinished worker must be detached after the deadline");

    assert!(!controller.is_running());
    assert!(error.to_string().contains("incomplete worker was detached"));
    release_worker(release, exited);
}

#[test]
fn drop_detaches_an_unfinished_worker_within_its_configured_deadlines() {
    let (controller, release, exited) = signalled_but_blocked_controller();

    drop(controller);

    release_worker(release, exited);
}

#[test]
fn deadline_race_joins_a_finished_worker_and_preserves_its_failure() {
    let (mut controller, release, exited) = blocked_controller();
    release
        .send(())
        .expect("finished worker release signal must be received");
    exited
        .recv_timeout(Duration::from_secs(1))
        .expect("worker must report completion");
    while !controller.worker_finished() {
        thread::yield_now();
    }

    let error = controller
        .reclaim_after_forced_deadline(None)
        .expect_err("the elapsed deadline remains the primary failure");

    let message = error.to_string();
    assert!(message.contains("exceeded its 1 ms forced shutdown deadline"));
    assert!(message.contains("test worker failure"));
    assert!(!controller.is_running());
}

#[test]
fn finished_worker_is_observable_before_explicit_shutdown() {
    let (mut controller, release, exited) = blocked_controller();
    release
        .send(())
        .expect("finished worker release signal must be received");
    exited
        .recv_timeout(Duration::from_secs(1))
        .expect("worker must report completion");
    while !controller.worker_finished() {
        thread::yield_now();
    }

    let error = controller
        .ensure_running()
        .expect_err("an exited worker must fail the liveness boundary");

    assert!(!controller.is_running());
    assert!(error.to_string().contains("exited unexpectedly"));
    let stop_error = controller
        .stop()
        .expect_err("shutdown must preserve the worker failure");
    assert!(stop_error.to_string().contains("test worker failure"));
}

fn signalled_but_blocked_controller() -> (ShutdownController, SyncSender<()>, Receiver<()>) {
    let (graceful_tx, graceful_rx) = oneshot::channel();
    let (force_tx, force_rx) = oneshot::channel();
    let (finished_tx, finished_rx) = sync_channel(1);
    let (announced_tx, announced_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let (exited_tx, exited_rx) = sync_channel(1);
    let worker = thread::spawn(move || {
        let _graceful_rx = graceful_rx;
        let _force_rx = force_rx;
        finished_tx
            .send(())
            .expect("completion signal receiver must remain available");
        announced_tx
            .send(())
            .expect("test must observe the premature completion signal");
        release_rx
            .recv()
            .expect("test must release the blocked worker");
        exited_tx
            .send(())
            .expect("test must observe worker completion");
        Ok(OtlpShutdownOutcome::Forced)
    });
    announced_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("worker must publish its completion signal");
    let controller = ShutdownController::with_test_deadlines(
        graceful_tx,
        force_tx,
        finished_rx,
        worker,
        ShutdownDeadlines::new(TEST_DEADLINE, TEST_DEADLINE),
    );
    (controller, release_tx, exited_rx)
}

fn blocked_controller() -> (ShutdownController, SyncSender<()>, Receiver<()>) {
    let (graceful_tx, graceful_rx) = oneshot::channel();
    let (force_tx, force_rx) = oneshot::channel();
    let (finished_tx, finished_rx) = sync_channel(1);
    let (release_tx, release_rx) = sync_channel(1);
    let (exited_tx, exited_rx) = sync_channel(1);
    let worker = thread::spawn(move || {
        let _graceful_rx = graceful_rx;
        let _force_rx = force_rx;
        release_rx
            .recv()
            .expect("test must release the blocked worker");
        finished_tx
            .send(())
            .expect("completion signal receiver must remain available");
        exited_tx
            .send(())
            .expect("test must observe worker completion");
        Err("test worker failure".to_string())
    });
    let controller = ShutdownController::with_test_deadlines(
        graceful_tx,
        force_tx,
        finished_rx,
        worker,
        ShutdownDeadlines::new(TEST_DEADLINE, TEST_DEADLINE),
    );
    (controller, release_tx, exited_rx)
}

fn release_worker(release: SyncSender<()>, exited: Receiver<()>) {
    release
        .send(())
        .expect("detached worker release signal must be received");
    exited
        .recv_timeout(Duration::from_secs(1))
        .expect("detached worker must finish after release");
}
