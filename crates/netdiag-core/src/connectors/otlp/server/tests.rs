use super::shutdown::{ShutdownController, ShutdownDeadlines};
use super::*;
use std::sync::mpsc::{Receiver, SyncSender};

const TEST_DEADLINE: Duration = Duration::from_millis(1);

#[test]
fn startup_deadline_cancels_without_joining_an_unfinished_worker() {
    let (startup_tx, startup_rx) = sync_channel(1);
    let (mut shutdown, release, exited) = blocked_startup_controller();

    let error = await_startup(&startup_rx, &mut shutdown, TEST_DEADLINE)
        .expect_err("startup must fail when readiness is not reported by its deadline");

    let message = error.to_string();
    assert!(message.contains("exceeded its 1 ms startup deadline"));
    assert!(message.contains("incomplete worker was detached"));
    assert!(!shutdown.is_running());
    drop(startup_tx);
    release
        .send(())
        .expect("detached startup worker release signal must be received");
    exited
        .recv_timeout(Duration::from_secs(1))
        .expect("detached startup worker must finish after release");
}

fn blocked_startup_controller() -> (ShutdownController, SyncSender<()>, Receiver<()>) {
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
            .expect("test must release the blocked startup worker");
        finished_tx
            .send(())
            .expect("completion signal receiver must remain available");
        exited_tx
            .send(())
            .expect("test must observe startup worker completion");
        Ok(OtlpShutdownOutcome::Forced)
    });
    let shutdown = ShutdownController::with_test_deadlines(
        graceful_tx,
        force_tx,
        finished_rx,
        worker,
        ShutdownDeadlines::new(TEST_DEADLINE, TEST_DEADLINE),
    );
    (shutdown, release_tx, exited_rx)
}
