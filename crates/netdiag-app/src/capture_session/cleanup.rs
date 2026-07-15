use netdiag_core::NetdiagError;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(super) const WORKER_EXIT_TIMEOUT: Duration = Duration::from_secs(3);
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug)]
pub(super) struct OtlpRuntimeAndCleanupFailure {
    pub(super) primary: NetdiagError,
    pub(super) cleanup: NetdiagError,
}

impl std::fmt::Display for OtlpRuntimeAndCleanupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "OTLP receiver failed while running: {}; OTLP receiver cleanup also failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl std::error::Error for OtlpRuntimeAndCleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkerCleanupOutcome {
    NoWorker,
    Joined,
    Panicked,
    TimedOut,
}

pub(super) fn finish_worker_within(
    worker: &mut Option<JoinHandle<()>>,
    timeout: Duration,
) -> WorkerCleanupOutcome {
    let Some(handle) = worker.as_ref() else {
        return WorkerCleanupOutcome::NoWorker;
    };
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return WorkerCleanupOutcome::TimedOut;
        }
        thread::park_timeout(remaining.min(WORKER_POLL_INTERVAL));
    }
    match worker
        .take()
        .expect("capture worker was checked above")
        .join()
    {
        Ok(()) => WorkerCleanupOutcome::Joined,
        Err(_) => WorkerCleanupOutcome::Panicked,
    }
}
