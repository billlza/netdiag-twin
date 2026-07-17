use super::{OtlpShutdownOutcome, WorkerResult};
use crate::error::{NetdiagError, Result};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);
const FORCED_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const WORKER_FINISH_POLL_INTERVAL: Duration = Duration::from_millis(1);

#[derive(Clone, Copy)]
pub(super) struct ShutdownDeadlines {
    graceful: Duration,
    forced: Duration,
}

impl ShutdownDeadlines {
    const DEFAULT: Self = Self {
        graceful: GRACEFUL_SHUTDOWN_TIMEOUT,
        forced: FORCED_SHUTDOWN_TIMEOUT,
    };

    #[cfg(test)]
    pub(super) const fn new(graceful: Duration, forced: Duration) -> Self {
        Self { graceful, forced }
    }
}

pub(super) struct ShutdownController {
    graceful: Option<oneshot::Sender<()>>,
    force: Option<oneshot::Sender<()>>,
    finished: Receiver<()>,
    worker: Option<JoinHandle<WorkerResult>>,
    deadlines: ShutdownDeadlines,
}

impl ShutdownController {
    pub(super) fn new(
        graceful: oneshot::Sender<()>,
        force: oneshot::Sender<()>,
        finished: Receiver<()>,
        worker: JoinHandle<WorkerResult>,
    ) -> Self {
        Self::with_deadlines(
            graceful,
            force,
            finished,
            worker,
            ShutdownDeadlines::DEFAULT,
        )
    }

    fn with_deadlines(
        graceful: oneshot::Sender<()>,
        force: oneshot::Sender<()>,
        finished: Receiver<()>,
        worker: JoinHandle<WorkerResult>,
        deadlines: ShutdownDeadlines,
    ) -> Self {
        Self {
            graceful: Some(graceful),
            force: Some(force),
            finished,
            worker: Some(worker),
            deadlines,
        }
    }

    #[cfg(test)]
    pub(super) fn with_test_deadlines(
        graceful: oneshot::Sender<()>,
        force: oneshot::Sender<()>,
        finished: Receiver<()>,
        worker: JoinHandle<WorkerResult>,
        deadlines: ShutdownDeadlines,
    ) -> Self {
        Self::with_deadlines(graceful, force, finished, worker, deadlines)
    }

    pub(super) fn is_running(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
    }

    pub(super) fn ensure_running(&self) -> Result<()> {
        match self.worker.as_ref() {
            Some(worker) if !worker.is_finished() => Ok(()),
            Some(_) => Err(NetdiagError::Connector(
                "OTLP receiver worker exited unexpectedly".to_string(),
            )),
            None => Err(NetdiagError::Connector(
                "OTLP receiver worker is no longer managed".to_string(),
            )),
        }
    }

    pub(super) fn stop(&mut self) -> Result<OtlpShutdownOutcome> {
        if self.worker.is_none() {
            return Ok(OtlpShutdownOutcome::Graceful);
        }
        let graceful_failure = self.send_graceful_shutdown();
        if self.wait_for_worker(self.deadlines.graceful) {
            return self.join_completed_worker(graceful_failure);
        }
        self.force_and_reclaim(graceful_failure)
    }

    fn send_graceful_shutdown(&mut self) -> Option<NetdiagError> {
        let failed = self
            .graceful
            .take()
            .is_some_and(|signal| signal.send(()).is_err());
        if failed && !self.worker_finished() {
            return Some(NetdiagError::Connector(
                "OTLP receiver graceful shutdown channel closed unexpectedly".to_string(),
            ));
        }
        None
    }

    fn force_and_reclaim(
        &mut self,
        graceful_failure: Option<NetdiagError>,
    ) -> Result<OtlpShutdownOutcome> {
        let force_failed = self
            .force
            .take()
            .is_some_and(|signal| signal.send(()).is_err());
        let signal_failure = if force_failed && !self.worker_finished() {
            append_failure(
                graceful_failure,
                NetdiagError::Connector(
                    "OTLP receiver forced shutdown channel closed unexpectedly".to_string(),
                ),
            )
        } else {
            graceful_failure
        };
        if self.wait_for_worker(self.deadlines.forced) {
            return self.join_completed_worker(signal_failure);
        }
        self.reclaim_after_forced_deadline(signal_failure)
    }

    fn wait_for_worker(&self, timeout: Duration) -> bool {
        let Some(worker) = self.worker.as_ref() else {
            return true;
        };
        if worker.is_finished() {
            return true;
        }
        let deadline = Instant::now() + timeout;
        let remaining = deadline.saturating_duration_since(Instant::now());
        match self.finished.recv_timeout(remaining) {
            Err(RecvTimeoutError::Timeout) => return worker.is_finished(),
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {}
        }
        while !worker.is_finished() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return worker.is_finished();
            }
            thread::park_timeout(remaining.min(WORKER_FINISH_POLL_INTERVAL));
        }
        true
    }

    fn worker_finished(&self) -> bool {
        self.worker.as_ref().is_some_and(JoinHandle::is_finished)
    }

    fn join_completed_worker(
        &mut self,
        signal_failure: Option<NetdiagError>,
    ) -> Result<OtlpShutdownOutcome> {
        let worker_result = self.join_worker();
        match (signal_failure, worker_result) {
            (None, result) => result,
            (Some(signal), Ok(_)) => Err(signal),
            (Some(signal), Err(worker)) => Err(signal.with_secondary_failure(
                "OTLP shutdown signalling failed",
                "OTLP worker completion also failed",
                worker,
            )),
        }
    }

    fn reclaim_after_forced_deadline(
        &mut self,
        signal_failure: Option<NetdiagError>,
    ) -> Result<OtlpShutdownOutcome> {
        let mut deadline = NetdiagError::Connector(format!(
            "OTLP receiver exceeded its {} ms forced shutdown deadline; its incomplete worker was detached",
            self.deadlines.forced.as_millis()
        ));
        if let Some(signal) = signal_failure {
            deadline = deadline.with_secondary_failure(
                "OTLP worker reclamation exceeded its deadline",
                "OTLP shutdown signalling also failed",
                signal,
            );
        }
        if self.worker_finished() {
            return match self.join_worker() {
                Ok(_) => Err(deadline),
                Err(worker) => Err(deadline.with_secondary_failure(
                    "OTLP worker reclamation exceeded its deadline",
                    "OTLP worker completion also failed",
                    worker,
                )),
            };
        }
        self.detach_worker();
        Err(deadline)
    }

    fn join_worker(&mut self) -> Result<OtlpShutdownOutcome> {
        let Some(worker) = self.worker.take() else {
            return Ok(OtlpShutdownOutcome::Graceful);
        };
        worker
            .join()
            .map_err(|_| NetdiagError::Connector("OTLP receiver thread panicked".to_string()))?
            .map_err(|error| NetdiagError::Connector(format!("OTLP receiver failed: {error}")))
    }

    fn detach_worker(&mut self) {
        drop(self.worker.take());
    }
}

fn append_failure(primary: Option<NetdiagError>, secondary: NetdiagError) -> Option<NetdiagError> {
    Some(match primary {
        Some(primary) => primary.with_secondary_failure(
            "OTLP graceful shutdown signalling failed",
            "OTLP forced shutdown signalling also failed",
            secondary,
        ),
        None => secondary,
    })
}

impl Drop for ShutdownController {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("OTLP receiver cleanup failed: {error}");
        }
    }
}

#[cfg(test)]
mod tests;
