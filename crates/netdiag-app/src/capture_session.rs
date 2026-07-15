use crate::connector_flow::CaptureSessionCompletion;
use netdiag_app::data_source::SourceSnapshot;
use netdiag_app::settings::ConnectorKind;
use netdiag_core::NetdiagError;
use netdiag_core::connectors::{CaptureProgress, OtlpReceiverSession, OtlpShutdownOutcome};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

mod cleanup;
use cleanup::{
    OtlpRuntimeAndCleanupFailure, WORKER_EXIT_TIMEOUT, WorkerCleanupOutcome, finish_worker_within,
};

pub(super) type CaptureSessionJob = mpsc::Receiver<CaptureSessionEvent>;

pub(super) enum CaptureSessionEvent {
    Progress(CaptureProgress),
    Finished(CaptureSessionCompletion),
    OtlpStopped(anyhow::Result<OtlpShutdownOutcome>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CaptureSessionPhase {
    Running,
    Cancelling,
    Completed,
    Cancelled,
    Failed,
}

impl CaptureSessionPhase {
    pub(super) fn is_active(self) -> bool {
        matches!(self, Self::Running | Self::Cancelling)
    }
}

pub(super) struct CaptureSessionState {
    pub(super) kind: ConnectorKind,
    pub(super) phase: CaptureSessionPhase,
    pub(super) started_at: chrono::DateTime<chrono::Utc>,
    pub(super) timeout: Duration,
    pub(super) progress: Option<CaptureProgress>,
    pub(super) last_sample: Option<SourceSnapshot>,
    pub(super) status: String,
    pub(super) job: Option<CaptureSessionJob>,
    pub(super) worker: Option<JoinHandle<()>>,
    pub(super) cancel: Option<Arc<AtomicBool>>,
    pub(super) otlp: Option<OtlpReceiverSession>,
}

impl CaptureSessionState {
    pub(super) fn failed(kind: ConnectorKind, status: String) -> Self {
        Self {
            kind,
            phase: CaptureSessionPhase::Failed,
            started_at: chrono::Utc::now(),
            timeout: Duration::ZERO,
            progress: None,
            last_sample: None,
            status,
            job: None,
            worker: None,
            cancel: None,
            otlp: None,
        }
    }

    pub(super) fn stop_otlp_after_failure(&mut self, failure: NetdiagError) -> bool {
        let Some(otlp) = self.otlp.take() else {
            return false;
        };
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = match otlp.stop() {
                Ok(_) => Err(anyhow::Error::from(failure)),
                Err(cleanup) => Err(anyhow::Error::new(OtlpRuntimeAndCleanupFailure {
                    primary: failure,
                    cleanup,
                })),
            };
            drop(sender.send(CaptureSessionEvent::OtlpStopped(result)));
        });
        self.job = Some(receiver);
        self.worker = Some(worker);
        true
    }
}

impl Drop for CaptureSessionState {
    fn drop(&mut self) {
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::Relaxed);
        }
        if let Some(otlp) = self.otlp.take()
            && let Err(error) = otlp.stop()
        {
            eprintln!("OTLP capture cleanup failed: {error}");
        }
        match finish_worker_within(&mut self.worker, WORKER_EXIT_TIMEOUT) {
            WorkerCleanupOutcome::Joined | WorkerCleanupOutcome::NoWorker => {}
            WorkerCleanupOutcome::Panicked => eprintln!("capture worker panicked during cleanup"),
            WorkerCleanupOutcome::TimedOut => eprintln!(
                "capture worker exceeded its {} ms cleanup deadline and was detached",
                WORKER_EXIT_TIMEOUT.as_millis()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netdiag_core::connectors::OtlpGrpcReceiverConfig;
    use std::collections::BTreeMap;
    use std::time::Instant;

    #[test]
    fn drop_signals_cancellation_and_joins_worker() {
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            while !worker_cancel.load(Ordering::Relaxed) {
                thread::park_timeout(Duration::from_millis(1));
            }
            finished_tx.send(()).expect("test receiver remains alive");
        });
        let state = CaptureSessionState {
            kind: ConnectorKind::NativePcap,
            phase: CaptureSessionPhase::Running,
            started_at: chrono::Utc::now(),
            timeout: Duration::from_secs(1),
            progress: None,
            last_sample: None,
            status: String::new(),
            job: None,
            worker: Some(worker),
            cancel: Some(cancel),
            otlp: None,
        };

        drop(state);

        finished_rx
            .recv_timeout(Duration::from_millis(50))
            .expect("worker must exit before state cleanup completes");
    }

    #[test]
    fn worker_cleanup_timeout_is_bounded_and_reports_detachment_boundary() {
        let (release_tx, release_rx) = mpsc::channel();
        let mut worker = Some(thread::spawn(move || {
            release_rx.recv().expect("test releases worker");
        }));
        let started = Instant::now();

        let outcome = finish_worker_within(&mut worker, Duration::from_millis(1));

        assert_eq!(outcome, WorkerCleanupOutcome::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(250));
        release_tx.send(()).expect("worker remains connected");
        worker
            .take()
            .expect("timed-out worker handle is retained")
            .join()
            .expect("worker exits after release");
    }

    #[test]
    fn otlp_runtime_failure_is_preserved_after_bounded_cleanup() {
        let otlp = OtlpReceiverSession::start(&OtlpGrpcReceiverConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            timeout: Duration::from_secs(1),
            metrics: BTreeMap::new(),
            sample: "runtime-failure".to_string(),
        })
        .expect("test receiver");
        let mut state = CaptureSessionState {
            kind: ConnectorKind::OtlpGrpcReceiver,
            phase: CaptureSessionPhase::Running,
            started_at: chrono::Utc::now(),
            timeout: Duration::from_secs(1),
            progress: None,
            last_sample: None,
            status: String::new(),
            job: None,
            worker: None,
            cancel: None,
            otlp: Some(otlp),
        };

        assert!(state.stop_otlp_after_failure(NetdiagError::Connector(
            "injected receiver failure".to_string()
        )));
        let event = state
            .job
            .as_ref()
            .expect("cleanup result channel")
            .recv_timeout(Duration::from_secs(5))
            .expect("bounded cleanup result");

        let CaptureSessionEvent::OtlpStopped(Err(error)) = event else {
            panic!("runtime failure must remain the primary result");
        };
        assert!(error.to_string().contains("injected receiver failure"));
    }
}
