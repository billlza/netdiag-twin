use super::{OtlpMetricsReceiver, OtlpShutdownOutcome};
use crate::error::{NetdiagError, Result};
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_server::MetricsServiceServer;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::thread;
use std::time::Duration;
use tokio::sync::oneshot;

mod incoming;
mod runtime;
mod shutdown;
use runtime::run_server;
use shutdown::ShutdownController;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) type StartupResult = std::result::Result<(), String>;
pub(super) type WorkerResult = std::result::Result<OtlpShutdownOutcome, String>;

pub(super) struct OtlpServer {
    local_addr: SocketAddr,
    shutdown: ShutdownController,
    active_connections: Arc<AtomicUsize>,
}

impl std::fmt::Debug for OtlpServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OtlpServer")
            .field("local_addr", &self.local_addr)
            .field("running", &self.shutdown.is_running())
            .field(
                "active_connections",
                &self.active_connections.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl OtlpServer {
    pub(super) fn start(
        requested_addr: SocketAddr,
        service: MetricsServiceServer<OtlpMetricsReceiver>,
    ) -> Result<Self> {
        let listener = StdTcpListener::bind(requested_addr).map_err(|source| {
            NetdiagError::Connector(format!("OTLP gRPC receiver could not bind: {source}"))
        })?;
        listener.set_nonblocking(true).map_err(|source| {
            NetdiagError::Connector(format!(
                "OTLP gRPC receiver could not configure its listener: {source}"
            ))
        })?;
        let local_addr = listener.local_addr().map_err(|source| {
            NetdiagError::Connector(format!(
                "OTLP gRPC receiver could not read its bound address: {source}"
            ))
        })?;

        let active_connections = Arc::new(AtomicUsize::new(0));
        let worker_connections = Arc::clone(&active_connections);
        let (startup_tx, startup_rx) = sync_channel::<StartupResult>(1);
        let (finished_tx, finished_rx) = sync_channel::<()>(1);
        let (graceful_tx, graceful_rx) = oneshot::channel();
        let (force_tx, force_rx) = oneshot::channel();
        let worker = thread::Builder::new()
            .name("netdiag-otlp-receiver".to_string())
            .spawn(move || {
                let result = run_server(
                    listener,
                    service,
                    graceful_rx,
                    force_rx,
                    worker_connections,
                    startup_tx,
                );
                if finished_tx.send(()).is_err() {
                    return result;
                }
                result
            })
            .map_err(|source| {
                NetdiagError::Connector(format!(
                    "OTLP gRPC receiver thread could not start: {source}"
                ))
            })?;

        let mut shutdown = ShutdownController::new(graceful_tx, force_tx, finished_rx, worker);
        await_startup(&startup_rx, &mut shutdown, STARTUP_TIMEOUT)?;
        Ok(Self {
            local_addr,
            shutdown,
            active_connections,
        })
    }

    pub(super) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(super) fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub(super) fn ensure_running(&self) -> Result<()> {
        self.shutdown.ensure_running()
    }

    pub(super) fn stop(mut self) -> Result<OtlpShutdownOutcome> {
        self.shutdown.stop()
    }
}

fn await_startup(
    startup: &Receiver<StartupResult>,
    shutdown: &mut ShutdownController,
    timeout: Duration,
) -> Result<()> {
    match startup.recv_timeout(timeout) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => reclaim_failed_start(
            shutdown,
            NetdiagError::Connector(format!("OTLP gRPC receiver failed to start: {error}")),
        ),
        Err(RecvTimeoutError::Disconnected) => reclaim_failed_start(
            shutdown,
            NetdiagError::Connector(
                "OTLP receiver startup channel disconnected before readiness".to_string(),
            ),
        ),
        Err(RecvTimeoutError::Timeout) => reclaim_failed_start(
            shutdown,
            NetdiagError::Connector(format!(
                "OTLP receiver exceeded its {} ms startup deadline",
                timeout.as_millis()
            )),
        ),
    }
}

fn reclaim_failed_start(
    shutdown: &mut ShutdownController,
    startup_failure: NetdiagError,
) -> Result<()> {
    match shutdown.stop() {
        Ok(_) => Err(startup_failure),
        Err(cleanup) => Err(startup_failure.with_secondary_failure(
            "OTLP receiver startup failed",
            "OTLP startup worker reclamation also failed",
            cleanup,
        )),
    }
}

#[cfg(test)]
mod tests;
