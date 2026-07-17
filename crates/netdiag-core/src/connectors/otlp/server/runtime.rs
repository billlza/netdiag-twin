use super::incoming::BoundedIncoming;
use super::{OtlpShutdownOutcome, StartupResult, WorkerResult};
use crate::connectors::otlp::OtlpMetricsReceiver;
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_server::MetricsServiceServer;
use std::future::pending;
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::SyncSender;
use std::time::Duration;
use tokio::sync::oneshot;
use tonic::transport::Server;
use tonic::transport::server::TcpIncoming;
use tower::limit::GlobalConcurrencyLimitLayer;

pub(super) const MAX_CONCURRENT_REQUESTS: usize = 16;
const MAX_CONCURRENT_STREAMS_PER_CONNECTION: usize = 8;
const MAX_EXPORT_DURATION: Duration = Duration::from_secs(5);
const MAX_CONNECTION_AGE: Duration = Duration::from_secs(60);
const MAX_CONNECTION_AGE_GRACE: Duration = Duration::from_secs(2);
const HTTP2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const HTTP2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(3);
pub(super) fn run_server(
    listener: StdTcpListener,
    service: MetricsServiceServer<OtlpMetricsReceiver>,
    graceful_shutdown: oneshot::Receiver<()>,
    force_shutdown: oneshot::Receiver<()>,
    active_connections: Arc<AtomicUsize>,
    startup: SyncSender<StartupResult>,
) -> WorkerResult {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| report_startup_failure(&startup, "runtime initialization", error))?;
    let listener = runtime
        .block_on(async move { tokio::net::TcpListener::from_std(listener) })
        .map_err(|error| report_startup_failure(&startup, "listener initialization", error))?;
    let incoming = BoundedIncoming::new(
        TcpIncoming::from(listener).with_nodelay(Some(true)),
        active_connections,
    );
    startup
        .send(Ok(()))
        .map_err(|_| "OTLP receiver startup handshake was cancelled".to_string())?;

    runtime.block_on(async move {
        let server = Server::builder()
            .layer(GlobalConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
            .concurrency_limit_per_connection(MAX_CONCURRENT_STREAMS_PER_CONNECTION)
            .max_concurrent_streams(Some(
                u32::try_from(MAX_CONCURRENT_STREAMS_PER_CONNECTION)
                    .expect("per-connection OTLP stream limit fits u32"),
            ))
            .load_shed(true)
            .timeout(MAX_EXPORT_DURATION)
            .max_connection_age(MAX_CONNECTION_AGE)
            .max_connection_age_grace(MAX_CONNECTION_AGE_GRACE)
            .http2_keepalive_interval(Some(HTTP2_KEEPALIVE_INTERVAL))
            .http2_keepalive_timeout(Some(HTTP2_KEEPALIVE_TIMEOUT))
            .http2_max_header_list_size(Some(16 * 1024))
            .add_service(service)
            .serve_with_incoming_shutdown(incoming, wait_for_explicit_signal(graceful_shutdown));
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result
                .map(|()| OtlpShutdownOutcome::Graceful)
                .map_err(|error| error.to_string()),
            () = wait_for_explicit_signal(force_shutdown) => {
                Ok(OtlpShutdownOutcome::Forced)
            }
        }
    })
}

fn report_startup_failure(
    startup: &SyncSender<StartupResult>,
    context: &str,
    error: impl std::fmt::Display,
) -> String {
    let message = format!("{context} failed: {error}");
    if startup.send(Err(message.clone())).is_err() {
        return "OTLP receiver startup failure could not be reported".to_string();
    }
    message
}

async fn wait_for_explicit_signal(signal: oneshot::Receiver<()>) {
    if signal.await.is_err() {
        pending::<()>().await;
    }
}
