use super::validation::{checked_chrono_duration, validate_otlp_timeout};
use super::{
    ConnectorLoadResult, ConnectorResourceUsage, fallback_warnings_for_missing_events,
    merge_wire_metric_mapping, record_from_values, replace_metric_provenance,
};
use crate::error::{NetdiagError, Result};
use crate::ingest::build_ingest_result;
use buffer::OtlpFrameBuffer;
use chrono::{DateTime, Utc};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
    metrics_service_server::{MetricsService, MetricsServiceServer},
};
use projection::{MAX_DECODING_MESSAGE_BYTES, OtlpProjectionSchema};
use server::OtlpServer;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tonic::{Request, Response, Status};

mod buffer;
mod projection;
mod server;
#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct OtlpGrpcReceiverConfig {
    pub bind_addr: String,
    pub timeout: Duration,
    pub metrics: BTreeMap<String, String>,
    pub sample: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpShutdownOutcome {
    Graceful,
    Forced,
}

impl std::fmt::Debug for OtlpGrpcReceiverConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OtlpGrpcReceiverConfig")
            .field("bind_addr", &self.bind_addr)
            .field("timeout", &self.timeout)
            .field("metric_entries", &self.metrics.len())
            .field("sample", &self.sample)
            .finish()
    }
}

#[derive(Debug)]
struct OtlpMetricFrame {
    received_at: DateTime<Utc>,
    timestamp_ms: i64,
    input_bytes: u64,
    values: Box<[f64]>,
}

impl OtlpMetricFrame {
    fn payload_bytes(&self) -> Option<usize> {
        self.values.len().checked_mul(std::mem::size_of::<f64>())
    }
}

pub struct OtlpReceiverSession {
    bind_addr: SocketAddr,
    schema: Arc<OtlpProjectionSchema>,
    sample: String,
    buffer: Arc<Mutex<OtlpFrameBuffer>>,
    server: Option<OtlpServer>,
}

impl std::fmt::Debug for OtlpReceiverSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let buffered_frames = self.buffer.lock().ok().map(|buffer| buffer.len());
        formatter
            .debug_struct("OtlpReceiverSession")
            .field("bind_addr", &self.bind_addr)
            .field("mapping_entries", &self.schema.len())
            .field("buffered_frames", &buffered_frames)
            .field("active_connections", &self.active_connections())
            .field("running", &self.server.is_some())
            .finish()
    }
}

impl OtlpReceiverSession {
    pub fn start(config: &OtlpGrpcReceiverConfig) -> Result<Self> {
        validate_otlp_timeout(config.timeout)?;
        let bind_addr = parse_loopback_bind_addr(&config.bind_addr)?;
        let mapping = merge_wire_metric_mapping(&config.metrics)
            .map_err(|error| NetdiagError::Connector(format!("OTLP gRPC receiver {error}")))?;
        let schema = Arc::new(OtlpProjectionSchema::new(mapping)?);
        let buffer = Arc::new(Mutex::new(OtlpFrameBuffer::default()));
        let service = OtlpMetricsReceiver {
            buffer: Arc::clone(&buffer),
            schema: Arc::clone(&schema),
        };
        let server = OtlpServer::start(bind_addr, configured_metrics_service(service))?;
        let bind_addr = server.local_addr();
        Ok(Self {
            bind_addr,
            schema,
            sample: config.sample.clone(),
            buffer,
            server: Some(server),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    fn active_connections(&self) -> usize {
        self.server
            .as_ref()
            .map(OtlpServer::active_connections)
            .unwrap_or_default()
    }

    pub fn snapshot(&self, lookback: Duration) -> Result<ConnectorLoadResult> {
        self.ensure_running()?;
        let cutoff = Utc::now() - checked_chrono_duration("OTLP snapshot lookback", lookback)?;
        let buffer = self
            .buffer
            .lock()
            .map_err(|_| NetdiagError::Connector("OTLP receiver buffer poisoned".to_string()))?;
        let mut records = Vec::new();
        let mut warnings = Vec::new();
        let mut frames_buffered = 0usize;
        let mut input_bytes = 0_u64;
        for frame in buffer.iter_since(cutoff) {
            frames_buffered += 1;
            input_bytes = input_bytes.checked_add(frame.input_bytes).ok_or_else(|| {
                NetdiagError::Connector("OTLP snapshot byte accounting overflowed".to_string())
            })?;
            let values = self
                .schema
                .values(frame)
                .map(|(name, value)| (name.to_string(), value))
                .collect::<BTreeMap<_, _>>();
            warnings.extend(fallback_warnings_for_missing_events(
                &values,
                "OTLP metric is missing",
            ));
            records.push(record_from_values(frame.timestamp_ms, &values)?);
        }
        drop(buffer);
        self.ensure_running()?;
        if frames_buffered == 0 {
            return Err(NetdiagError::ConnectorNotReady(
                "OTLP receiver is listening but has not received metrics yet".to_string(),
            ));
        }
        let mut ingest = build_ingest_result(records, self.sample.clone())?;
        ingest.warnings.extend(warnings);
        replace_metric_provenance(&mut ingest, "otlp_grpc_session");
        let resource_usage = ConnectorResourceUsage {
            input_bytes,
            records: ingest.records.len(),
        };
        Ok(ConnectorLoadResult {
            sample: self.sample.clone(),
            ingest,
            provenance: BTreeMap::from([
                ("kind".to_string(), "otlp_grpc_session".to_string()),
                ("bind_addr".to_string(), self.bind_addr.to_string()),
            ]),
            payload: Some(serde_json::json!({
                "frames_buffered": frames_buffered,
            })),
            resource_usage,
        })
    }

    pub fn progress_snapshot(&self) -> Result<(usize, Option<DateTime<Utc>>)> {
        self.ensure_running()?;
        let buffer = self
            .buffer
            .lock()
            .map_err(|_| NetdiagError::Connector("OTLP receiver buffer poisoned".to_string()))?;
        let progress = (buffer.len(), buffer.last_received_at());
        drop(buffer);
        self.ensure_running()?;
        Ok(progress)
    }

    pub fn stop(mut self) -> Result<OtlpShutdownOutcome> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<OtlpShutdownOutcome> {
        if let Some(server) = self.server.take() {
            return server.stop();
        }
        Ok(OtlpShutdownOutcome::Graceful)
    }

    fn ensure_running(&self) -> Result<()> {
        self.server
            .as_ref()
            .ok_or_else(|| {
                NetdiagError::Connector("OTLP receiver session is already stopped".to_string())
            })?
            .ensure_running()
    }
}

pub fn load_otlp_grpc_receiver(config: &OtlpGrpcReceiverConfig) -> Result<ConnectorLoadResult> {
    if parse_loopback_bind_addr(&config.bind_addr)?.port() == 0 {
        return Err(NetdiagError::Connector(
            "one-shot OTLP collection requires a fixed non-zero bind port".to_string(),
        ));
    }
    let session = OtlpReceiverSession::start(config)?;
    let started = Instant::now();
    let result = loop {
        match session.snapshot(config.timeout) {
            Ok(result) => break Ok(result),
            Err(NetdiagError::ConnectorNotReady(_)) if started.elapsed() < config.timeout => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(NetdiagError::ConnectorNotReady(_)) => {
                break Err(NetdiagError::Connector(format!(
                    "OTLP gRPC receiver timed out after {}s waiting for metrics",
                    config.timeout.as_secs()
                )));
            }
            Err(error) => break Err(error),
        }
    };
    finish_one_shot_collection(session, result)
}

pub(crate) fn parse_loopback_bind_addr(value: &str) -> Result<SocketAddr> {
    let bind_addr = value
        .trim()
        .parse::<SocketAddr>()
        .map_err(|error| NetdiagError::Connector(format!("invalid OTLP bind address: {error}")))?;
    if !bind_addr.ip().is_loopback() {
        return Err(NetdiagError::Connector(
            "OTLP gRPC receiver bind address must use a loopback interface".to_string(),
        ));
    }
    Ok(bind_addr)
}

fn finish_one_shot_collection<T>(session: OtlpReceiverSession, result: Result<T>) -> Result<T> {
    match (result, session.stop()) {
        (Ok(value), Ok(_)) => Ok(value),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(primary), Ok(_)) => Err(primary),
        (Err(primary), Err(cleanup)) => Err(primary.with_secondary_failure(
            "OTLP collection failed",
            "OTLP receiver cleanup also failed",
            cleanup,
        )),
    }
}

fn configured_metrics_service(
    service: OtlpMetricsReceiver,
) -> MetricsServiceServer<OtlpMetricsReceiver> {
    MetricsServiceServer::new(service).max_decoding_message_size(MAX_DECODING_MESSAGE_BYTES)
}

#[derive(Debug)]
struct OtlpMetricsReceiver {
    buffer: Arc<Mutex<OtlpFrameBuffer>>,
    schema: Arc<OtlpProjectionSchema>,
}

#[tonic::async_trait]
impl MetricsService for OtlpMetricsReceiver {
    async fn export(
        &self,
        request: Request<ExportMetricsServiceRequest>,
    ) -> std::result::Result<Response<ExportMetricsServiceResponse>, Status> {
        let frame = self.schema.project(request.get_ref())?;
        self.schema.validate_complete(&frame)?;
        self.buffer
            .lock()
            .map_err(|_| Status::internal("OTLP receiver buffer lock poisoned"))?
            .push(frame)?;
        Ok(Response::new(ExportMetricsServiceResponse {
            partial_success: None,
        }))
    }
}

#[cfg(test)]
pub(super) fn parse_otlp_metrics_request(
    request: &ExportMetricsServiceRequest,
    mapping: &BTreeMap<String, String>,
) -> std::result::Result<(BTreeMap<String, f64>, i64), Status> {
    let schema = OtlpProjectionSchema::new(mapping.clone())
        .map_err(|_| Status::invalid_argument("invalid OTLP metric mapping"))?;
    let frame = schema.project(request)?;
    let values = schema
        .values(&frame)
        .map(|(name, value)| (name.to_string(), value))
        .collect();
    Ok((values, frame.timestamp_ms))
}
