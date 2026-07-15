use super::*;
use crate::connector_auth::bearer_scope_for_endpoint;
use crate::secrets::{MemorySecretStore, SecretStore};
use crate::settings::{ApiSettings, AppSettings};
use chrono::TimeZone;
use netdiag_core::authentication::{BearerSourceKind, ValidatedBearerToken, validate_bearer_token};
use netdiag_core::connectors::NativePcapSource;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;

struct NoSecrets;

impl SecretStore for NoSecrets {
    fn get_bearer_token(
        &self,
        _scope: &crate::secrets::BearerSecretScope,
    ) -> anyhow::Result<Option<ValidatedBearerToken>> {
        panic!("unauthenticated source must not read the secret store")
    }

    fn set_bearer_token(
        &self,
        _scope: &crate::secrets::BearerSecretScope,
        _token: &str,
    ) -> anyhow::Result<()> {
        panic!("test does not write secrets")
    }

    fn delete_bearer_token(
        &self,
        _scope: &crate::secrets::BearerSecretScope,
    ) -> anyhow::Result<()> {
        panic!("test does not delete secrets")
    }

    fn get_legacy_live_api_token(&self) -> anyhow::Result<Option<ValidatedBearerToken>> {
        panic!("unauthenticated source must not read the legacy secret store")
    }

    fn delete_legacy_live_api_token(&self) -> anyhow::Result<()> {
        panic!("test does not delete legacy secrets")
    }
}

static NO_SECRETS: NoSecrets = NoSecrets;

struct MutableCountingStore {
    scope: crate::secrets::BearerSecretScope,
    token: Mutex<Option<String>>,
    reads: AtomicUsize,
}

impl MutableCountingStore {
    fn new(scope: crate::secrets::BearerSecretScope, token: &str) -> Self {
        Self {
            scope,
            token: Mutex::new(Some(token.to_string())),
            reads: AtomicUsize::new(0),
        }
    }
}

impl SecretStore for MutableCountingStore {
    fn get_bearer_token(
        &self,
        scope: &crate::secrets::BearerSecretScope,
    ) -> anyhow::Result<Option<ValidatedBearerToken>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if scope != &self.scope {
            return Ok(None);
        }
        let tokens = self
            .token
            .lock()
            .map_err(|_| anyhow::anyhow!("test token lock poisoned"))?;
        tokens
            .as_deref()
            .map(|token| validate_bearer_token(token.to_owned()).map_err(anyhow::Error::from))
            .transpose()
    }

    fn set_bearer_token(
        &self,
        scope: &crate::secrets::BearerSecretScope,
        token: &str,
    ) -> anyhow::Result<()> {
        if scope != &self.scope {
            anyhow::bail!("unexpected test scope");
        }
        *self
            .token
            .lock()
            .map_err(|_| anyhow::anyhow!("test token lock poisoned"))? = Some(token.to_string());
        Ok(())
    }

    fn delete_bearer_token(&self, scope: &crate::secrets::BearerSecretScope) -> anyhow::Result<()> {
        if scope != &self.scope {
            anyhow::bail!("unexpected test scope");
        }
        *self
            .token
            .lock()
            .map_err(|_| anyhow::anyhow!("test token lock poisoned"))? = None;
        Ok(())
    }

    fn get_legacy_live_api_token(&self) -> anyhow::Result<Option<ValidatedBearerToken>> {
        Ok(None)
    }

    fn delete_legacy_live_api_token(&self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[test]
fn unavailable_and_invalid_sources_fail_closed() {
    let unavailable = SourceMode::Unavailable {
        reason: "configured source is unavailable".to_string(),
    }
    .load(&NO_SECRETS)
    .expect_err("unavailable source must not run a simulation");
    assert!(
        unavailable
            .to_string()
            .contains("configured source is unavailable")
    );

    let invalid = SourceMode::LocalProbe(LocalProbeSettings { samples: 0 })
        .load(&NO_SECRETS)
        .expect_err("invalid sample count must not be clamped");
    assert!(invalid.to_string().contains("between 1 and 20"));
}

#[test]
fn native_pcap_source_classification_is_lexical_and_unambiguous() {
    assert!(matches!(
        native_pcap_source("iface:en0"),
        NativePcapSource::Interface(interface) if interface == "en0"
    ));
    assert!(matches!(
        native_pcap_source("capture"),
        NativePcapSource::Interface(interface) if interface == "capture"
    ));
    assert!(matches!(
        native_pcap_source("capture.pcap"),
        NativePcapSource::File(path) if path == std::path::Path::new("capture.pcap")
    ));
    assert!(matches!(
        native_pcap_source(r"captures\capture"),
        NativePcapSource::File(path) if path == std::path::Path::new(r"captures\capture")
    ));
}

#[test]
fn http_json_connector_accepts_bare_records_and_bearer_token() {
    let records = vec![record(0, 42.0)];
    let body = serde_json::to_string(&records).expect("records json");
    let (url, handle) = serve_once(200, body, Some("authorization: Bearer secret-token"));
    let secrets = MemorySecretStore::new();
    let scope = bearer_scope_for_endpoint("legacy_live_api", BearerSourceKind::HttpJson, &url)
        .expect("legacy API scope");
    secrets
        .set_bearer_token(&scope, "secret-token")
        .expect("store token");
    let config = api_config(url);

    let snapshot = SourceMode::Api(config, Some(scope))
        .load(&secrets)
        .expect("api source");
    handle.join().expect("server thread");

    assert_eq!(snapshot.ingest.records.len(), 1);
    assert_eq!(snapshot.ingest.records[0].latency_ms, 42.0);
    assert_eq!(snapshot.descriptor.kind, "Live API");
}

#[test]
fn source_mode_reads_the_latest_token_once_and_deletion_blocks_the_next_load() {
    let records = vec![record(0, 42.0)];
    let body = serde_json::to_string(&records).expect("records json");
    let (url, handle) = serve_once(200, body, Some("authorization: Bearer rotated-token"));
    let scope = bearer_scope_for_endpoint("rotating-profile", BearerSourceKind::HttpJson, &url)
        .expect("scope");
    let store = MutableCountingStore::new(scope.clone(), "stale-token");
    let source = SourceMode::Api(api_config(url), Some(scope.clone()));
    store
        .set_bearer_token(&scope, "rotated-token")
        .expect("rotate token");

    source.load(&store).expect("load with rotated token");
    handle.join().expect("server thread");
    assert_eq!(store.reads.load(Ordering::SeqCst), 1);

    store.delete_bearer_token(&scope).expect("delete token");
    let error = source
        .load(&store)
        .expect_err("deleted token must block the next load before networking");
    assert!(error.to_string().contains("no token is bound"), "{error}");
    assert!(!error.to_string().contains("rotated-token"));
    assert_eq!(store.reads.load(Ordering::SeqCst), 2);
}

#[test]
fn mismatched_scope_is_rejected_before_secret_store_access() {
    let scope = bearer_scope_for_endpoint(
        "profile",
        BearerSourceKind::HttpJson,
        "http://127.0.0.1:21001/traces",
    )
    .expect("scope");
    let store = MutableCountingStore::new(scope.clone(), "secret-token");
    let source = SourceMode::Api(
        api_config("http://127.0.0.1:21002/traces".to_string()),
        Some(scope),
    );

    let error = source
        .load(&store)
        .expect_err("origin mismatch must fail before reading the token");
    assert!(
        error.to_string().contains("scope does not match"),
        "{error}"
    );
    assert_eq!(store.reads.load(Ordering::SeqCst), 0);
    assert!(!format!("{source:?}").contains("secret-token"));
    assert!(!format!("{source:?}").contains("bearer_v1_"));
}

#[test]
fn http_json_connector_accepts_metadata_and_flows() {
    let body = serde_json::json!({
        "sample": "lab-router-1",
        "protocol": "TCP",
        "flows": [
            { "src": "10.0.0.2", "dst": "10.0.0.3", "bytes": 2048, "protocol": "TCP" }
        ],
        "records": [record(0, 55.0)]
    })
    .to_string();
    let (url, handle) = serve_once(200, body, None);
    let snapshot = SourceMode::Api(api_config(url), None)
        .load(&NO_SECRETS)
        .expect("metadata source");
    handle.join().expect("server thread");

    assert_eq!(snapshot.descriptor.name, "lab-router-1");
    assert_eq!(snapshot.flow_summary.flows, Some(1));
    assert_eq!(snapshot.flow_summary.total_bytes, Some(2048));
    assert_eq!(
        snapshot.flow_summary.top_talkers[0].label,
        "10.0.0.2 ↔ 10.0.0.3"
    );
}

#[test]
fn http_json_connector_rejects_error_status_and_invalid_json() {
    let (error_url, error_handle) = serve_once(500, "boom".to_string(), None);
    let err = SourceMode::Api(api_config(error_url), None)
        .load(&NO_SECRETS)
        .expect_err("500 should fail");
    error_handle.join().expect("server thread");
    assert!(err.to_string().contains("HTTP status 500"), "{err}");

    let (json_url, json_handle) = serve_once(200, "not-json".to_string(), None);
    let err = SourceMode::Api(api_config(json_url), None)
        .load(&NO_SECRETS)
        .expect_err("invalid json should fail");
    json_handle.join().expect("server thread");
    assert!(err.to_string().contains("valid JSON"));
}

#[test]
fn http_json_connector_rejects_empty_records() {
    let (url, handle) = serve_once(200, r#"{"records":[]}"#.to_string(), None);
    let err = SourceMode::Api(api_config(url), None)
        .load(&NO_SECRETS)
        .expect_err("empty records should fail");
    handle.join().expect("server thread");
    assert!(err.to_string().contains("trace has no rows"));
}

#[test]
fn probe_sources_emit_fallback_warnings_without_inventing_throughput() {
    let snapshot = SourceMode::LocalProbe(LocalProbeSettings { samples: 2 })
        .load(&NO_SECRETS)
        .expect("local probe");

    assert_eq!(snapshot.ingest.records.len(), 2);
    assert!(
        snapshot
            .ingest
            .warnings
            .iter()
            .any(|warning| warning.column == "throughput_mbps")
    );
    assert!(
        snapshot
            .ingest
            .records
            .iter()
            .all(|record| record.throughput_mbps == 0.0)
    );
}

#[test]
fn website_probe_collects_a_hermetic_loopback_http_target() {
    let (url, handle) = serve_once(200, "ok".to_string(), None);
    let snapshot = SourceMode::WebsiteProbe(WebsiteProbeSettings {
        targets: vec![url],
        samples_per_target: 1,
    })
    .load(&NO_SECRETS)
    .expect("loopback website probe");
    handle.join().expect("server thread");

    assert_eq!(snapshot.ingest.records.len(), 1);
    let record = &snapshot.ingest.records[0];
    assert_eq!(record.packet_loss_rate, 0.0);
    assert_eq!(record.timeout_events, 0.0);
    assert_eq!(record.retry_events, 0.0);
    assert!(record.latency_ms > 0.0);
}

#[test]
fn website_probe_reports_loopback_connection_refusal_as_a_failed_sample() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve loopback address");
    let addr = listener.local_addr().expect("local address");
    drop(listener);

    let snapshot = SourceMode::WebsiteProbe(WebsiteProbeSettings {
        targets: vec![format!("http://{addr}/unreachable")],
        samples_per_target: 1,
    })
    .load(&NO_SECRETS)
    .expect("a failed probe remains an observed sample");

    assert_eq!(snapshot.ingest.records.len(), 1);
    let record = &snapshot.ingest.records[0];
    assert_eq!(record.packet_loss_rate, 100.0);
    assert_eq!(record.timeout_events, 0.0);
    assert_eq!(record.retry_events, 0.0);
    assert_eq!(record.dns_failure_events, 0.0);
}

#[test]
#[ignore = "touches public network targets; run manually for release smoke"]
fn website_probe_can_collect_default_public_targets() {
    let snapshot = SourceMode::WebsiteProbe(WebsiteProbeSettings::default())
        .load(&NO_SECRETS)
        .expect("website probe");

    assert!(!snapshot.ingest.records.is_empty());
    assert!(
        snapshot
            .ingest
            .records
            .iter()
            .any(|record| record.latency_ms > 0.0)
    );
}

fn api_config(url: String) -> ApiConfig {
    AppSettings {
        api: ApiSettings {
            endpoint: url,
            timeout_secs: 2,
        },
        ..AppSettings::default()
    }
    .api_config_with_env(std::iter::empty::<(&str, &str)>())
    .expect("api config")
}

fn serve_once(
    status: u16,
    body: String,
    expected_header: Option<&'static str>,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let addr = listener.local_addr().expect("local addr");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut request = [0_u8; 4096];
        let bytes = stream.read(&mut request).expect("read request");
        let request_text = String::from_utf8_lossy(&request[..bytes]);
        if let Some(header) = expected_header {
            assert!(request_text.contains(header), "{request_text}");
        }
        let status_text = if status == 200 { "OK" } else { "ERROR" };
        let response = format!(
            "HTTP/1.1 {status} {status_text}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write response");
    });
    (format!("http://{addr}/trace"), handle)
}

fn record(offset: i64, latency_ms: f64) -> TraceRecord {
    TraceRecord {
        timestamp: Utc
            .with_ymd_and_hms(2026, 4, 30, 12, 0, 0)
            .single()
            .expect("timestamp")
            + Duration::seconds(offset),
        latency_ms,
        jitter_ms: 1.0,
        packet_loss_rate: 0.0,
        retransmission_rate: 0.0,
        timeout_events: 0.0,
        retry_events: 0.0,
        throughput_mbps: 10.0,
        dns_failure_events: 0.0,
        tls_failure_events: 0.0,
        quic_blocked_ratio: 0.0,
    }
}
