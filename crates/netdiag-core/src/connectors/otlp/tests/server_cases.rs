use super::*;
use opentelemetry_proto::tonic::collector::metrics::v1::metrics_service_client::MetricsServiceClient;
use std::io::Write;
use std::net::TcpStream;
use std::time::Instant;

#[test]
fn receiver_core_boundary_rejects_non_loopback_addresses_before_startup() {
    for address in ["0.0.0.0:4317", "192.0.2.1:4317", "[::]:4317"] {
        let error = OtlpReceiverSession::start(&OtlpGrpcReceiverConfig {
            bind_addr: address.to_string(),
            timeout: Duration::from_secs(1),
            metrics: BTreeMap::new(),
            sample: "loopback-boundary".to_string(),
        })
        .expect_err("non-loopback startup must fail before binding");
        assert!(error.to_string().contains("loopback interface"));
    }
    assert!(parse_loopback_bind_addr("127.0.0.1:4317").is_ok());
    assert!(parse_loopback_bind_addr("[::1]:4317").is_ok());
}

#[test]
fn receiver_reports_actual_address_and_bounds_partial_connection_shutdown() {
    let session = test_session("bounded-shutdown");
    let address = session.local_addr();
    assert_ne!(address.port(), 0);

    let mut slow_connection = TcpStream::connect(address).expect("partial HTTP/2 connection");
    slow_connection
        .write_all(b"PRI * HTTP/2.0\r\n")
        .expect("partial HTTP/2 preface");
    let admission_deadline = Instant::now() + Duration::from_secs(2);
    while session.active_connections() == 0 && Instant::now() < admission_deadline {
        std::thread::yield_now();
    }
    assert_eq!(session.active_connections(), 1);

    let stop_started = Instant::now();
    let outcome = session
        .stop()
        .expect("partial HTTP/2 connection must be reclaimed");
    assert_eq!(outcome, OtlpShutdownOutcome::Forced);
    assert!(stop_started.elapsed() < Duration::from_secs(5));
    drop(slow_connection);
}

#[test]
fn generated_grpc_client_exports_and_snapshots_a_complete_observation() {
    let session = test_session("transport-roundtrip");
    let endpoint = format!("http://{}", session.local_addr());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test client runtime");
    runtime.block_on(async move {
        let mut client = MetricsServiceClient::connect(endpoint)
            .await
            .expect("generated OTLP client connection");
        client
            .export(complete_numeric_request(1_777_000_000_000_000_000))
            .await
            .expect("complete OTLP export");
    });
    drop(runtime);
    let snapshot = session
        .snapshot(Duration::from_secs(1))
        .expect("transported observation snapshot");

    assert_eq!(snapshot.ingest.records.len(), 1);
    let disconnect_deadline = Instant::now() + Duration::from_secs(2);
    while session.active_connections() != 0 && Instant::now() < disconnect_deadline {
        std::thread::yield_now();
    }
    assert_eq!(session.active_connections(), 0);
    assert_eq!(
        session.stop().expect("graceful receiver stop"),
        OtlpShutdownOutcome::Graceful
    );
}

fn test_session(sample: &str) -> OtlpReceiverSession {
    OtlpReceiverSession::start(&OtlpGrpcReceiverConfig {
        bind_addr: "127.0.0.1:0".to_string(),
        timeout: Duration::from_secs(1),
        metrics: BTreeMap::new(),
        sample: sample.to_string(),
    })
    .expect("receiver startup")
}
