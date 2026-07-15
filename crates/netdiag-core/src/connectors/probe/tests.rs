use super::*;
use crate::connectors::CaptureControl;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::{Duration, Instant};

const PROXY_CHILD_ENV: &str = "NETDIAG_PROBE_NO_PROXY_CHILD";

#[test]
fn target_validation_rejects_ambiguous_or_sensitive_inputs_without_echoing_them() {
    for target in [
        "HTTP://example.com/",
        "ftp://example.com/",
        "http://user:password@example.com/",
        "https://example.com/#secret-fragment",
        "https://example.com/?access_token=secret-value",
        "localhost:443",
        " https://example.com/",
        "https://example.com/ ",
    ] {
        let error = website_config([target], 1)
            .validate()
            .expect_err("ambiguous target must fail before I/O");
        assert!(!error.to_string().contains(target), "{error}");
        assert!(!error.to_string().contains("secret-value"), "{error}");
        assert!(!error.to_string().contains("password"), "{error}");
    }
}

#[test]
fn target_validation_enforces_shape_and_canonical_uniqueness() {
    assert!(
        website_config(std::iter::empty::<&str>(), 1)
            .validate()
            .is_err()
    );
    assert!(website_config(["127.0.0.1:80"], 0).validate().is_err());
    assert!(website_config(["127.0.0.1:80"], 13).validate().is_err());
    assert!(
        website_config(["http://example.com", "http://example.com/"], 1)
            .validate()
            .is_err()
    );
    let oversized = "a".repeat(MAX_PROBE_TARGET_BYTES + 1);
    assert!(website_config([oversized.as_str()], 1).validate().is_err());
    let too_many = (0..=MAX_WEBSITE_PROBE_TARGETS)
        .map(|port| format!("127.0.0.1:{}", 10_000 + port))
        .collect::<Vec<_>>();
    assert!(
        WebsiteProbeConfig {
            targets: too_many,
            samples_per_target: 1,
        }
        .validate()
        .is_err()
    );
}

#[test]
fn maximum_website_shape_fits_the_default_bounded_execution_budget() {
    let targets = (0..MAX_WEBSITE_PROBE_TARGETS)
        .map(|port| format!("127.0.0.1:{}", 20_000 + port))
        .collect::<Vec<_>>();
    WebsiteProbeConfig {
        targets,
        samples_per_target: MAX_WEBSITE_PROBE_SAMPLES,
    }
    .validate()
    .expect("maximum shape is valid");

    let batches = MAX_WEBSITE_PROBE_TARGETS.div_ceil(MAX_PROBE_CONCURRENCY);
    let worst_case = DEFAULT_REQUEST_TIMEOUT * (batches * MAX_WEBSITE_PROBE_SAMPLES) as u32;
    assert!(worst_case < DEFAULT_OVERALL_TIMEOUT);
}

#[test]
fn local_probe_uses_adjacent_same_target_latency_for_jitter() {
    let loaded = load_local_probe(&LocalProbeConfig { samples: 3 }).expect("local probe");
    let records = &loaded.ingest.records;
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].jitter_ms, 0.0);
    assert_eq!(
        records[1].jitter_ms,
        (records[1].latency_ms - records[0].latency_ms).abs()
    );
    assert_eq!(
        records[2].jitter_ms,
        (records[2].latency_ms - records[1].latency_ms).abs()
    );
    assert!(records.iter().all(|record| record.packet_loss_rate == 0.0));
    let jitter = loaded
        .ingest
        .metric_provenance
        .iter()
        .find(|item| item.field == "jitter_ms")
        .expect("jitter provenance");
    assert!(jitter.reason.contains("same target"));
    assert!(jitter.reason.contains("history is unavailable"));
}

#[test]
fn website_probe_collects_loopback_and_computes_nonzero_jitter() {
    let (url, server) = serve_delayed([Duration::from_millis(5), Duration::from_millis(60)]);
    let loaded = load_website_probe_with_control(
        &website_config([url.as_str()], 2),
        test_options(Duration::from_millis(250), Duration::from_secs(2)),
        &CaptureControl::default(),
    )
    .expect("website probe");
    server.join().expect("loopback server");

    let records = &loaded.ingest.records;
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].jitter_ms, 0.0);
    assert_eq!(
        records[1].jitter_ms,
        (records[1].latency_ms - records[0].latency_ms).abs()
    );
    assert!(records[1].jitter_ms > 20.0, "{records:?}");
    assert!(records.iter().all(|record| record.packet_loss_rate == 0.0));
}

#[test]
fn refused_connection_is_a_real_failed_sample_without_fake_timeout_latency() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve address");
    let address = listener.local_addr().expect("address");
    drop(listener);
    let request_timeout = Duration::from_millis(500);
    let loaded = load_website_probe_with_control(
        &website_config([address.to_string().as_str()], 1),
        test_options(request_timeout, Duration::from_secs(2)),
        &CaptureControl::default(),
    )
    .expect("failed connection remains an observed sample");
    let record = &loaded.ingest.records[0];
    assert_eq!(record.packet_loss_rate, 100.0);
    assert_eq!(record.timeout_events, 0.0);
    assert_eq!(record.retry_events, 0.0);
    assert!(record.latency_ms < request_timeout.as_millis() as f64);
}

#[test]
fn http_redirect_is_not_followed() {
    let destination = TcpListener::bind("127.0.0.1:0").expect("destination listener");
    destination
        .set_nonblocking(true)
        .expect("nonblocking destination");
    let destination_url = format!(
        "http://{}/should-not-be-requested",
        destination.local_addr().expect("destination address")
    );
    let (url, server) = serve_response(
        302,
        &format!("location: {destination_url}\r\ncontent-length: 0\r\n"),
    );
    let loaded = load_website_probe_with_control(
        &website_config([url.as_str()], 1),
        test_options(Duration::from_millis(250), Duration::from_secs(2)),
        &CaptureControl::default(),
    )
    .expect("redirect is a failed observed sample");
    server.join().expect("redirect server");

    assert_eq!(loaded.ingest.records[0].packet_loss_rate, 100.0);
    assert!(matches!(
        destination.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[test]
fn http_probe_does_not_use_environment_proxy() {
    if std::env::var_os(PROXY_CHILD_ENV).is_some() {
        let loaded = load_website_probe_with_control(
            &website_config(["http://no-proxy-contract.invalid/"], 1),
            test_options(Duration::from_millis(150), Duration::from_secs(1)),
            &CaptureControl::default(),
        )
        .expect("transport failure remains a sample");
        assert_eq!(loaded.ingest.records[0].packet_loss_rate, 100.0);
        return;
    }

    let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy listener");
    proxy.set_nonblocking(true).expect("nonblocking proxy");
    let proxy_url = format!("http://{}", proxy.local_addr().expect("proxy address"));
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("connectors::probe::tests::http_probe_does_not_use_environment_proxy")
        .arg("--nocapture")
        .env(PROXY_CHILD_ENV, "1")
        .env("HTTP_PROXY", &proxy_url)
        .env("http_proxy", &proxy_url)
        .env("ALL_PROXY", &proxy_url)
        .env("all_proxy", &proxy_url)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .output()
        .expect("run isolated no-proxy contract");
    assert!(
        output.status.success(),
        "child stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(matches!(
        proxy.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
}

#[test]
fn overall_deadline_stops_an_incomplete_plan() {
    let (url, accepted, server) = serve_hanging_with_accept(Duration::from_millis(450));
    let started = Instant::now();
    let error = load_website_probe_with_control(
        &website_config([url.as_str()], 3),
        test_options(Duration::from_millis(150), Duration::from_millis(200)),
        &CaptureControl::default(),
    )
    .expect_err("incomplete plan must fail closed at the global deadline");
    let elapsed = started.elapsed();
    drop(accepted);
    server.join().expect("hanging server");
    assert!(error.to_string().contains("overall deadline"), "{error}");
    assert!(elapsed < Duration::from_millis(350), "{elapsed:?}");
}

#[test]
fn cancellation_stops_an_incomplete_plan() {
    let (url, accepted, server) = serve_hanging_with_accept(Duration::from_millis(350));
    let control = CaptureControl::new(Arc::new(AtomicBool::new(false)));
    let worker_control = control.clone();
    let worker = thread::spawn(move || {
        load_website_probe_with_control(
            &website_config([url.as_str()], 2),
            test_options(Duration::from_millis(300), Duration::from_secs(1)),
            &worker_control,
        )
    });
    accepted
        .recv_timeout(Duration::from_secs(1))
        .expect("first request accepted");
    control.cancel();
    let started = Instant::now();
    let error = worker
        .join()
        .expect("probe worker")
        .expect_err("cancelled plan must fail closed");
    let elapsed = started.elapsed();
    server.join().expect("hanging server");
    assert!(matches!(error, NetdiagError::CaptureCancelled { .. }));
    assert!(elapsed < Duration::from_millis(400), "{elapsed:?}");
}

#[test]
fn fixed_concurrency_avoids_serial_target_execution() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("parallel server");
    let address = listener.local_addr().expect("parallel address");
    let server = thread::spawn(move || {
        let mut handlers = Vec::new();
        for _ in 0..MAX_PROBE_CONCURRENCY {
            let (stream, _) = listener.accept().expect("parallel accept");
            handlers.push(thread::spawn(move || {
                respond_after(stream, Duration::from_millis(100), 200, "")
            }));
        }
        for handler in handlers {
            handler.join().expect("parallel response");
        }
    });
    let targets = (0..MAX_PROBE_CONCURRENCY)
        .map(|index| format!("http://{address}/target-{index}"))
        .collect::<Vec<_>>();
    let started = Instant::now();
    let loaded = load_website_probe_with_control(
        &WebsiteProbeConfig {
            targets,
            samples_per_target: 1,
        },
        test_options(Duration::from_millis(500), Duration::from_secs(2)),
        &CaptureControl::default(),
    )
    .expect("parallel website probe");
    let elapsed = started.elapsed();
    server.join().expect("parallel server");
    assert_eq!(loaded.ingest.records.len(), MAX_PROBE_CONCURRENCY);
    assert!(elapsed < Duration::from_millis(600), "{elapsed:?}");
}

fn website_config<I, S>(targets: I, samples_per_target: usize) -> WebsiteProbeConfig
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    WebsiteProbeConfig {
        targets: targets
            .into_iter()
            .map(|target| target.as_ref().to_string())
            .collect(),
        samples_per_target,
    }
}

fn test_options(request_timeout: Duration, overall_timeout: Duration) -> ProbeExecutionOptions {
    ProbeExecutionOptions {
        request_timeout,
        overall_timeout,
    }
}

fn serve_delayed<const N: usize>(delays: [Duration; N]) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("delayed server");
    let address = listener.local_addr().expect("delayed address");
    let server = thread::spawn(move || {
        for delay in delays {
            let (stream, _) = listener.accept().expect("delayed accept");
            respond_after(stream, delay, 200, "");
        }
    });
    (format!("http://{address}/probe"), server)
}

fn serve_response(status: u16, headers: &str) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("response server");
    let address = listener.local_addr().expect("response address");
    let headers = headers.to_string();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("response accept");
        respond_after(stream, Duration::ZERO, status, &headers);
    });
    (format!("http://{address}/probe"), server)
}

fn serve_hanging_with_accept(
    delay: Duration,
) -> (
    String,
    std::sync::mpsc::Receiver<()>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("hanging server");
    let address = listener.local_addr().expect("hanging address");
    let (sender, receiver) = std::sync::mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("hanging accept");
        let mut request = [0_u8; 1024];
        let _bytes = stream.read(&mut request).expect("hanging request");
        sender.send(()).expect("notify accepted request");
        thread::sleep(delay);
    });
    (format!("http://{address}/probe"), receiver, server)
}

fn respond_after(mut stream: TcpStream, delay: Duration, status: u16, headers: &str) {
    let mut request = [0_u8; 2048];
    let _bytes = stream.read(&mut request).expect("read request");
    thread::sleep(delay);
    let reason = if status == 200 { "OK" } else { "Redirect" };
    let response = format!("HTTP/1.1 {status} {reason}\r\n{headers}connection: close\r\n\r\n");
    stream
        .write_all(response.as_bytes())
        .expect("write response");
}
