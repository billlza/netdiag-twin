use super::target::ProbeTarget;
use crate::error::{NetdiagError, Result};
use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use std::net::TcpStream;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(super) struct ProbeMeasurement {
    pub(super) target_index: usize,
    pub(super) sample_index: usize,
    pub(super) success: bool,
    pub(super) latency_ms: f64,
    pub(super) timeout: bool,
}

pub(super) fn build_http_client(request_timeout: Duration) -> Result<Client> {
    Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .connect_timeout(request_timeout)
        .timeout(request_timeout)
        .build()
        .map_err(|_| {
            NetdiagError::Connector("active probe HTTP client initialization failed".to_string())
        })
}

pub(super) fn measure_target(
    target: &ProbeTarget,
    target_index: usize,
    sample_index: usize,
    timeout: Duration,
    http_client: Option<&Client>,
) -> Result<ProbeMeasurement> {
    let started = Instant::now();
    let (success, timed_out) = match target {
        ProbeTarget::Http(endpoint) => {
            let client = http_client.ok_or_else(|| {
                NetdiagError::Connector(
                    "active probe HTTP client is unavailable for an HTTP target".to_string(),
                )
            })?;
            match client.get(endpoint.clone()).timeout(timeout).send() {
                Ok(response) => (response.status().is_success(), false),
                Err(error) => (false, error.is_timeout()),
            }
        }
        ProbeTarget::Tcp(address) => match TcpStream::connect_timeout(address, timeout) {
            Ok(stream) => {
                drop(stream);
                (true, false)
            }
            Err(error) => (false, error.kind() == std::io::ErrorKind::TimedOut),
        },
    };
    Ok(ProbeMeasurement {
        target_index,
        sample_index,
        success,
        latency_ms: started.elapsed().as_secs_f64() * 1000.0,
        timeout: timed_out,
    })
}
