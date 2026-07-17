use super::{CaptureControl, ConnectorLoadResult};
use crate::error::{NetdiagError, Result};
use std::net::{Ipv4Addr, TcpListener};
use std::time::Duration;

mod executor;
mod measurement;
mod output;
mod target;

use executor::execute_probe_plan;
use output::build_probe_result;
use target::{ProbeTarget, parse_website_targets};

pub const MAX_LOCAL_PROBE_SAMPLES: usize = 20;
pub const MAX_WEBSITE_PROBE_SAMPLES: usize = 12;
pub const MAX_WEBSITE_PROBE_TARGETS: usize = 64;
pub const MAX_PROBE_TARGET_BYTES: usize = 2 * 1024;
pub const MAX_PROBE_CONCURRENCY: usize = 16;

const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_OVERALL_TIMEOUT: Duration = Duration::from_secs(60);
const MIN_REQUEST_TIMEOUT: Duration = Duration::from_millis(1);
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_OVERALL_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalProbeConfig {
    pub samples: usize,
}

impl LocalProbeConfig {
    pub fn validate(&self) -> Result<()> {
        validate_sample_count(
            self.samples,
            MAX_LOCAL_PROBE_SAMPLES,
            "local probe sample count",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebsiteProbeConfig {
    pub targets: Vec<String>,
    pub samples_per_target: usize,
}

impl WebsiteProbeConfig {
    pub fn validate(&self) -> Result<()> {
        validate_sample_count(
            self.samples_per_target,
            MAX_WEBSITE_PROBE_SAMPLES,
            "website probe samples per target",
        )?;
        parse_website_targets(&self.targets).map(drop)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeExecutionOptions {
    pub request_timeout: Duration,
    pub overall_timeout: Duration,
}

impl Default for ProbeExecutionOptions {
    fn default() -> Self {
        Self {
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            overall_timeout: DEFAULT_OVERALL_TIMEOUT,
        }
    }
}

impl ProbeExecutionOptions {
    fn validate(self) -> Result<Self> {
        if self.request_timeout < MIN_REQUEST_TIMEOUT || self.request_timeout > MAX_REQUEST_TIMEOUT
        {
            return Err(NetdiagError::Connector(format!(
                "active probe request timeout must be within 1ms..={}ms",
                MAX_REQUEST_TIMEOUT.as_millis()
            )));
        }
        if self.overall_timeout < self.request_timeout || self.overall_timeout > MAX_OVERALL_TIMEOUT
        {
            return Err(NetdiagError::Connector(format!(
                "active probe overall timeout must be between the request timeout and {}ms",
                MAX_OVERALL_TIMEOUT.as_millis()
            )));
        }
        Ok(self)
    }
}

pub fn load_local_probe(config: &LocalProbeConfig) -> Result<ConnectorLoadResult> {
    load_local_probe_with_control(
        config,
        ProbeExecutionOptions::default(),
        &CaptureControl::default(),
    )
}

pub fn load_local_probe_with_control(
    config: &LocalProbeConfig,
    options: ProbeExecutionOptions,
    control: &CaptureControl,
) -> Result<ConnectorLoadResult> {
    config.validate()?;
    let options = options.validate()?;
    ensure_not_cancelled(control)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| {
        NetdiagError::Connector("local probe could not bind its loopback listener".to_string())
    })?;
    let address = listener.local_addr().map_err(|_| {
        NetdiagError::Connector("local probe could not inspect its loopback listener".to_string())
    })?;
    let measurements = execute_probe_plan(
        vec![ProbeTarget::Tcp(address)],
        config.samples,
        options,
        control,
    )?;
    drop(listener);
    build_probe_result(measurements, 1, config.samples, "local_probe")
}

pub fn load_website_probe(config: &WebsiteProbeConfig) -> Result<ConnectorLoadResult> {
    load_website_probe_with_control(
        config,
        ProbeExecutionOptions::default(),
        &CaptureControl::default(),
    )
}

pub fn load_website_probe_with_control(
    config: &WebsiteProbeConfig,
    options: ProbeExecutionOptions,
    control: &CaptureControl,
) -> Result<ConnectorLoadResult> {
    validate_sample_count(
        config.samples_per_target,
        MAX_WEBSITE_PROBE_SAMPLES,
        "website probe samples per target",
    )?;
    let targets = parse_website_targets(&config.targets)?;
    let options = options.validate()?;
    ensure_not_cancelled(control)?;
    let target_count = targets.len();
    let measurements = execute_probe_plan(targets, config.samples_per_target, options, control)?;
    build_probe_result(
        measurements,
        target_count,
        config.samples_per_target,
        "website_probe",
    )
}

fn validate_sample_count(samples: usize, maximum: usize, context: &str) -> Result<()> {
    if (1..=maximum).contains(&samples) {
        Ok(())
    } else {
        Err(NetdiagError::Connector(format!(
            "{context} must be between 1 and {maximum}"
        )))
    }
}

fn ensure_not_cancelled(control: &CaptureControl) -> Result<()> {
    if control.is_cancelled() {
        Err(NetdiagError::CaptureCancelled {
            context: "active probe before network access",
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
