use super::{BTreeMapString, validate_api_timeout};
use anyhow::{Result, bail};
use netdiag_core::connectors::default_prometheus_mapping;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct OtlpGrpcSettings {
    pub bind_addr: String,
    pub timeout_secs: u64,
    pub mapping: BTreeMapString,
}

impl Default for OtlpGrpcSettings {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:4317".to_string(),
            timeout_secs: 20,
            mapping: default_prometheus_mapping(),
        }
    }
}

impl OtlpGrpcSettings {
    pub fn validate(&self) -> Result<()> {
        validate_api_timeout(self.timeout_secs)?;
        validate_otlp_bind_addr(&self.bind_addr)
    }
}

pub(super) fn validate_otlp_bind_addr(value: &str) -> Result<()> {
    let bind_addr = value
        .trim()
        .parse::<SocketAddr>()
        .map_err(|_| anyhow::anyhow!("OTLP bind address must be a valid loopback host:port"))?;
    if !bind_addr.ip().is_loopback() {
        bail!("OTLP bind address must use a loopback interface");
    }
    if bind_addr.port() == 0 {
        bail!("OTLP bind address must use a fixed non-zero port");
    }
    Ok(())
}
