use super::super::{NativePcapConfig, NativePcapSource, SystemCountersConfig};
use crate::error::{NetdiagError, Result};
use crate::resource_limits::{MAX_COLLECTION_TIMEOUT_SECS, MAX_PCAP_PACKET_LIMIT};
use std::time::Duration;

const MIN_PCAP_TIMEOUT: Duration = Duration::from_millis(1);
const MIN_COUNTER_INTERVAL: Duration = Duration::from_secs(1);
const MAX_COUNTER_INTERVAL: Duration = Duration::from_secs(10);
const MAX_INTERFACE_BYTES: usize = 128;

pub(in crate::connectors) fn validate_native_pcap_config(config: &NativePcapConfig) -> Result<()> {
    let maximum_timeout = Duration::from_secs(MAX_COLLECTION_TIMEOUT_SECS);
    if config.timeout < MIN_PCAP_TIMEOUT || config.timeout > maximum_timeout {
        return Err(NetdiagError::Connector(format!(
            "native pcap timeout must be within 1ms..={}ms",
            maximum_timeout.as_millis()
        )));
    }
    if !(1..=MAX_PCAP_PACKET_LIMIT).contains(&config.packet_limit) {
        return Err(NetdiagError::Connector(format!(
            "native pcap packet limit must be between 1 and {MAX_PCAP_PACKET_LIMIT}"
        )));
    }
    match &config.source {
        NativePcapSource::File(path) if path.as_os_str().is_empty() => Err(
            NetdiagError::Connector("native pcap file path is empty".to_string()),
        ),
        NativePcapSource::Interface(interface) => validate_interface(interface, "native pcap"),
        NativePcapSource::File(_) => Ok(()),
    }
}

pub(in crate::connectors) fn validate_system_counters_config(
    config: &SystemCountersConfig,
) -> Result<()> {
    if config.interval < MIN_COUNTER_INTERVAL || config.interval > MAX_COUNTER_INTERVAL {
        return Err(NetdiagError::Connector(
            "system counters interval must be between 1 and 10 seconds".to_string(),
        ));
    }
    if let Some(interface) = &config.interface {
        validate_interface(interface, "system counters")?;
    }
    Ok(())
}

fn validate_interface(interface: &str, context: &str) -> Result<()> {
    if interface.is_empty()
        || interface.len() > MAX_INTERFACE_BYTES
        || interface.trim() != interface
        || interface.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(NetdiagError::Connector(format!(
            "{context} interface must be a non-empty, whitespace-free value of at most {MAX_INTERFACE_BYTES} bytes"
        )));
    }
    Ok(())
}
