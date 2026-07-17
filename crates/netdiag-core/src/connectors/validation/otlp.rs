use crate::error::{NetdiagError, Result};
use std::time::Duration;

pub(in crate::connectors) fn validate_otlp_timeout(timeout: Duration) -> Result<()> {
    if timeout.is_zero() || timeout > Duration::from_secs(300) {
        Err(NetdiagError::Connector(
            "OTLP receiver timeout must be between 1 and 300 seconds".to_string(),
        ))
    } else {
        Ok(())
    }
}

pub(in crate::connectors) fn checked_chrono_duration(
    name: &str,
    value: Duration,
) -> Result<chrono::Duration> {
    chrono::Duration::from_std(value)
        .map_err(|_| NetdiagError::Connector(format!("{name} exceeds the supported range")))
}
