use crate::error::{NetdiagError, Result};
use crate::resource_limits::{
    MAX_COLLECTION_TIMEOUT_SECS as MAX_TIMEOUT_SECS, MAX_PCAP_PACKET_LIMIT,
};
use serde::{Deserialize, Serialize};

const MAX_LOOKBACK_SECS: i64 = 86_400;
const MAX_STEP_SECS: u64 = 3_600;
const MAX_INTERVAL_SECS: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotCollection {
    #[serde(default = "default_pilot_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_pilot_lookback_secs")]
    pub lookback_secs: i64,
    #[serde(default = "default_pilot_step_secs")]
    pub step_secs: u64,
    #[serde(default = "default_pilot_packet_limit")]
    pub packet_limit: usize,
    #[serde(default = "default_pilot_interval_secs")]
    pub interval_secs: u64,
}

impl Default for PilotCollection {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            lookback_secs: 300,
            step_secs: 15,
            packet_limit: 256,
            interval_secs: 1,
        }
    }
}

impl PilotCollection {
    pub(crate) fn validate(&self) -> Result<()> {
        require_range("timeout_secs", self.timeout_secs, 1, MAX_TIMEOUT_SECS)?;
        if !(1..=MAX_LOOKBACK_SECS).contains(&self.lookback_secs) {
            return Err(NetdiagError::InvalidTrace(format!(
                "pilot collection lookback_secs must be between 1 and {MAX_LOOKBACK_SECS}"
            )));
        }
        require_range("step_secs", self.step_secs, 1, MAX_STEP_SECS)?;
        if self.step_secs > self.lookback_secs as u64 {
            return Err(NetdiagError::InvalidTrace(
                "pilot collection step_secs must not exceed lookback_secs".to_string(),
            ));
        }
        if !(1..=MAX_PCAP_PACKET_LIMIT).contains(&self.packet_limit) {
            return Err(NetdiagError::InvalidTrace(format!(
                "pilot collection packet_limit must be between 1 and {MAX_PCAP_PACKET_LIMIT}"
            )));
        }
        require_range("interval_secs", self.interval_secs, 1, MAX_INTERVAL_SECS)
    }
}

fn require_range(name: &str, value: u64, minimum: u64, maximum: u64) -> Result<()> {
    if (minimum..=maximum).contains(&value) {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "pilot collection {name} must be between {minimum} and {maximum}"
        )))
    }
}

fn default_pilot_timeout_secs() -> u64 {
    10
}
fn default_pilot_lookback_secs() -> i64 {
    300
}
fn default_pilot_step_secs() -> u64 {
    15
}
fn default_pilot_packet_limit() -> usize {
    256
}
fn default_pilot_interval_secs() -> u64 {
    1
}
