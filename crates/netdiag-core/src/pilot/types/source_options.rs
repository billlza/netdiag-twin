use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PilotAdapterOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<PilotAdapterMode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Names of environment variables explicitly forwarded to the adapter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_allowlist: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotAdapterMode {
    Sample,
    Live,
}

impl PilotAdapterMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Sample => "sample",
            Self::Live => "live",
        }
    }
}
