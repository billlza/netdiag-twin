use super::ConnectorKind;
use serde::{Deserialize, Serialize};

pub const LEGACY_LIVE_API_SCOPE_ID: &str = "legacy_live_api";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(tag = "owner_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum BearerCredentialOwner {
    LegacyLiveApi,
    Profile { profile_id: String },
}

impl BearerCredentialOwner {
    pub fn legacy_live_api() -> Self {
        Self::LegacyLiveApi
    }

    pub fn profile(profile_id: impl Into<String>) -> Self {
        Self::Profile {
            profile_id: profile_id.into(),
        }
    }

    pub(crate) fn scope_id(&self) -> &str {
        match self {
            Self::LegacyLiveApi => LEGACY_LIVE_API_SCOPE_ID,
            Self::Profile { profile_id } => profile_id,
        }
    }

    pub(crate) fn profile_id(&self) -> Option<&str> {
        match self {
            Self::LegacyLiveApi => None,
            Self::Profile { profile_id } => Some(profile_id),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BearerCredentialState {
    Active,
    PendingActivation,
    PendingDeletion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BearerCredentialBinding {
    pub owner: BearerCredentialOwner,
    pub connector_kind: ConnectorKind,
    pub canonical_origin: String,
    pub state: BearerCredentialState,
}
