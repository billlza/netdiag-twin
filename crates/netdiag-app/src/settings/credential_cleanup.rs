use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CredentialCleanupJournal {
    pub legacy_live_api_pending_deletion: bool,
}
