use super::SettingsStore;
use super::revision::SettingsAccessState;
use netdiag_core::NetdiagError;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsVerificationError {
    Conflict { path: PathBuf },
    Indeterminate { path: PathBuf, detail: String },
    UnpersistedSnapshot { path: PathBuf },
}

impl std::fmt::Display for SettingsVerificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict { path } => write!(
                formatter,
                "settings changed in another process; reload or restart before using {}",
                path.display()
            ),
            Self::Indeterminate { path, detail } => write!(
                formatter,
                "settings state at {} could not be verified; reload or restart before continuing: {detail}",
                path.display()
            ),
            Self::UnpersistedSnapshot { path } => write!(
                formatter,
                "the in-memory settings do not match {}; save valid settings before continuing",
                path.display()
            ),
        }
    }
}

impl std::error::Error for SettingsVerificationError {}

pub(super) fn settings_conflict(path: &Path) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "settings changed in another process; restart or reload before updating {}",
        path.display()
    ))
}

pub(super) fn settings_unavailable(path: &Path, state: SettingsAccessState) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "settings updates are disabled after {state:?} state at {}; explicitly reload or restart",
        path.display()
    ))
}

impl SettingsStore {
    pub(super) fn verification_error(&self, source: NetdiagError) -> SettingsVerificationError {
        match self.state.lock().as_deref() {
            Ok(SettingsAccessState::Conflict) => SettingsVerificationError::Conflict {
                path: self.path.clone(),
            },
            _ => SettingsVerificationError::Indeterminate {
                path: self.path.clone(),
                detail: source.to_string(),
            },
        }
    }
}
