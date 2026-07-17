use super::{AppSettings, SETTINGS_FILE, app_support_dir};
use anyhow::Result;
use netdiag_core::storage;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

mod errors;
mod revision;
mod snapshot;
mod transaction;

pub use errors::SettingsVerificationError;
use revision::SettingsAccessState;

#[derive(Debug, Clone)]
pub struct SettingsStore {
    path: PathBuf,
    state: Arc<Mutex<SettingsAccessState>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsLoadState {
    Loaded,
    Missing,
    Rejected,
}

#[derive(Debug)]
pub struct SettingsLoadOutcome {
    pub settings: AppSettings,
    pub warning: Option<String>,
    pub state: SettingsLoadState,
}

impl SettingsLoadOutcome {
    pub fn startup_authorized(&self) -> bool {
        self.state != SettingsLoadState::Rejected
    }
}

impl SettingsStore {
    pub fn default_path() -> PathBuf {
        app_support_dir().join(SETTINGS_FILE)
    }

    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Arc::new(Mutex::new(SettingsAccessState::Unloaded)),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load_for_startup(&self) -> SettingsLoadOutcome {
        match self.load_optional() {
            Ok(Some(settings)) => SettingsLoadOutcome {
                settings,
                warning: None,
                state: SettingsLoadState::Loaded,
            },
            Ok(None) => SettingsLoadOutcome {
                settings: AppSettings::default(),
                warning: None,
                state: SettingsLoadState::Missing,
            },
            Err(error) => SettingsLoadOutcome {
                settings: AppSettings::default(),
                warning: Some(format!("{error:#}")),
                state: SettingsLoadState::Rejected,
            },
        }
    }

    pub fn load(&self) -> Result<AppSettings> {
        Ok(self.load_optional()?.unwrap_or_default())
    }

    fn load_optional(&self) -> Result<Option<AppSettings>> {
        let result = storage::with_exclusive_file_lock(&self.path, || {
            let (raw, revision) = self.read_raw()?;
            let settings = self.decode_snapshot(raw.as_deref())?;
            *self.lock_state()? = SettingsAccessState::Ready(revision);
            Ok(settings)
        });
        if result.is_err() {
            self.mark_indeterminate_unless_conflict();
        }
        result.map_err(anyhow::Error::from)
    }
}
