use super::SettingsStore;
use super::errors::{SettingsVerificationError, settings_conflict, settings_unavailable};
use super::revision::{SettingsAccessState, SettingsRevision};
use crate::settings::{AppSettings, validate_settings};
use anyhow::{Context, Result, bail};
use netdiag_core::{NetdiagError, storage};

impl SettingsStore {
    pub fn save(&self, settings: &mut AppSettings) -> Result<()> {
        validate_settings(settings)?;
        let result = storage::with_exclusive_file_lock(&self.path, || self.save_locked(settings));
        if result.is_err() {
            self.mark_indeterminate_unless_conflict();
        }
        result
            .map_err(anyhow::Error::from)
            .with_context(|| format!("failed to replace settings file: {}", self.path.display()))
    }

    pub fn verify_current(
        &self,
        settings: &AppSettings,
    ) -> std::result::Result<(), SettingsVerificationError> {
        let result = storage::with_exclusive_file_lock(&self.path, || self.ensure_current());
        let disk = match result {
            Ok(disk) => disk,
            Err(source) => {
                self.mark_indeterminate_unless_conflict();
                return Err(self.verification_error(source));
            }
        };
        if Self::snapshot_matches(disk.as_ref(), settings) {
            Ok(())
        } else {
            Err(SettingsVerificationError::UnpersistedSnapshot {
                path: self.path.clone(),
            })
        }
    }

    pub(crate) fn with_current_transaction<T>(
        &self,
        settings: &mut AppSettings,
        action: impl FnOnce(&mut AppSettings) -> Result<T>,
    ) -> Result<T> {
        validate_settings(settings)?;
        let mut action = Some(action);
        let mut outcome = None;
        let mut unpersisted_snapshot = false;
        let coordination = storage::with_exclusive_file_lock(&self.path, || {
            let disk = self.ensure_current()?;
            if !Self::snapshot_matches(disk.as_ref(), settings) {
                unpersisted_snapshot = true;
                return Err(NetdiagError::InvalidTrace(
                    "the in-memory settings snapshot is not persisted".to_string(),
                ));
            }
            outcome = Some(action.take().expect("settings transaction action exists")(
                settings,
            ));
            let disk = self.ensure_current()?;
            if !Self::snapshot_matches(disk.as_ref(), settings) {
                unpersisted_snapshot = true;
                return Err(NetdiagError::InvalidTrace(
                    "the settings transaction left an unpersisted in-memory snapshot".to_string(),
                ));
            }
            Ok(())
        });
        if coordination.is_err() && !unpersisted_snapshot {
            self.mark_indeterminate_unless_conflict();
        }
        match (coordination, outcome) {
            (Ok(()), Some(outcome)) => outcome,
            (Err(coordination), Some(Err(action))) => bail!(
                "settings transaction failed ({action:#}); settings coordination also failed ({coordination})"
            ),
            (Err(coordination), Some(Ok(_))) | (Err(coordination), None) => {
                Err(anyhow::Error::from(coordination))
            }
            (Ok(()), None) => bail!("settings transaction action was not executed"),
        }
    }

    fn save_locked(&self, settings: &mut AppSettings) -> netdiag_core::Result<()> {
        let current = self.ensure_current()?;
        let current_generation = current
            .as_ref()
            .map_or(0, |settings| settings.settings_generation);
        if settings.settings_generation != current_generation {
            if let Ok(mut state) = self.state.lock() {
                *state = SettingsAccessState::Conflict;
            }
            return Err(settings_conflict(&self.path));
        }
        let mut persisted = settings.clone();
        persisted.settings_generation = current_generation.checked_add(1).ok_or_else(|| {
            NetdiagError::InvalidTrace("settings generation reached u64::MAX".to_string())
        })?;
        validate_settings(&persisted).map_err(|error| {
            NetdiagError::InvalidTrace(format!(
                "settings became invalid after advancing its generation: {error:#}"
            ))
        })?;
        storage::save_json_atomic(&self.path, &persisted).map(drop)?;
        #[cfg(test)]
        self.maybe_fail_after_publication()?;
        let (raw, revision) = self.read_raw()?;
        let saved = self.decode_snapshot(raw.as_deref())?;
        if saved.as_ref() != Some(&persisted) {
            return Err(NetdiagError::InvalidTrace(
                "settings changed during atomic publication verification".to_string(),
            ));
        }
        *self.lock_state()? = SettingsAccessState::Ready(revision);
        *settings = persisted;
        Ok(())
    }

    fn ensure_current(&self) -> netdiag_core::Result<Option<AppSettings>> {
        let (raw, current) = self.read_raw()?;
        let mut state = self.lock_state()?;
        match *state {
            SettingsAccessState::Ready(expected) if expected == current => {}
            SettingsAccessState::Unloaded if current == SettingsRevision::Missing => {
                *state = SettingsAccessState::Ready(SettingsRevision::Missing);
            }
            SettingsAccessState::Ready(_) => {
                *state = SettingsAccessState::Conflict;
                return Err(settings_conflict(&self.path));
            }
            SettingsAccessState::Unloaded => {
                *state = SettingsAccessState::Conflict;
                return Err(NetdiagError::InvalidTrace(format!(
                    "settings baseline was not loaded before updating {}",
                    self.path.display()
                )));
            }
            blocked @ (SettingsAccessState::Conflict | SettingsAccessState::Indeterminate) => {
                return Err(settings_unavailable(&self.path, blocked));
            }
        }
        drop(state);
        self.decode_snapshot(raw.as_deref())
    }

    fn snapshot_matches(disk: Option<&AppSettings>, settings: &AppSettings) -> bool {
        disk == Some(settings) || (disk.is_none() && settings == &AppSettings::default())
    }

    pub(super) fn lock_state(
        &self,
    ) -> netdiag_core::Result<std::sync::MutexGuard<'_, SettingsAccessState>> {
        self.state.lock().map_err(|_| {
            NetdiagError::InvalidTrace("settings revision state is poisoned".to_string())
        })
    }

    pub(super) fn mark_indeterminate_unless_conflict(&self) {
        if let Ok(mut state) = self.state.lock()
            && *state != SettingsAccessState::Conflict
        {
            *state = SettingsAccessState::Indeterminate;
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_after_publications_for_test(&self, count: usize) {
        TEST_FAILURE_AFTER_PUBLICATIONS.with(|remaining| remaining.set(count));
    }

    #[cfg(test)]
    fn maybe_fail_after_publication(&self) -> netdiag_core::Result<()> {
        TEST_FAILURE_AFTER_PUBLICATIONS.with(|remaining| match remaining.get() {
            0 => Ok(()),
            1 => {
                remaining.set(0);
                Err(NetdiagError::AtomicPublish {
                    path: self.path.clone(),
                    phase: netdiag_core::error::AtomicPublishPhase::Published,
                    source: Box::new(NetdiagError::InvalidTrace(
                        "injected post-publication settings failure".to_string(),
                    )),
                })
            }
            count => {
                remaining.set(count - 1);
                Ok(())
            }
        })
    }
}

#[cfg(test)]
thread_local! {
    static TEST_FAILURE_AFTER_PUBLICATIONS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}
