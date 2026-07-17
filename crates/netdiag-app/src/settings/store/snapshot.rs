use super::SettingsStore;
use super::revision::{SettingsRevision, revision};
use crate::settings::{AppSettings, MAX_SETTINGS_FILE_BYTES, validate_settings};
use netdiag_core::{NetdiagError, storage};

impl SettingsStore {
    pub(super) fn read_raw(&self) -> netdiag_core::Result<(Option<Vec<u8>>, SettingsRevision)> {
        let raw =
            storage::read_stable_regular_file_bounded(&self.path, MAX_SETTINGS_FILE_BYTES as u64)?;
        let revision = raw.as_deref().map_or(SettingsRevision::Missing, revision);
        Ok((raw, revision))
    }

    pub(super) fn decode_snapshot(
        &self,
        raw: Option<&[u8]>,
    ) -> netdiag_core::Result<Option<AppSettings>> {
        let Some(raw) = raw else {
            return Ok(None);
        };
        let settings = netdiag_core::strict_json::from_slice(raw).map_err(|error| {
            NetdiagError::InvalidTrace(format!(
                "settings file at {} {}",
                self.path.display(),
                netdiag_core::strict_json::error_summary(&error)
            ))
        })?;
        validate_settings(&settings).map_err(|error| {
            NetdiagError::InvalidTrace(format!(
                "settings file at {} is invalid: {error:#}",
                self.path.display()
            ))
        })?;
        Ok(Some(settings))
    }
}
