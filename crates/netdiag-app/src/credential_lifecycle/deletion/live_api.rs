use super::super::cleanup_pending_bindings;
use super::plan::mark_bearer_deletion;
use crate::credential_lifecycle::legacy_live_api_binding;
use crate::secrets::SecretStore;
use crate::settings::{AppSettings, BearerCredentialOwner, SettingsStore};
use anyhow::{Context, Result};

pub fn delete_live_api_credentials(
    settings_store: &SettingsStore,
    settings: &mut AppSettings,
    secrets: &dyn SecretStore,
) -> Result<()> {
    settings_store.with_current_transaction(settings, |settings| {
        prepare_live_api_deletion(settings_store, settings)?;
        complete_live_api_deletion(settings_store, settings, secrets)
    })
}

pub fn resume_pending_live_api_credential_deletion(
    settings_store: &SettingsStore,
    settings: &mut AppSettings,
    secrets: &dyn SecretStore,
) -> Result<()> {
    if !settings.credential_cleanup.legacy_live_api_pending_deletion {
        return Ok(());
    }
    settings_store.with_current_transaction(settings, |settings| {
        prepare_live_api_deletion(settings_store, settings)?;
        complete_live_api_deletion(settings_store, settings, secrets)
    })
}

fn prepare_live_api_deletion(
    settings_store: &SettingsStore,
    settings: &mut AppSettings,
) -> Result<()> {
    let owner = BearerCredentialOwner::legacy_live_api();
    let current_scope = if settings.api.endpoint.trim().is_empty() {
        None
    } else {
        Some(legacy_live_api_binding(&settings.api.endpoint)?)
    };
    let mut prepared = settings.clone();
    mark_bearer_deletion(&mut prepared, &owner, current_scope)?;
    prepared.credential_cleanup.legacy_live_api_pending_deletion = true;
    settings_store
        .save(&mut prepared)
        .context("failed to persist the Live API credential deletion journal")?;
    *settings = prepared;
    Ok(())
}

fn complete_live_api_deletion(
    settings_store: &SettingsStore,
    settings: &mut AppSettings,
    secrets: &dyn SecretStore,
) -> Result<()> {
    secrets
        .delete_legacy_live_api_token()
        .context("failed to delete the journaled legacy Live API credential")?;
    let owner = BearerCredentialOwner::legacy_live_api();
    cleanup_pending_bindings(settings_store, settings, secrets, Some(&owner)).context(
        "the legacy Live API credential was deleted, but scoped credential cleanup is incomplete and must be retried",
    )?;
    let mut completed = settings.clone();
    completed
        .credential_cleanup
        .legacy_live_api_pending_deletion = false;
    settings_store
        .save(&mut completed)
        .context("credentials were deleted, but clearing the deletion journal failed")?;
    *settings = completed;
    Ok(())
}
