use super::cleanup_pending_bindings;
use crate::secrets::SecretStore;
use crate::settings::{AppSettings, BearerCredentialState, ConnectorAuthentication, SettingsStore};
use anyhow::{Context, Result};
use std::collections::HashSet;

pub fn reconcile_inactive_profile_credentials(
    settings_store: &SettingsStore,
    settings: &mut AppSettings,
    secrets: &dyn SecretStore,
) -> Result<()> {
    if !requires_reconciliation(settings) {
        return Ok(());
    }
    settings_store.with_current_transaction(settings, |settings| {
        reconcile_locked(settings_store, settings, secrets)
    })
}

fn reconcile_locked(
    settings_store: &SettingsStore,
    settings: &mut AppSettings,
    secrets: &dyn SecretStore,
) -> Result<()> {
    let active_profiles = settings
        .data_connectors
        .profiles
        .iter()
        .filter(|profile| {
            profile.authentication == ConnectorAuthentication::BearerToken
                && profile.kind.supports_bearer_authentication()
        })
        .map(|profile| profile.id.clone())
        .collect::<HashSet<_>>();
    let mut updated = settings.clone();
    for binding in &mut updated.bearer_credentials {
        if let Some(profile_id) = binding.owner.profile_id()
            && !active_profiles.contains(profile_id)
        {
            binding.state = BearerCredentialState::PendingDeletion;
        }
    }
    if updated != *settings {
        settings_store
            .save(&mut updated)
            .context("failed to register inactive bearer credentials for deletion")?;
        *settings = updated;
    }
    cleanup_pending_bindings(settings_store, settings, secrets, None)
}

fn requires_reconciliation(settings: &AppSettings) -> bool {
    settings.bearer_credentials.iter().any(|binding| {
        binding.state != BearerCredentialState::Active
            || binding.owner.profile_id().is_some_and(|profile_id| {
                !settings.data_connectors.profiles.iter().any(|profile| {
                    profile.id == profile_id
                        && profile.authentication == ConnectorAuthentication::BearerToken
                        && profile.kind.supports_bearer_authentication()
                })
            })
    })
}
