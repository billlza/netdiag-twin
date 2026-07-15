use super::super::same_scope;
use crate::settings::{
    AppSettings, BearerCredentialBinding, BearerCredentialOwner, BearerCredentialState,
    SettingsStore,
};
use anyhow::{Context, Result, bail};

pub(super) fn mark_bearer_deletion(
    updated: &mut AppSettings,
    owner: &BearerCredentialOwner,
    current_scope: Option<BearerCredentialBinding>,
) -> Result<()> {
    for binding in &mut updated.bearer_credentials {
        if &binding.owner == owner {
            binding.state = BearerCredentialState::PendingDeletion;
        }
    }
    if let Some(mut current_scope) = current_scope {
        if current_scope.owner != *owner {
            bail!("bearer credential deletion owner does not match its current scope");
        }
        current_scope.state = BearerCredentialState::PendingDeletion;
        if !updated
            .bearer_credentials
            .iter()
            .any(|binding| same_scope(binding, &current_scope))
        {
            updated.bearer_credentials.push(current_scope);
        }
    }
    Ok(())
}

pub(super) fn prepare_bearer_deletion(
    settings_store: &SettingsStore,
    settings: &mut AppSettings,
    owner: &BearerCredentialOwner,
    current_scope: Option<BearerCredentialBinding>,
) -> Result<()> {
    let mut updated = settings.clone();
    mark_bearer_deletion(&mut updated, owner, current_scope)?;
    if updated != *settings {
        settings_store
            .save(&mut updated)
            .context("failed to register bearer credentials for deletion")?;
        *settings = updated;
    }
    Ok(())
}
