use super::SettingsBudget;
use crate::settings::{
    AppSettings, BearerCredentialOwner, BearerCredentialState, LEGACY_LIVE_API_SCOPE_ID,
};
use anyhow::{Result, bail};
use netdiag_core::authentication::canonical_http_origin;
use netdiag_core::connectors::validate_http_connector_bearer_endpoint;
use std::collections::BTreeSet;

const MAX_BEARER_CREDENTIAL_BINDINGS: usize = 130;

pub(super) fn validate(settings: &AppSettings, budget: &mut SettingsBudget) -> Result<()> {
    if settings.bearer_credentials.len() > MAX_BEARER_CREDENTIAL_BINDINGS {
        bail!(
            "settings contain more than {MAX_BEARER_CREDENTIAL_BINDINGS} bearer credential bindings"
        );
    }

    let mut identities = BTreeSet::new();
    let mut active_owners = BTreeSet::new();
    for binding in &settings.bearer_credentials {
        validate_owner(&binding.owner, budget)?;
        if !binding.connector_kind.supports_bearer_authentication() {
            bail!(
                "bearer credential binding cannot use connector kind {}",
                binding.connector_kind.stable_name()
            );
        }
        budget.validate_string(
            "bearer credential canonical origin",
            &binding.canonical_origin,
            false,
        )?;
        let canonical =
            canonical_http_origin(&binding.canonical_origin).map_err(anyhow::Error::from)?;
        if canonical.as_str() != binding.canonical_origin {
            bail!("bearer credential binding origin is not canonical");
        }
        validate_http_connector_bearer_endpoint(&binding.canonical_origin)
            .map_err(anyhow::Error::from)?;

        let identity = (
            binding.owner.clone(),
            binding.connector_kind,
            binding.canonical_origin.as_str(),
        );
        if !identities.insert(identity) {
            bail!("settings contain a duplicate bearer credential binding");
        }
        if binding.state == BearerCredentialState::Active
            && !active_owners.insert(binding.owner.clone())
        {
            bail!("settings contain multiple active bearer credentials for one owner");
        }
    }
    Ok(())
}

fn validate_owner(owner: &BearerCredentialOwner, budget: &mut SettingsBudget) -> Result<()> {
    if let BearerCredentialOwner::Profile { profile_id } = owner {
        budget.validate_string("bearer credential profile id", profile_id, false)?;
        if profile_id == LEGACY_LIVE_API_SCOPE_ID {
            bail!("source profile id is reserved for the legacy Live API credential scope");
        }
    }
    Ok(())
}
