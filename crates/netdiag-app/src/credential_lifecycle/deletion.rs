use super::cleanup_pending_bindings;
use crate::secrets::SecretStore;
use crate::settings::{AppSettings, BearerCredentialBinding, BearerCredentialOwner, SettingsStore};
use anyhow::Result;

mod live_api;
mod plan;
pub use live_api::{delete_live_api_credentials, resume_pending_live_api_credential_deletion};

pub fn delete_bearer_credentials(
    settings_store: &SettingsStore,
    settings: &mut AppSettings,
    secrets: &dyn SecretStore,
    owner: &BearerCredentialOwner,
    current_scope: Option<BearerCredentialBinding>,
) -> Result<()> {
    settings_store.with_current_transaction(settings, |settings| {
        delete_bearer_credentials_locked(settings_store, settings, secrets, owner, current_scope)
    })
}

pub(super) fn delete_bearer_credentials_locked(
    settings_store: &SettingsStore,
    settings: &mut AppSettings,
    secrets: &dyn SecretStore,
    owner: &BearerCredentialOwner,
    current_scope: Option<BearerCredentialBinding>,
) -> Result<()> {
    plan::prepare_bearer_deletion(settings_store, settings, owner, current_scope)?;
    cleanup_pending_bindings(settings_store, settings, secrets, Some(owner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_lifecycle::{
        legacy_live_api_binding, profile_binding, scope_for_binding, store_bearer_credential,
    };
    use crate::secrets::{BearerSecretScope, MemorySecretStore};
    use crate::settings::{
        ApiSettings, BearerCredentialState, ConnectorAuthentication, ConnectorKind,
    };
    use anyhow::bail;
    use netdiag_core::authentication::ValidatedBearerToken;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn settings(endpoint: &str) -> AppSettings {
        AppSettings {
            api: ApiSettings {
                endpoint: endpoint.to_string(),
                ..ApiSettings::default()
            },
            ..AppSettings::default()
        }
    }

    #[test]
    fn removes_legacy_entry_without_a_valid_endpoint() {
        let root = tempfile::tempdir().expect("temporary root");
        let store = SettingsStore::new(root.path().join("settings.json"));
        let secrets =
            MemorySecretStore::with_legacy_live_api_token("legacy-secret").expect("legacy fixture");
        let mut settings = AppSettings::default();

        delete_live_api_credentials(&store, &mut settings, &secrets)
            .expect("legacy deletion must not require a destination endpoint");
        assert!(
            secrets
                .get_legacy_live_api_token()
                .expect("read legacy entry")
                .is_none()
        );
        assert!(settings.bearer_credentials.is_empty());
    }

    #[test]
    fn legacy_failure_persists_deletion_intent_and_resumes_after_restart() {
        let root = tempfile::tempdir().expect("temporary root");
        let store = SettingsStore::new(root.path().join("settings.json"));
        let secrets = FailingDeleteStore::with_legacy();
        let mut settings = settings("https://delete.example.test/traces");
        let binding = legacy_live_api_binding(&settings.api.endpoint).expect("binding");
        let scope = scope_for_binding(&binding).expect("scope");
        store
            .save(&mut settings)
            .expect("persist endpoint settings");
        store_bearer_credential(
            &store,
            &mut settings,
            &secrets,
            binding.clone(),
            "scoped-secret",
        )
        .expect("scoped fixture");
        *secrets.fail_legacy.lock().expect("failure lock") = true;

        let error = delete_live_api_credentials(&store, &mut settings, &secrets)
            .expect_err("legacy deletion failure must be visible");
        assert!(
            error
                .to_string()
                .contains("failed to delete the journaled legacy Live API credential"),
            "{error:#}"
        );
        assert_eq!(
            settings.bearer_credentials[0].state,
            BearerCredentialState::PendingDeletion
        );
        assert!(settings.credential_cleanup.legacy_live_api_pending_deletion);
        assert!(
            secrets
                .get_bearer_token(&scope)
                .expect("read scoped")
                .is_some()
        );

        let restart_store = SettingsStore::new(store.path().to_path_buf());
        let mut recovered = restart_store.load().expect("reload journaled settings");
        assert_eq!(
            recovered.bearer_credentials[0].state,
            BearerCredentialState::PendingDeletion
        );
        assert!(
            recovered
                .credential_cleanup
                .legacy_live_api_pending_deletion
        );
        *secrets.fail_legacy.lock().expect("failure lock") = false;
        resume_pending_live_api_credential_deletion(&restart_store, &mut recovered, &secrets)
            .expect("resume journaled deletion");
        assert!(recovered.bearer_credentials.is_empty());
        assert!(
            !recovered
                .credential_cleanup
                .legacy_live_api_pending_deletion
        );
        assert!(
            secrets
                .get_bearer_token(&scope)
                .expect("read deleted scoped")
                .is_none()
        );
        assert!(
            secrets
                .get_legacy_live_api_token()
                .expect("read deleted legacy")
                .is_none()
        );
    }

    #[test]
    fn scoped_failure_is_persisted_and_retryable() {
        let root = tempfile::tempdir().expect("temporary root");
        let store = SettingsStore::new(root.path().join("settings.json"));
        let secrets = FailingDeleteStore::with_legacy();
        let mut settings = settings("https://retry.example.test/traces");
        let binding = legacy_live_api_binding(&settings.api.endpoint).expect("binding");
        let scope = scope_for_binding(&binding).expect("scope");
        store
            .save(&mut settings)
            .expect("persist endpoint settings");
        store_bearer_credential(&store, &mut settings, &secrets, binding, "scoped-secret")
            .expect("scoped fixture");
        *secrets.fail_scope.lock().expect("failure lock") = Some(scope.clone());

        let error = delete_live_api_credentials(&store, &mut settings, &secrets)
            .expect_err("scoped deletion failure must be visible");
        assert!(
            error.to_string().contains("cleanup is incomplete"),
            "{error:#}"
        );
        assert!(
            secrets
                .get_legacy_live_api_token()
                .expect("read legacy")
                .is_none()
        );
        assert_eq!(
            settings.bearer_credentials[0].state,
            BearerCredentialState::PendingDeletion
        );
        assert!(settings.credential_cleanup.legacy_live_api_pending_deletion);

        *secrets.fail_scope.lock().expect("failure lock") = None;
        resume_pending_live_api_credential_deletion(&store, &mut settings, &secrets)
            .expect("retry deletion");
        assert!(settings.bearer_credentials.is_empty());
        assert!(!settings.credential_cleanup.legacy_live_api_pending_deletion);
        assert!(
            secrets
                .get_bearer_token(&scope)
                .expect("read scoped")
                .is_none()
        );
    }

    #[test]
    fn resume_re_marks_an_active_legacy_binding_before_deleting_it() {
        let root = tempfile::tempdir().expect("temporary root");
        let store = SettingsStore::new(root.path().join("settings.json"));
        let secrets = FailingDeleteStore::with_legacy();
        let mut settings = settings("https://recover.example.test/traces");
        let binding = legacy_live_api_binding(&settings.api.endpoint).expect("binding");
        let scope = scope_for_binding(&binding).expect("scope");
        store
            .save(&mut settings)
            .expect("persist endpoint settings");
        store_bearer_credential(&store, &mut settings, &secrets, binding, "scoped-secret")
            .expect("scoped fixture");
        settings.credential_cleanup.legacy_live_api_pending_deletion = true;
        store
            .save(&mut settings)
            .expect("persist interrupted deletion journal");

        resume_pending_live_api_credential_deletion(&store, &mut settings, &secrets)
            .expect("resume must re-mark active binding");

        assert!(settings.bearer_credentials.is_empty());
        assert!(!settings.credential_cleanup.legacy_live_api_pending_deletion);
        assert!(
            secrets
                .get_bearer_token(&scope)
                .expect("read deleted scoped")
                .is_none()
        );
        assert!(
            secrets
                .get_legacy_live_api_token()
                .expect("read deleted legacy")
                .is_none()
        );
    }

    #[test]
    fn pending_live_api_deletion_blocks_only_legacy_replacement_until_recovery() {
        let root = tempfile::tempdir().expect("temporary root");
        let settings_path = root.path().join("settings.json");
        let store = SettingsStore::new(settings_path.clone());
        let secrets = FailingDeleteStore::default();
        let mut settings = settings("https://legacy.example.test/traces");
        settings.credential_cleanup.legacy_live_api_pending_deletion = true;
        let profile = settings
            .data_connectors
            .profiles
            .iter_mut()
            .find(|profile| profile.kind == ConnectorKind::HttpJson)
            .expect("HTTP profile");
        profile.authentication = ConnectorAuthentication::BearerToken;
        profile.http_json.endpoint = "https://profile.example.test/traces".to_string();
        let profile_binding = profile_binding(profile)
            .expect("profile binding")
            .expect("bearer profile");
        store.save(&mut settings).expect("persist deletion journal");

        let legacy_binding =
            legacy_live_api_binding(&settings.api.endpoint).expect("legacy binding");
        let settings_before = settings.clone();
        let disk_before = std::fs::read(&settings_path).expect("settings snapshot");
        secrets.mutation_calls.store(0, Ordering::Relaxed);

        let error = store_bearer_credential(
            &store,
            &mut settings,
            &secrets,
            legacy_binding.clone(),
            "replacement-token",
        )
        .expect_err("pending deletion must reject a legacy replacement");
        assert!(
            error.to_string().contains("deletion must complete"),
            "{error:#}"
        );
        assert_eq!(settings, settings_before);
        assert_eq!(
            std::fs::read(&settings_path).expect("unchanged settings"),
            disk_before
        );
        assert_eq!(secrets.mutation_calls.load(Ordering::Relaxed), 0);

        store_bearer_credential(
            &store,
            &mut settings,
            &secrets,
            profile_binding,
            "profile-token",
        )
        .expect("unrelated profile credential remains writable");
        resume_pending_live_api_credential_deletion(&store, &mut settings, &secrets)
            .expect("recover pending legacy deletion");
        assert!(!settings.credential_cleanup.legacy_live_api_pending_deletion);

        store_bearer_credential(
            &store,
            &mut settings,
            &secrets,
            legacy_binding,
            "replacement-token",
        )
        .expect("legacy credential is writable after recovery");
    }

    #[derive(Default)]
    struct FailingDeleteStore {
        inner: MemorySecretStore,
        fail_scope: Mutex<Option<BearerSecretScope>>,
        fail_legacy: Mutex<bool>,
        mutation_calls: AtomicUsize,
    }

    impl FailingDeleteStore {
        fn with_legacy() -> Self {
            Self {
                inner: MemorySecretStore::with_legacy_live_api_token("legacy-secret")
                    .expect("legacy fixture"),
                ..Self::default()
            }
        }
    }

    impl SecretStore for FailingDeleteStore {
        fn get_bearer_token(
            &self,
            scope: &BearerSecretScope,
        ) -> Result<Option<ValidatedBearerToken>> {
            self.inner.get_bearer_token(scope)
        }

        fn set_bearer_token(&self, scope: &BearerSecretScope, token: &str) -> Result<()> {
            self.mutation_calls.fetch_add(1, Ordering::Relaxed);
            self.inner.set_bearer_token(scope, token)
        }

        fn delete_bearer_token(&self, scope: &BearerSecretScope) -> Result<()> {
            self.mutation_calls.fetch_add(1, Ordering::Relaxed);
            if self
                .fail_scope
                .lock()
                .map_err(|_| anyhow::anyhow!("failure lock poisoned"))?
                .as_ref()
                == Some(scope)
            {
                bail!("injected scoped credential deletion failure");
            }
            self.inner.delete_bearer_token(scope)
        }

        fn get_legacy_live_api_token(&self) -> Result<Option<ValidatedBearerToken>> {
            self.inner.get_legacy_live_api_token()
        }

        fn delete_legacy_live_api_token(&self) -> Result<()> {
            self.mutation_calls.fetch_add(1, Ordering::Relaxed);
            if *self
                .fail_legacy
                .lock()
                .map_err(|_| anyhow::anyhow!("failure lock poisoned"))?
            {
                bail!("injected legacy credential deletion failure");
            }
            self.inner.delete_legacy_live_api_token()
        }
    }
}
