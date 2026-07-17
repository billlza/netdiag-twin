use crate::secrets::{BearerSecretScope, SecretStore};
use crate::settings::{
    AppSettings, BearerCredentialBinding, BearerCredentialOwner, BearerCredentialState,
    ConnectorAuthentication, ConnectorKind, SettingsStore, SourceProfile,
};
use anyhow::{Context, Result, bail};
use netdiag_core::authentication::{BearerSourceKind, canonical_http_origin};
use netdiag_core::connectors::validate_http_connector_bearer_endpoint;

mod deletion;
mod reconciliation;
pub use deletion::{
    delete_bearer_credentials, delete_live_api_credentials,
    resume_pending_live_api_credential_deletion,
};
pub use reconciliation::reconcile_inactive_profile_credentials;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyCredentialMigration {
    NotPresent,
    Migrated,
}

pub fn legacy_live_api_binding(endpoint: &str) -> Result<BearerCredentialBinding> {
    binding(
        BearerCredentialOwner::legacy_live_api(),
        ConnectorKind::HttpJson,
        endpoint,
        BearerCredentialState::Active,
    )
}

pub fn profile_binding(profile: &SourceProfile) -> Result<Option<BearerCredentialBinding>> {
    if profile.authentication == ConnectorAuthentication::None {
        return Ok(None);
    }
    let endpoint = profile
        .http_endpoint()
        .ok_or_else(|| anyhow::anyhow!("authenticated source profile has no HTTP endpoint"))?;
    binding(
        BearerCredentialOwner::profile(profile.id.clone()),
        profile.kind,
        endpoint,
        BearerCredentialState::Active,
    )
    .map(Some)
}

pub fn store_bearer_credential(
    settings_store: &SettingsStore,
    settings: &mut AppSettings,
    secrets: &dyn SecretStore,
    desired: BearerCredentialBinding,
    token: &str,
) -> Result<()> {
    settings_store.with_current_transaction(settings, |settings| {
        store_bearer_credential_locked(settings_store, settings, secrets, desired, token)
    })
}

fn store_bearer_credential_locked(
    settings_store: &SettingsStore,
    settings: &mut AppSettings,
    secrets: &dyn SecretStore,
    mut desired: BearerCredentialBinding,
    token: &str,
) -> Result<()> {
    if settings.credential_cleanup.legacy_live_api_pending_deletion
        && desired.owner == BearerCredentialOwner::legacy_live_api()
    {
        bail!("pending Live API credential deletion must complete before storing a replacement");
    }
    desired.state = BearerCredentialState::Active;
    let desired_scope = scope_for_binding(&desired)?;
    let exact_active = settings.bearer_credentials.iter().any(|binding| {
        binding.state == BearerCredentialState::Active && same_scope(binding, &desired)
    });
    if exact_active {
        settings_store
            .save(settings)
            .context("failed to persist the credential rotation generation fence")?;
        secrets
            .set_bearer_token(&desired_scope, token)
            .context("failed to rotate the scoped bearer credential")?;
        return cleanup_pending_bindings(settings_store, settings, secrets, Some(&desired.owner));
    }

    let previous_target = secrets
        .get_bearer_token(&desired_scope)
        .context("failed to read the destination bearer credential before replacement")?;
    let destination_is_registered = settings
        .bearer_credentials
        .iter()
        .any(|binding| same_scope(binding, &desired));
    if previous_target.is_some() && !destination_is_registered {
        let has_other_active = settings.bearer_credentials.iter().any(|binding| {
            binding.owner == desired.owner && binding.state == BearerCredentialState::Active
        });
        if has_other_active {
            bail!(
                "the destination scope already contains an unregistered credential while another scope is active; delete the destination credential before rotating"
            );
        }
        let mut adopted = settings.clone();
        adopted.bearer_credentials.push(desired.clone());
        settings_store
            .save(&mut adopted)
            .context("failed to register the existing destination bearer credential")?;
        *settings = adopted;
        secrets
            .set_bearer_token(&desired_scope, token)
            .context("failed to rotate the newly registered bearer credential")?;
        return cleanup_pending_bindings(settings_store, settings, secrets, Some(&desired.owner));
    }

    let mut activation = desired.clone();
    activation.state = BearerCredentialState::PendingActivation;
    let mut prepared = settings.clone();
    prepared
        .bearer_credentials
        .retain(|binding| !same_scope(binding, &desired));
    prepared.bearer_credentials.push(activation);
    settings_store
        .save(&mut prepared)
        .context("failed to prepare the destination bearer credential registry")?;
    *settings = prepared;

    if let Err(write_error) = secrets.set_bearer_token(&desired_scope, token) {
        let cleanup =
            cleanup_pending_bindings(settings_store, settings, secrets, Some(&desired.owner));
        return match cleanup {
            Ok(()) => Err(write_error).context(
                "failed to write the new scoped bearer credential; its activation marker was rolled back",
            ),
            Err(cleanup_error) => bail!(
                "failed to write the new scoped bearer credential ({write_error:#}); activation rollback also failed ({cleanup_error:#})"
            ),
        };
    }

    let mut committed = settings.clone();
    for binding in &mut committed.bearer_credentials {
        if same_scope(binding, &desired) {
            binding.state = BearerCredentialState::Active;
        } else if binding.owner == desired.owner && binding.state == BearerCredentialState::Active {
            binding.state = BearerCredentialState::PendingDeletion;
        }
    }
    settings_store.save(&mut committed).with_context(|| {
        "failed to confirm activation of the new bearer credential; its prepared state and secret were retained for deterministic startup reconciliation"
    })?;
    *settings = committed;
    cleanup_pending_bindings(settings_store, settings, secrets, Some(&desired.owner))
}

pub fn migrate_legacy_live_api_credential(
    settings_store: &SettingsStore,
    settings: &mut AppSettings,
    secrets: &dyn SecretStore,
) -> Result<LegacyCredentialMigration> {
    settings_store.with_current_transaction(settings, |settings| {
        migrate_legacy_live_api_credential_locked(settings_store, settings, secrets)
    })
}

fn migrate_legacy_live_api_credential_locked(
    settings_store: &SettingsStore,
    settings: &mut AppSettings,
    secrets: &dyn SecretStore,
) -> Result<LegacyCredentialMigration> {
    if settings.credential_cleanup.legacy_live_api_pending_deletion {
        bail!("pending Live API credential deletion must complete before legacy migration");
    }
    let Some(legacy) = secrets
        .get_legacy_live_api_token()
        .context("failed to inspect the legacy Live API credential")?
    else {
        return Ok(LegacyCredentialMigration::NotPresent);
    };
    let desired = legacy_live_api_binding(&settings.api.endpoint).context(
        "legacy Live API credential remains in its old Keychain entry because no safe destination scope is configured",
    )?;
    let desired_scope = scope_for_binding(&desired)?;
    let existing = secrets
        .get_bearer_token(&desired_scope)
        .context("failed to inspect the scoped Live API credential during migration")?;
    let source = existing.as_ref().unwrap_or(&legacy);
    store_bearer_credential_locked(settings_store, settings, secrets, desired, source.as_str())?;
    secrets.delete_legacy_live_api_token().context(
        "scoped Live API credential is active, but deleting the legacy Keychain entry failed",
    )?;
    Ok(LegacyCredentialMigration::Migrated)
}

pub fn has_stale_active_binding(settings: &AppSettings, desired: &BearerCredentialBinding) -> bool {
    settings.bearer_credentials.iter().any(|binding| {
        binding.owner == desired.owner
            && binding.state == BearerCredentialState::Active
            && !same_scope(binding, desired)
    })
}

pub fn has_active_binding(settings: &AppSettings, desired: &BearerCredentialBinding) -> bool {
    settings.bearer_credentials.iter().any(|binding| {
        binding.state == BearerCredentialState::Active && same_scope(binding, desired)
    })
}

fn binding(
    owner: BearerCredentialOwner,
    connector_kind: ConnectorKind,
    endpoint: &str,
    state: BearerCredentialState,
) -> Result<BearerCredentialBinding> {
    if !connector_kind.supports_bearer_authentication() {
        bail!(
            "connector kind {} does not support bearer credentials",
            connector_kind.stable_name()
        );
    }
    validate_http_connector_bearer_endpoint(endpoint).map_err(anyhow::Error::from)?;
    let origin = canonical_http_origin(endpoint).map_err(anyhow::Error::from)?;
    Ok(BearerCredentialBinding {
        owner,
        connector_kind,
        canonical_origin: origin.as_str().to_string(),
        state,
    })
}

fn scope_for_binding(binding: &BearerCredentialBinding) -> Result<BearerSecretScope> {
    let origin = canonical_http_origin(&binding.canonical_origin).map_err(anyhow::Error::from)?;
    if origin.as_str() != binding.canonical_origin {
        bail!("bearer credential binding origin is not canonical");
    }
    BearerSecretScope::new(
        binding.owner.scope_id(),
        bearer_source_kind(binding.connector_kind)?,
        &origin,
    )
}

fn bearer_source_kind(kind: ConnectorKind) -> Result<BearerSourceKind> {
    match kind {
        ConnectorKind::HttpJson => Ok(BearerSourceKind::HttpJson),
        ConnectorKind::PrometheusQueryRange => Ok(BearerSourceKind::PrometheusQuery),
        ConnectorKind::PrometheusExposition => Ok(BearerSourceKind::PrometheusMetrics),
        unsupported => bail!(
            "connector kind {} does not support bearer credentials",
            unsupported.stable_name()
        ),
    }
}

fn same_scope(left: &BearerCredentialBinding, right: &BearerCredentialBinding) -> bool {
    left.owner == right.owner
        && left.connector_kind == right.connector_kind
        && left.canonical_origin == right.canonical_origin
}

fn cleanup_pending_bindings(
    settings_store: &SettingsStore,
    settings: &mut AppSettings,
    secrets: &dyn SecretStore,
    owner: Option<&BearerCredentialOwner>,
) -> Result<()> {
    let pending = settings
        .bearer_credentials
        .iter()
        .filter(|binding| {
            binding.state != BearerCredentialState::Active
                && owner.is_none_or(|owner| &binding.owner == owner)
        })
        .cloned()
        .collect::<Vec<_>>();
    if pending.is_empty() {
        return Ok(());
    }

    let mut deleted = Vec::new();
    let mut failures = Vec::new();
    for binding in pending {
        let result =
            scope_for_binding(&binding).and_then(|scope| secrets.delete_bearer_token(&scope));
        match result {
            Ok(()) => deleted.push(binding),
            Err(error) => failures.push(format!(
                "{}",
                error.context("scoped credential deletion failed")
            )),
        }
    }

    if !deleted.is_empty() {
        let mut updated = settings.clone();
        updated
            .bearer_credentials
            .retain(|binding| !deleted.iter().any(|deleted| same_scope(binding, deleted)));
        settings_store.save(&mut updated).context(
            "credential secrets were deleted, but removing their registry entries failed",
        )?;
        *settings = updated;
    }
    if !failures.is_empty() {
        bail!(
            "bearer credential cleanup is incomplete: {}",
            failures.join("; ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::MemorySecretStore;
    use netdiag_core::authentication::ValidatedBearerToken;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn test_store(name: &str) -> (SettingsStore, std::path::PathBuf) {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "netdiag-credential-lifecycle-{}-{name}-{id}",
            std::process::id()
        ));
        (SettingsStore::new(root.join("settings.json")), root)
    }

    fn cleanup(root: &std::path::Path) {
        if root.exists() {
            std::fs::remove_dir_all(root).expect("remove credential lifecycle fixture");
        }
    }

    #[test]
    fn store_rotate_and_delete_keep_registry_and_secret_store_consistent() {
        let (store, root) = test_store("rotate");
        let secrets = MemorySecretStore::new();
        let mut settings = AppSettings::default();
        let owner = BearerCredentialOwner::profile("http_json_lab");
        let first = binding(
            owner.clone(),
            ConnectorKind::HttpJson,
            "https://one.example.test/traces",
            BearerCredentialState::Active,
        )
        .expect("first binding");
        let first_scope = scope_for_binding(&first).expect("first scope");

        store_bearer_credential(&store, &mut settings, &secrets, first, "first-token")
            .expect("store first token");
        assert_eq!(settings.bearer_credentials.len(), 1);
        assert_eq!(
            secrets
                .get_bearer_token(&first_scope)
                .expect("read first")
                .expect("first token")
                .as_str(),
            "first-token"
        );

        let second = binding(
            owner.clone(),
            ConnectorKind::HttpJson,
            "https://two.example.test/traces",
            BearerCredentialState::Active,
        )
        .expect("second binding");
        let second_scope = scope_for_binding(&second).expect("second scope");
        store_bearer_credential(
            &store,
            &mut settings,
            &secrets,
            second.clone(),
            "second-token",
        )
        .expect("rotate token");
        assert!(
            secrets
                .get_bearer_token(&first_scope)
                .expect("read deleted first")
                .is_none()
        );
        assert_eq!(
            secrets
                .get_bearer_token(&second_scope)
                .expect("read second")
                .expect("second token")
                .as_str(),
            "second-token"
        );
        assert_eq!(settings.bearer_credentials, vec![second.clone()]);

        delete_bearer_credentials(&store, &mut settings, &secrets, &owner, Some(second))
            .expect("delete token");
        assert!(settings.bearer_credentials.is_empty());
        assert!(
            secrets
                .get_bearer_token(&second_scope)
                .expect("read deleted second")
                .is_none()
        );
        cleanup(&root);
    }

    #[test]
    fn coordination_failure_precedes_any_destination_secret_mutation() {
        let (_unused, root) = test_store("rollback");
        std::fs::create_dir_all(&root).expect("fixture root");
        let settings_path_is_directory = root.join("settings-target");
        std::fs::create_dir(&settings_path_is_directory).expect("directory target");
        let store = SettingsStore::new(settings_path_is_directory);
        let secrets = MemorySecretStore::new();
        let mut settings = AppSettings::default();
        let desired = binding(
            BearerCredentialOwner::profile("http_json_lab"),
            ConnectorKind::HttpJson,
            "https://rollback.example.test/traces",
            BearerCredentialState::Active,
        )
        .expect("binding");
        let scope = scope_for_binding(&desired).expect("scope");
        secrets
            .set_bearer_token(&scope, "previous-token")
            .expect("seed previous token");

        let error = store_bearer_credential(
            &store,
            &mut settings,
            &secrets,
            desired,
            "replacement-token",
        )
        .expect_err("registry save must fail");
        assert!(
            error.to_string().contains("regular, non-symlink"),
            "{error:#}"
        );
        assert!(settings.bearer_credentials.is_empty());
        assert_eq!(
            secrets
                .get_bearer_token(&scope)
                .expect("read restored token")
                .expect("restored token")
                .as_str(),
            "previous-token"
        );
        cleanup(&root);
    }

    #[test]
    fn startup_reconciliation_removes_an_interrupted_activation_and_its_secret() {
        let (store, root) = test_store("activation-recovery");
        let secrets = MemorySecretStore::new();
        let activation = binding(
            BearerCredentialOwner::profile("http_json_lab"),
            ConnectorKind::HttpJson,
            "https://interrupted.example.test/traces",
            BearerCredentialState::PendingActivation,
        )
        .expect("activation binding");
        let scope = scope_for_binding(&activation).expect("activation scope");
        secrets
            .set_bearer_token(&scope, "interrupted-token")
            .expect("seed interrupted destination");
        let mut settings = AppSettings {
            bearer_credentials: vec![activation],
            ..AppSettings::default()
        };
        store
            .save(&mut settings)
            .expect("persist activation marker");

        reconcile_inactive_profile_credentials(&store, &mut settings, &secrets)
            .expect("recover interrupted activation");
        assert!(settings.bearer_credentials.is_empty());
        assert!(
            secrets
                .get_bearer_token(&scope)
                .expect("read recovered scope")
                .is_none()
        );
        cleanup(&root);
    }

    #[test]
    fn failed_old_scope_cleanup_is_tracked_and_retryable() {
        let (store, root) = test_store("cleanup-retry");
        let secrets = FailingDeleteStore::default();
        let mut settings = AppSettings::default();
        let owner = BearerCredentialOwner::profile("http_json_lab");
        let first = binding(
            owner.clone(),
            ConnectorKind::HttpJson,
            "https://old.example.test/traces",
            BearerCredentialState::Active,
        )
        .expect("old binding");
        let old_scope = scope_for_binding(&first).expect("old scope");
        store_bearer_credential(&store, &mut settings, &secrets, first, "old-token")
            .expect("store old token");
        *secrets.fail_scope.lock().expect("failure lock") = Some(old_scope.clone());

        let second = binding(
            owner.clone(),
            ConnectorKind::HttpJson,
            "https://new.example.test/traces",
            BearerCredentialState::Active,
        )
        .expect("new binding");
        let error = store_bearer_credential(&store, &mut settings, &secrets, second, "new-token")
            .expect_err("old deletion must be reported");
        assert!(error.to_string().contains("cleanup is incomplete"));
        assert_eq!(
            settings
                .bearer_credentials
                .iter()
                .filter(|binding| binding.state == BearerCredentialState::Active)
                .count(),
            1
        );
        assert_eq!(
            settings
                .bearer_credentials
                .iter()
                .filter(|binding| binding.state == BearerCredentialState::PendingDeletion)
                .count(),
            1
        );

        *secrets.fail_scope.lock().expect("failure lock") = None;
        cleanup_pending_bindings(&store, &mut settings, &secrets, Some(&owner))
            .expect("retry cleanup");
        assert_eq!(settings.bearer_credentials.len(), 1);
        assert!(
            secrets
                .get_bearer_token(&old_scope)
                .expect("read old token")
                .is_none()
        );
        cleanup(&root);
    }

    #[test]
    fn post_publication_activation_failure_never_rolls_back_the_new_secret() {
        let (store, root) = test_store("activation-commit-unknown");
        let secrets = MemorySecretStore::new();
        let mut settings = AppSettings::default();
        let desired = binding(
            BearerCredentialOwner::profile("http_json_lab"),
            ConnectorKind::HttpJson,
            "https://commit-unknown.example.test/traces",
            BearerCredentialState::Active,
        )
        .expect("binding");
        let scope = scope_for_binding(&desired).expect("scope");
        store.fail_after_publications_for_test(2);

        let error = store_bearer_credential(
            &store,
            &mut settings,
            &secrets,
            desired.clone(),
            "new-secret",
        )
        .expect_err("post-publication activation failure must be visible");

        assert!(
            format!("{error:#}").contains("retained for deterministic startup reconciliation"),
            "{error:#}"
        );
        assert_eq!(
            secrets
                .get_bearer_token(&scope)
                .expect("read retained secret")
                .expect("retained secret")
                .as_str(),
            "new-secret"
        );
        let persisted = SettingsStore::new(store.path().to_path_buf())
            .load()
            .expect("reload published activation");
        assert_eq!(persisted.bearer_credentials, vec![desired]);
        cleanup(&root);
    }

    #[test]
    fn stale_instance_is_rejected_before_rotating_an_active_secret() {
        let (first_store, root) = test_store("stale-active-rotation");
        let secrets = MemorySecretStore::new();
        let mut first = AppSettings::default();
        let desired = binding(
            BearerCredentialOwner::profile("http_json_lab"),
            ConnectorKind::HttpJson,
            "https://rotation.example.test/traces",
            BearerCredentialState::Active,
        )
        .expect("binding");
        let scope = scope_for_binding(&desired).expect("scope");
        store_bearer_credential(
            &first_store,
            &mut first,
            &secrets,
            desired.clone(),
            "initial-secret",
        )
        .expect("seed active secret");
        let stale_store = SettingsStore::new(first_store.path().to_path_buf());
        let mut stale = stale_store.load().expect("load stale process snapshot");

        store_bearer_credential(
            &first_store,
            &mut first,
            &secrets,
            desired.clone(),
            "winner-secret",
        )
        .expect("rotate from current process");
        let error =
            store_bearer_credential(&stale_store, &mut stale, &secrets, desired, "stale-secret")
                .expect_err("stale process must fail before its Keychain mutation");

        assert!(format!("{error:#}").contains("changed in another process"));
        assert_eq!(
            secrets
                .get_bearer_token(&scope)
                .expect("read winning secret")
                .expect("winning secret")
                .as_str(),
            "winner-secret"
        );
        cleanup(&root);
    }

    #[test]
    fn legacy_token_migrates_once_without_entering_settings_json() {
        let (store, root) = test_store("legacy");
        let secrets =
            MemorySecretStore::with_legacy_live_api_token("legacy-secret").expect("legacy fixture");
        let mut settings = AppSettings {
            api: crate::settings::ApiSettings {
                endpoint: "https://legacy.example.test/traces".to_string(),
                ..crate::settings::ApiSettings::default()
            },
            ..AppSettings::default()
        };
        store
            .save(&mut settings)
            .expect("persist legacy destination settings");

        assert_eq!(
            migrate_legacy_live_api_credential(&store, &mut settings, &secrets)
                .expect("migrate legacy token"),
            LegacyCredentialMigration::Migrated
        );
        assert!(
            secrets
                .get_legacy_live_api_token()
                .expect("read legacy entry")
                .is_none()
        );
        let binding = settings
            .bearer_credentials
            .first()
            .expect("scoped registry entry");
        let scope = scope_for_binding(binding).expect("migrated scope");
        assert_eq!(
            secrets
                .get_bearer_token(&scope)
                .expect("read migrated token")
                .expect("migrated token")
                .as_str(),
            "legacy-secret"
        );
        let serialized = serde_json::to_string(&settings).expect("serialize settings");
        assert!(!serialized.contains("legacy-secret"));
        assert!(!format!("{settings:?}").contains("legacy-secret"));
        assert_eq!(
            migrate_legacy_live_api_credential(&store, &mut settings, &secrets)
                .expect("migration is idempotent"),
            LegacyCredentialMigration::NotPresent
        );
        cleanup(&root);
    }

    #[test]
    fn unsafe_legacy_destination_fails_closed_and_retains_the_old_entry() {
        let (store, root) = test_store("legacy-fail-closed");
        let secrets =
            MemorySecretStore::with_legacy_live_api_token("legacy-secret").expect("legacy fixture");
        let mut settings = AppSettings::default();

        let error = migrate_legacy_live_api_credential(&store, &mut settings, &secrets)
            .expect_err("missing destination endpoint must block migration");
        assert!(error.to_string().contains("no safe destination scope"));
        assert!(
            secrets
                .get_legacy_live_api_token()
                .expect("read retained legacy entry")
                .is_some()
        );
        assert!(settings.bearer_credentials.is_empty());
        cleanup(&root);
    }

    #[derive(Default)]
    struct FailingDeleteStore {
        inner: MemorySecretStore,
        fail_scope: Mutex<Option<BearerSecretScope>>,
    }

    impl SecretStore for FailingDeleteStore {
        fn get_bearer_token(
            &self,
            scope: &BearerSecretScope,
        ) -> Result<Option<ValidatedBearerToken>> {
            self.inner.get_bearer_token(scope)
        }

        fn set_bearer_token(&self, scope: &BearerSecretScope, token: &str) -> Result<()> {
            self.inner.set_bearer_token(scope, token)
        }

        fn delete_bearer_token(&self, scope: &BearerSecretScope) -> Result<()> {
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
            self.inner.delete_legacy_live_api_token()
        }
    }
}
