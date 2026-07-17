#[cfg(target_os = "macos")]
use anyhow::Context;
#[cfg(any(test, not(target_os = "macos")))]
use anyhow::anyhow;
use anyhow::{Result, bail};
use netdiag_core::authentication::{
    BearerSourceKind, CanonicalHttpOrigin, ValidatedBearerToken, validate_bearer_token,
};
use sha2::{Digest, Sha256};
#[cfg(any(test, not(target_os = "macos")))]
use std::collections::BTreeMap;
#[cfg(any(test, not(target_os = "macos")))]
use std::sync::Mutex;
#[cfg(target_os = "macos")]
use std::sync::OnceLock;

mod presence;
#[cfg(test)]
use presence::{BEARER_SECRET_PRESENCE_TTL, BEARER_SECRET_READ_FAILURE_RETRY_DELAY};
pub use presence::{BearerSecretPresence, BearerSecretPresenceCache};

pub const DEFAULT_KEYCHAIN_SERVICE: &str = "com.netdiag.twin";
pub const LEGACY_LIVE_API_TOKEN_ACCOUNT: &str = "live_api_token";
const BEARER_SCOPE_DOMAIN: &[u8] = b"netdiag-twin/bearer-secret/v1";
const MAX_SCOPE_COMPONENT_BYTES: usize = 16 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct BearerSecretScope {
    account: String,
    source_kind: BearerSourceKind,
    origin: CanonicalHttpOrigin,
}

impl BearerSecretScope {
    pub fn new(
        profile_id: &str,
        source_kind: BearerSourceKind,
        origin: &CanonicalHttpOrigin,
    ) -> Result<Self> {
        for (name, value) in [
            ("profile id", profile_id),
            ("source kind", source_kind.as_str()),
            ("canonical origin", origin.as_str()),
        ] {
            if value.is_empty() {
                bail!("bearer secret scope {name} is empty");
            }
            if value.len() > MAX_SCOPE_COMPONENT_BYTES {
                bail!("bearer secret scope {name} is too long");
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(BEARER_SCOPE_DOMAIN);
        for value in [profile_id, source_kind.as_str(), origin.as_str()] {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        let digest = hasher.finalize();
        let mut account = String::with_capacity("bearer_v1_".len() + digest.len() * 2);
        account.push_str("bearer_v1_");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in digest {
            account.push(HEX[(byte >> 4) as usize] as char);
            account.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Ok(Self {
            account,
            source_kind,
            origin: origin.clone(),
        })
    }

    fn account(&self) -> &str {
        &self.account
    }

    pub(crate) fn ensure_matches(
        &self,
        source_kind: BearerSourceKind,
        origin: &CanonicalHttpOrigin,
    ) -> Result<()> {
        if self.source_kind != source_kind || &self.origin != origin {
            bail!("bearer secret scope does not match the connector kind and origin");
        }
        Ok(())
    }
}

impl std::fmt::Debug for BearerSecretScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BearerSecretScope(<redacted>)")
    }
}

pub trait SecretStore: Send + Sync {
    fn get_bearer_token(&self, scope: &BearerSecretScope) -> Result<Option<ValidatedBearerToken>>;
    fn set_bearer_token(&self, scope: &BearerSecretScope, token: &str) -> Result<()>;
    fn delete_bearer_token(&self, scope: &BearerSecretScope) -> Result<()>;
    fn get_legacy_live_api_token(&self) -> Result<Option<ValidatedBearerToken>>;
    fn delete_legacy_live_api_token(&self) -> Result<()>;

    fn has_bearer_token(&self, scope: &BearerSecretScope) -> Result<bool> {
        Ok(self.get_bearer_token(scope)?.is_some())
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
pub struct KeychainSecretStore;

#[cfg(target_os = "macos")]
impl SecretStore for KeychainSecretStore {
    fn get_bearer_token(&self, scope: &BearerSecretScope) -> Result<Option<ValidatedBearerToken>> {
        match keychain_entry(scope)?.get_password() {
            Ok(token) => validate_bearer_token(token)
                .map(Some)
                .map_err(anyhow::Error::from),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(error) => Err(error.into()),
        }
        .context("failed to read scoped bearer token from macOS Keychain")
    }

    fn set_bearer_token(&self, scope: &BearerSecretScope, token: &str) -> Result<()> {
        let token = validate_bearer_token(token.to_string()).map_err(anyhow::Error::from)?;
        keychain_entry(scope)?
            .set_password(token.as_str())
            .context("failed to save scoped bearer token to macOS Keychain")
    }

    fn delete_bearer_token(&self, scope: &BearerSecretScope) -> Result<()> {
        keychain_entry(scope)?
            .delete_credential()
            .or_else(|error| {
                if matches!(error, keyring_core::Error::NoEntry) {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .context("failed to delete scoped bearer token from macOS Keychain")
    }

    fn get_legacy_live_api_token(&self) -> Result<Option<ValidatedBearerToken>> {
        match legacy_keychain_entry()?.get_password() {
            Ok(token) => validate_bearer_token(token)
                .map(Some)
                .map_err(anyhow::Error::from),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(error) => Err(error.into()),
        }
        .context("failed to read legacy Live API token from macOS Keychain")
    }

    fn delete_legacy_live_api_token(&self) -> Result<()> {
        legacy_keychain_entry()?
            .delete_credential()
            .or_else(|error| {
                if matches!(error, keyring_core::Error::NoEntry) {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .context("failed to delete legacy Live API token from macOS Keychain")
    }
}

#[cfg(target_os = "macos")]
fn keychain_entry(scope: &BearerSecretScope) -> Result<keyring_core::Entry> {
    ensure_keychain_store()?;
    keyring_core::Entry::new(DEFAULT_KEYCHAIN_SERVICE, scope.account())
        .context("failed to create macOS Keychain entry")
}

#[cfg(target_os = "macos")]
fn legacy_keychain_entry() -> Result<keyring_core::Entry> {
    ensure_keychain_store()?;
    keyring_core::Entry::new(DEFAULT_KEYCHAIN_SERVICE, LEGACY_LIVE_API_TOKEN_ACCOUNT)
        .context("failed to create legacy macOS Keychain entry")
}

#[cfg(target_os = "macos")]
fn ensure_keychain_store() -> Result<()> {
    static INIT: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    INIT.get_or_init(|| {
        let store = apple_native_keyring_store::keychain::Store::new()
            .map_err(|error| error.to_string())?;
        keyring_core::set_default_store(store);
        Ok(())
    })
    .as_ref()
    .map_err(|error| anyhow::anyhow!(error.clone()))
    .copied()
    .context("failed to initialize macOS Keychain store")
}

#[cfg(any(test, not(target_os = "macos")))]
#[derive(Default)]
pub struct MemorySecretStore {
    values: Mutex<BTreeMap<String, ValidatedBearerToken>>,
}

#[cfg(any(test, not(target_os = "macos")))]
impl std::fmt::Debug for MemorySecretStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MemorySecretStore(<redacted>)")
    }
}

#[cfg(any(test, not(target_os = "macos")))]
impl MemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub fn with_legacy_live_api_token(token: &str) -> Result<Self> {
        let token = validate_bearer_token(token.to_owned()).map_err(anyhow::Error::from)?;
        Ok(Self {
            values: Mutex::new(BTreeMap::from([(
                LEGACY_LIVE_API_TOKEN_ACCOUNT.to_string(),
                token,
            )])),
        })
    }

    fn lock_values(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, ValidatedBearerToken>>> {
        self.values
            .lock()
            .map_err(|_| anyhow!("memory secret store lock poisoned"))
    }
}

#[cfg(any(test, not(target_os = "macos")))]
impl SecretStore for MemorySecretStore {
    fn get_bearer_token(&self, scope: &BearerSecretScope) -> Result<Option<ValidatedBearerToken>> {
        self.lock_values()?
            .get(scope.account())
            .map(|token| validate_bearer_token(token.as_str().to_owned()))
            .transpose()
            .map_err(anyhow::Error::from)
    }

    fn set_bearer_token(&self, scope: &BearerSecretScope, token: &str) -> Result<()> {
        let token = validate_bearer_token(token.to_string()).map_err(anyhow::Error::from)?;
        self.lock_values()?
            .insert(scope.account().to_string(), token);
        Ok(())
    }

    fn delete_bearer_token(&self, scope: &BearerSecretScope) -> Result<()> {
        self.lock_values()?.remove(scope.account());
        Ok(())
    }

    fn get_legacy_live_api_token(&self) -> Result<Option<ValidatedBearerToken>> {
        self.lock_values()?
            .get(LEGACY_LIVE_API_TOKEN_ACCOUNT)
            .map(|token| validate_bearer_token(token.as_str().to_owned()))
            .transpose()
            .map_err(anyhow::Error::from)
    }

    fn delete_legacy_live_api_token(&self) -> Result<()> {
        self.lock_values()?.remove(LEGACY_LIVE_API_TOKEN_ACCOUNT);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netdiag_core::authentication::canonical_http_origin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    fn scope(profile: &str, endpoint: &str) -> BearerSecretScope {
        BearerSecretScope::new(
            profile,
            BearerSourceKind::HttpJson,
            &canonical_http_origin(endpoint).expect("origin"),
        )
        .expect("scope")
    }

    #[test]
    fn memory_store_round_trips_only_the_exact_scope() {
        let store = MemorySecretStore::default();
        let first = scope("first", "https://one.example.test/path");
        let other_profile = scope("other", "https://one.example.test/path");
        let other_origin = scope("first", "https://two.example.test/path");

        assert!(
            store
                .get_bearer_token(&first)
                .expect("read empty")
                .is_none()
        );
        store.set_bearer_token(&first, "secret-token").expect("set");
        let token = store
            .get_bearer_token(&first)
            .expect("read token")
            .expect("stored token");
        assert_eq!(token.as_str(), "secret-token");
        assert!(!format!("{token:?}").contains("secret-token"));
        assert!(
            store
                .get_bearer_token(&other_profile)
                .expect("other profile")
                .is_none()
        );
        assert!(
            store
                .get_bearer_token(&other_origin)
                .expect("other origin")
                .is_none()
        );
        store.delete_bearer_token(&first).expect("delete");
        assert!(
            store
                .get_bearer_token(&first)
                .expect("read deleted")
                .is_none()
        );
    }

    struct CountingStore {
        reads: AtomicUsize,
    }

    impl SecretStore for CountingStore {
        fn get_bearer_token(
            &self,
            _scope: &BearerSecretScope,
        ) -> Result<Option<ValidatedBearerToken>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            validate_bearer_token("opaque-token".to_string())
                .map(Some)
                .map_err(anyhow::Error::from)
        }

        fn set_bearer_token(&self, _scope: &BearerSecretScope, _token: &str) -> Result<()> {
            bail!("test store is read-only")
        }

        fn delete_bearer_token(&self, _scope: &BearerSecretScope) -> Result<()> {
            bail!("test store is read-only")
        }

        fn get_legacy_live_api_token(&self) -> Result<Option<ValidatedBearerToken>> {
            Ok(None)
        }

        fn delete_legacy_live_api_token(&self) -> Result<()> {
            bail!("test store is read-only")
        }
    }

    #[test]
    fn presence_cache_reads_once_per_scope_and_updates_after_mutation() {
        let store = CountingStore {
            reads: AtomicUsize::new(0),
        };
        let first = scope("first", "https://one.example.test/path");
        let second = scope("second", "https://one.example.test/path");
        let mut cache = BearerSecretPresenceCache::default();

        assert_eq!(
            cache.for_scope(&store, &first),
            &BearerSecretPresence::Present
        );
        assert_eq!(
            cache.for_scope(&store, &first),
            &BearerSecretPresence::Present
        );
        assert_eq!(store.reads.load(Ordering::SeqCst), 1);

        cache.mark_missing(&first);
        assert_eq!(
            cache.for_scope(&store, &first),
            &BearerSecretPresence::Missing
        );
        assert_eq!(store.reads.load(Ordering::SeqCst), 1);

        cache.invalidate();
        assert_eq!(
            cache.for_scope(&store, &first),
            &BearerSecretPresence::Present
        );
        assert_eq!(store.reads.load(Ordering::SeqCst), 2);

        assert_eq!(
            cache.for_scope(&store, &second),
            &BearerSecretPresence::Present
        );
        assert_eq!(store.reads.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn presence_cache_does_not_repeat_successful_reads_before_ttl() {
        let store = CountingStore {
            reads: AtomicUsize::new(0),
        };
        let scope = scope("ttl", "https://ttl.example.test/path");
        let mut cache = BearerSecretPresenceCache::default();
        let started = Instant::now();

        assert_eq!(
            cache.for_scope_at(&store, &scope, started),
            &BearerSecretPresence::Present
        );
        assert_eq!(
            cache.for_scope_at(
                &store,
                &scope,
                started + BEARER_SECRET_PRESENCE_TTL - Duration::from_nanos(1),
            ),
            &BearerSecretPresence::Present
        );
        assert_eq!(store.reads.load(Ordering::SeqCst), 1);

        assert_eq!(
            cache.for_scope_at(&store, &scope, started + BEARER_SECRET_PRESENCE_TTL),
            &BearerSecretPresence::Present
        );
        assert_eq!(store.reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn presence_cache_observes_external_secret_changes_after_ttl() {
        let store = MemorySecretStore::default();
        let scope = scope("external", "https://external.example.test/path");
        let mut cache = BearerSecretPresenceCache::default();
        let started = Instant::now();

        assert_eq!(
            cache.for_scope_at(&store, &scope, started),
            &BearerSecretPresence::Missing
        );
        store
            .set_bearer_token(&scope, "external-secret")
            .expect("external secret write");
        assert_eq!(
            cache.for_scope_at(
                &store,
                &scope,
                started + BEARER_SECRET_PRESENCE_TTL - Duration::from_nanos(1),
            ),
            &BearerSecretPresence::Missing
        );
        assert_eq!(
            cache.for_scope_at(&store, &scope, started + BEARER_SECRET_PRESENCE_TTL),
            &BearerSecretPresence::Present
        );

        store
            .delete_bearer_token(&scope)
            .expect("external secret deletion");
        assert_eq!(
            cache.for_scope_at(
                &store,
                &scope,
                started + BEARER_SECRET_PRESENCE_TTL * 2 - Duration::from_nanos(1),
            ),
            &BearerSecretPresence::Present
        );
        assert_eq!(
            cache.for_scope_at(&store, &scope, started + BEARER_SECRET_PRESENCE_TTL * 2,),
            &BearerSecretPresence::Missing
        );
    }

    struct RecoveringStore {
        reads: AtomicUsize,
    }

    impl SecretStore for RecoveringStore {
        fn get_bearer_token(
            &self,
            _scope: &BearerSecretScope,
        ) -> Result<Option<ValidatedBearerToken>> {
            if self.reads.fetch_add(1, Ordering::SeqCst) == 0 {
                bail!("transient secret store read failure");
            }
            validate_bearer_token("recovered-token".to_string())
                .map(Some)
                .map_err(anyhow::Error::from)
        }

        fn set_bearer_token(&self, _scope: &BearerSecretScope, _token: &str) -> Result<()> {
            bail!("test store is read-only")
        }

        fn delete_bearer_token(&self, _scope: &BearerSecretScope) -> Result<()> {
            bail!("test store is read-only")
        }

        fn get_legacy_live_api_token(&self) -> Result<Option<ValidatedBearerToken>> {
            Ok(None)
        }

        fn delete_legacy_live_api_token(&self) -> Result<()> {
            bail!("test store is read-only")
        }
    }

    #[test]
    fn presence_cache_retries_read_failures_without_reading_every_frame() {
        let store = RecoveringStore {
            reads: AtomicUsize::new(0),
        };
        let scope = scope("recovery", "https://recovery.example.test/path");
        let mut cache = BearerSecretPresenceCache::default();
        let started = Instant::now();

        let first = cache.for_scope_at(&store, &scope, started);
        assert!(
            matches!(first, BearerSecretPresence::ReadFailed(message) if message.contains("transient secret store read failure"))
        );
        let cached = cache.for_scope_at(
            &store,
            &scope,
            started + BEARER_SECRET_READ_FAILURE_RETRY_DELAY - Duration::from_nanos(1),
        );
        assert!(matches!(cached, BearerSecretPresence::ReadFailed(_)));
        assert_eq!(store.reads.load(Ordering::SeqCst), 1);

        assert_eq!(
            cache.for_scope_at(
                &store,
                &scope,
                started + BEARER_SECRET_READ_FAILURE_RETRY_DELAY,
            ),
            &BearerSecretPresence::Present
        );
        assert_eq!(store.reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn invalidation_reloads_partial_mutation_state_from_the_secret_store() {
        let store = MemorySecretStore::default();
        let scope = scope("partial", "https://partial.example.test/path");
        let mut cache = BearerSecretPresenceCache::default();

        assert_eq!(
            cache.for_scope(&store, &scope),
            &BearerSecretPresence::Missing
        );
        store
            .set_bearer_token(&scope, "new-secret")
            .expect("simulate a committed secret before a later cleanup failure");
        cache.invalidate();
        assert_eq!(
            cache.for_scope(&store, &scope),
            &BearerSecretPresence::Present
        );

        store
            .delete_bearer_token(&scope)
            .expect("simulate deletion before a later cleanup failure");
        cache.invalidate();
        assert_eq!(
            cache.for_scope(&store, &scope),
            &BearerSecretPresence::Missing
        );
    }

    #[test]
    fn memory_store_rejects_invalid_tokens_without_echoing_them() {
        let store = MemorySecretStore::default();
        let scope = scope("first", "https://one.example.test/path");
        let secret = "secret with whitespace";
        let error = store
            .set_bearer_token(&scope, secret)
            .expect_err("invalid token");
        assert!(!error.to_string().contains(secret));
        assert!(store.get_bearer_token(&scope).expect("read").is_none());
    }
}
