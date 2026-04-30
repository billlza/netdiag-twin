#[cfg(any(test, not(target_os = "macos")))]
use anyhow::anyhow;
use anyhow::{Context, Result};
#[cfg(any(test, not(target_os = "macos")))]
use std::collections::BTreeMap;
#[cfg(any(test, not(target_os = "macos")))]
use std::sync::Mutex;
#[cfg(target_os = "macos")]
use std::sync::OnceLock;

pub const DEFAULT_KEYCHAIN_SERVICE: &str = "com.netdiag.twin";
pub const LIVE_API_TOKEN_ACCOUNT: &str = "live_api_token";

pub trait SecretStore: Send + Sync {
    fn get_live_api_token(&self) -> Result<Option<String>>;
    fn set_live_api_token(&self, token: &str) -> Result<()>;
    fn delete_live_api_token(&self) -> Result<()>;
    fn has_live_api_token(&self) -> Result<bool> {
        Ok(self
            .get_live_api_token()?
            .is_some_and(|token| !token.trim().is_empty()))
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
pub struct KeychainSecretStore;

#[cfg(target_os = "macos")]
impl SecretStore for KeychainSecretStore {
    fn get_live_api_token(&self) -> Result<Option<String>> {
        match keychain_entry()?.get_password() {
            Ok(token) if token.trim().is_empty() => Ok(None),
            Ok(token) => Ok(Some(token)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(err) => Err(err),
        }
        .context("failed to read Live API token from macOS Keychain")
    }

    fn set_live_api_token(&self, token: &str) -> Result<()> {
        if token.trim().is_empty() {
            return self.delete_live_api_token();
        }
        keychain_entry()?
            .set_password(token)
            .context("failed to save Live API token to macOS Keychain")
    }

    fn delete_live_api_token(&self) -> Result<()> {
        keychain_entry()?
            .delete_credential()
            .or_else(|err| {
                if matches!(err, keyring_core::Error::NoEntry) {
                    Ok(())
                } else {
                    Err(err)
                }
            })
            .context("failed to delete Live API token from macOS Keychain")
    }
}

#[cfg(target_os = "macos")]
fn keychain_entry() -> Result<keyring_core::Entry> {
    ensure_keychain_store()?;
    keyring_core::Entry::new(DEFAULT_KEYCHAIN_SERVICE, LIVE_API_TOKEN_ACCOUNT)
        .context("failed to create macOS Keychain entry")
}

#[cfg(target_os = "macos")]
fn ensure_keychain_store() -> Result<()> {
    static INIT: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    INIT.get_or_init(|| keyring::use_named_store("keychain").map_err(|err| err.to_string()))
        .as_ref()
        .map_err(|err| anyhow::anyhow!(err.clone()))
        .copied()
        .context("failed to initialize macOS Keychain store")
}

#[cfg(any(test, not(target_os = "macos")))]
#[derive(Debug, Default)]
pub struct MemorySecretStore {
    values: Mutex<BTreeMap<String, String>>,
}

#[cfg(any(test, not(target_os = "macos")))]
impl MemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_token(token: impl Into<String>) -> Self {
        let mut values = BTreeMap::new();
        values.insert(LIVE_API_TOKEN_ACCOUNT.to_string(), token.into());
        Self {
            values: Mutex::new(values),
        }
    }

    fn lock_values(&self) -> Result<std::sync::MutexGuard<'_, BTreeMap<String, String>>> {
        self.values
            .lock()
            .map_err(|_| anyhow!("memory secret store lock poisoned"))
    }
}

#[cfg(any(test, not(target_os = "macos")))]
impl SecretStore for MemorySecretStore {
    fn get_live_api_token(&self) -> Result<Option<String>> {
        Ok(self.lock_values()?.get(LIVE_API_TOKEN_ACCOUNT).cloned())
    }

    fn set_live_api_token(&self, token: &str) -> Result<()> {
        let mut values = self.lock_values()?;
        if token.trim().is_empty() {
            values.remove(LIVE_API_TOKEN_ACCOUNT);
        } else {
            values.insert(LIVE_API_TOKEN_ACCOUNT.to_string(), token.to_string());
        }
        Ok(())
    }

    fn delete_live_api_token(&self) -> Result<()> {
        self.lock_values()?.remove(LIVE_API_TOKEN_ACCOUNT);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_round_trips_token() {
        let store = MemorySecretStore::default();

        assert_eq!(store.get_live_api_token().expect("read empty"), None);
        store.set_live_api_token("secret-token").expect("set");
        assert_eq!(
            store.get_live_api_token().expect("read token"),
            Some("secret-token".to_string())
        );
        store.delete_live_api_token().expect("delete");
        assert_eq!(store.get_live_api_token().expect("read deleted"), None);
    }

    #[test]
    fn memory_store_treats_empty_token_as_delete() {
        let store = MemorySecretStore::with_token("secret-token");
        store.set_live_api_token("  ").expect("clear");
        assert_eq!(store.get_live_api_token().expect("read cleared"), None);
    }
}
