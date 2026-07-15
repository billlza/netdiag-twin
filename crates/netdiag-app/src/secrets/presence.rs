use super::{BearerSecretScope, SecretStore};
use std::time::{Duration, Instant};

pub(super) const BEARER_SECRET_PRESENCE_TTL: Duration = Duration::from_secs(5);
pub(super) const BEARER_SECRET_READ_FAILURE_RETRY_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BearerSecretPresence {
    Present,
    Missing,
    ReadFailed(String),
}

#[derive(Debug, Default)]
pub struct BearerSecretPresenceCache {
    scope: Option<BearerSecretScope>,
    presence: Option<BearerSecretPresence>,
    checked_at: Option<Instant>,
}

impl BearerSecretPresenceCache {
    pub fn for_scope(
        &mut self,
        store: &dyn SecretStore,
        scope: &BearerSecretScope,
    ) -> &BearerSecretPresence {
        self.for_scope_at(store, scope, Instant::now())
    }

    pub fn mark_present(&mut self, scope: &BearerSecretScope) {
        self.scope = Some(scope.clone());
        self.presence = Some(BearerSecretPresence::Present);
        self.checked_at = Some(Instant::now());
    }

    pub fn mark_missing(&mut self, scope: &BearerSecretScope) {
        self.scope = Some(scope.clone());
        self.presence = Some(BearerSecretPresence::Missing);
        self.checked_at = Some(Instant::now());
    }

    pub fn invalidate(&mut self) {
        self.scope = None;
        self.presence = None;
        self.checked_at = None;
    }

    pub(super) fn for_scope_at(
        &mut self,
        store: &dyn SecretStore,
        scope: &BearerSecretScope,
        now: Instant,
    ) -> &BearerSecretPresence {
        let refresh_delay = match self.presence.as_ref() {
            Some(BearerSecretPresence::ReadFailed(_)) => BEARER_SECRET_READ_FAILURE_RETRY_DELAY,
            Some(BearerSecretPresence::Present | BearerSecretPresence::Missing) => {
                BEARER_SECRET_PRESENCE_TTL
            }
            None => Duration::ZERO,
        };
        let expired = self
            .checked_at
            .is_none_or(|checked_at| now.saturating_duration_since(checked_at) >= refresh_delay);
        if self.scope.as_ref() != Some(scope) || self.presence.is_none() || expired {
            let presence = match store.has_bearer_token(scope) {
                Ok(true) => BearerSecretPresence::Present,
                Ok(false) => BearerSecretPresence::Missing,
                Err(error) => BearerSecretPresence::ReadFailed(error.to_string()),
            };
            self.scope = Some(scope.clone());
            self.presence = Some(presence);
            self.checked_at = Some(now);
        }
        self.presence.as_ref().expect("presence was initialized")
    }
}
