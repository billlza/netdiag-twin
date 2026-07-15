use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SettingsRevision {
    Missing,
    Present([u8; 32]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SettingsAccessState {
    Unloaded,
    Ready(SettingsRevision),
    Conflict,
    Indeterminate,
}

pub(super) fn revision(raw: &[u8]) -> SettingsRevision {
    SettingsRevision::Present(Sha256::digest(raw).into())
}
