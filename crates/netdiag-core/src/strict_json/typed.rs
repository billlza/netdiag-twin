use super::validate_unique_keys;
use serde::de::DeserializeOwned;

/// Deserializes JSON after recursively rejecting duplicate object keys.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> serde_json::Result<T> {
    validate_unique_keys(bytes)?;
    serde_json::from_slice(bytes)
}
