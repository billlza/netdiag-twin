use serde::Deserialize;
use serde_json::Value;

mod validation;
use validation::validate_unique_keys;
mod typed;
pub use typed::from_slice;
mod value;
use value::UniqueJsonValue;
mod error;
pub use error::error_summary;

pub(crate) fn parse_unique_value(bytes: &[u8]) -> serde_json::Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueJsonValue::deserialize(&mut deserializer)?.into_inner();
    deserializer.end()?;
    Ok(value)
}

#[cfg(test)]
mod tests;
