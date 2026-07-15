use serde::de::{Deserialize, Error, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeSet;
use std::fmt;

pub(super) const DUPLICATE_KEY_ERROR: &str = "JSON object contains a duplicate key";

pub(super) fn validate_unique_keys(bytes: &[u8]) -> serde_json::Result<()> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    UniqueJsonShape::deserialize(&mut deserializer)?;
    deserializer.end()
}

struct UniqueJsonShape;

impl<'de> Deserialize<'de> for UniqueJsonShape {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonShapeVisitor)
    }
}

struct UniqueJsonShapeVisitor;

impl<'de> Visitor<'de> for UniqueJsonShapeVisitor {
    type Value = UniqueJsonShape;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value whose object keys are unique")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonShape)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonShape)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonShape)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(UniqueJsonShape)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonShape)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonShape)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonShape)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonShape)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<UniqueJsonShape>()?.is_some() {}
        Ok(UniqueJsonShape)
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = entries.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(A::Error::custom(DUPLICATE_KEY_ERROR));
            }
            entries.next_value::<UniqueJsonShape>()?;
        }
        Ok(UniqueJsonShape)
    }
}
