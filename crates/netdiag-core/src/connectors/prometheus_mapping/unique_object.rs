use serde::de::{Deserializer as _, Error, MapAccess, Visitor};
use std::collections::BTreeMap;
use std::fmt;

pub(super) fn parse_unique_string_map(input: &str) -> serde_json::Result<BTreeMap<String, String>> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let map = deserializer.deserialize_map(UniqueStringMapVisitor)?;
    deserializer.end()?;
    Ok(map)
}

struct UniqueStringMapVisitor;

impl<'de> Visitor<'de> for UniqueStringMapVisitor {
    type Value = BTreeMap<String, String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object with unique string keys and string values")
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut map = BTreeMap::new();
        while let Some((key, value)) = entries.next_entry::<String, String>()? {
            if map.insert(key, value).is_some() {
                return Err(A::Error::custom(
                    "mapping object contains a duplicate canonical field",
                ));
            }
        }
        Ok(map)
    }
}
