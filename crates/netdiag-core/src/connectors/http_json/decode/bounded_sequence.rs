use serde::de::{Deserialize, Deserializer, Error, IgnoredAny, SeqAccess, Visitor};
use std::fmt;
use std::marker::PhantomData;

pub(super) const LIMIT_ERROR_MARKER: &str = "netdiag-http-json-sequence-limit";

#[derive(Debug)]
pub(super) struct BoundedSequence<T, const LIMIT: usize>(pub(super) Vec<T>);

impl<'de, T, const LIMIT: usize> Deserialize<'de> for BoundedSequence<T, LIMIT>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedSequenceVisitor { item: PhantomData })
    }
}

struct BoundedSequenceVisitor<T, const LIMIT: usize> {
    item: PhantomData<T>,
}

impl<'de, T, const LIMIT: usize> Visitor<'de> for BoundedSequenceVisitor<T, LIMIT>
where
    T: Deserialize<'de>,
{
    type Value = BoundedSequence<T, LIMIT>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a JSON array containing at most {LIMIT} items")
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let capacity = sequence.size_hint().unwrap_or_default().min(LIMIT);
        let mut items = Vec::with_capacity(capacity);
        while items.len() < LIMIT {
            let Some(item) = sequence.next_element()? else {
                return Ok(BoundedSequence(items));
            };
            items.push(item);
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(A::Error::custom(format_args!(
                "{LIMIT_ERROR_MARKER}:{LIMIT}"
            )));
        }
        Ok(BoundedSequence(items))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_limits::MAX_SOURCE_RECORDS;

    #[test]
    fn production_record_limit_is_inclusive_without_large_record_fixtures() {
        let sequence = |count: usize| format!("[{}0]", "0,".repeat(count - 1));
        let exact = sequence(MAX_SOURCE_RECORDS);
        let decoded: BoundedSequence<u8, MAX_SOURCE_RECORDS> =
            serde_json::from_str(&exact).expect("exact record limit");
        assert_eq!(decoded.0.len(), MAX_SOURCE_RECORDS);

        let oversized = sequence(MAX_SOURCE_RECORDS + 1);
        let error = serde_json::from_str::<BoundedSequence<u8, MAX_SOURCE_RECORDS>>(&oversized)
            .expect_err("record limit plus one");
        assert!(error.to_string().contains(LIMIT_ERROR_MARKER), "{error}");
    }
}
