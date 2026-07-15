use super::{NETDIAG_API_TIMEOUT_SECONDS_ENV, NETDIAG_API_URL_ENV};
use anyhow::Result;
use std::env;

pub(super) fn read_api_environment() -> Result<Vec<(String, String)>> {
    [NETDIAG_API_URL_ENV, NETDIAG_API_TIMEOUT_SECONDS_ENV]
        .into_iter()
        .filter_map(|name| match env::var(name) {
            Ok(value) => Some(Ok((name.to_string(), value))),
            Err(env::VarError::NotPresent) => None,
            Err(env::VarError::NotUnicode(_)) => {
                Some(Err(anyhow::anyhow!("{name} contains non-Unicode data")))
            }
        })
        .collect()
}

pub(super) fn first_non_empty<'a>(
    values: impl IntoIterator<Item = Option<&'a str>>,
) -> Option<&'a str> {
    values.into_iter().flatten().find_map(non_empty)
}

fn non_empty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}
