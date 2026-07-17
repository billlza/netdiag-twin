use super::SECRET_PLACEHOLDER;
use super::key::{is_sensitive_parameter_key, query_contains_sensitive_or_ambiguous_syntax};

pub fn redact_string(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || is_redacted_value(trimmed) {
        return value.to_string();
    }
    if is_authorization_value(trimmed) {
        SECRET_PLACEHOLDER.to_string()
    } else if looks_like_url(trimmed) {
        redact_url(trimmed)
    } else if contains_embedded_url_secret(trimmed) {
        SECRET_PLACEHOLDER.to_string()
    } else {
        value.to_string()
    }
}

/// Returns a deterministic, persistence-safe representation of an endpoint URL.
///
/// User information is removed completely, sensitive query values are replaced,
/// and fragments are discarded. Invalid URLs fail closed.
pub fn redact_url(value: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(value.trim()) else {
        return SECRET_PLACEHOLDER.to_string();
    };
    let Ok(mut changed) = remove_user_info(&mut url) else {
        return SECRET_PLACEHOLDER.to_string();
    };
    let pairs = url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let has_standard_sensitive_key = pairs.iter().any(|(key, _)| is_sensitive_parameter_key(key));
    let needs_standard_redaction = pairs
        .iter()
        .any(|(key, value)| is_sensitive_parameter_key(key) && !is_redacted_value(value));
    if needs_standard_redaction {
        replace_sensitive_query_values(&mut url, pairs);
        changed = true;
    } else if !has_standard_sensitive_key
        && url
            .query()
            .is_some_and(query_contains_sensitive_or_ambiguous_syntax)
    {
        return SECRET_PLACEHOLDER.to_string();
    }
    if url.fragment().is_some() {
        url.set_fragment(None);
        changed = true;
    }
    if changed {
        url.to_string()
    } else {
        value.to_string()
    }
}

fn remove_user_info(url: &mut reqwest::Url) -> Result<bool, ()> {
    if url.username().is_empty() && url.password().is_none() {
        return Ok(false);
    }
    url.set_username("")?;
    url.set_password(None)?;
    Ok(true)
}

fn replace_sensitive_query_values(url: &mut reqwest::Url, pairs: Vec<(String, String)>) {
    url.set_query(None);
    let mut query = url.query_pairs_mut();
    for (key, value) in pairs {
        let value = if is_sensitive_parameter_key(&key) && !is_redacted_value(&value) {
            SECRET_PLACEHOLDER
        } else {
            &value
        };
        query.append_pair(&key, value);
    }
}

pub(super) fn looks_like_secret_value(value: &str) -> bool {
    is_authorization_value(value) || (looks_like_url(value) && redact_url(value) != value)
}

fn is_authorization_value(value: &str) -> bool {
    ["Bearer ", "Token ", "Basic "].iter().any(|prefix| {
        value
            .get(..prefix.len())
            .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
    })
}

pub(super) fn is_redacted_value(value: &str) -> bool {
    value == SECRET_PLACEHOLDER || value == "[redacted-env]"
}

fn looks_like_url(value: &str) -> bool {
    value.split_once("://").is_some_and(|(scheme, _)| {
        let mut bytes = scheme.bytes();
        bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    })
}

fn contains_embedded_url_secret(value: &str) -> bool {
    value.contains("://")
        && (value.contains('@')
            || value
                .split_once('?')
                .is_some_and(|(_, query)| query_contains_sensitive_or_ambiguous_syntax(query)))
}
