use crate::reliability::is_sensitive_parameter_key;

pub(in crate::pilot) fn redacted_adapter_argument(argument: &str) -> String {
    let trimmed = argument.trim();
    if let Some((flag, _)) = trimmed.split_once('=')
        && safe_option_name(flag)
    {
        return format!("{flag}=[redacted]");
    }
    if safe_long_option(trimmed) && !is_sensitive_parameter_key(&trimmed[2..])
        || safe_short_option(trimmed)
    {
        return trimmed.to_string();
    }
    attached_short_option(trimmed).map_or_else(
        || "[redacted]".to_string(),
        |flag| format!("{flag}[redacted]"),
    )
}

fn safe_option_name(value: &str) -> bool {
    safe_long_option(value) || safe_short_option(value)
}

fn safe_long_option(value: &str) -> bool {
    value
        .strip_prefix("--")
        .is_some_and(|name| !name.is_empty() && name.bytes().all(option_name_byte))
}

fn safe_short_option(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 2 && bytes[0] == b'-' && bytes[1].is_ascii_alphabetic()
}

fn attached_short_option(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    (bytes.len() > 2 && bytes[0] == b'-' && bytes[1].is_ascii_alphabetic()).then(|| &value[..2])
}

fn option_name_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_')
}
