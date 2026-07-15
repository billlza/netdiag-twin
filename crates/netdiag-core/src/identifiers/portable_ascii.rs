const MAX_PORTABLE_ID_LENGTH: usize = 128;

pub(super) fn validate_portable_ascii(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("is empty");
    }
    if value.len() > MAX_PORTABLE_ID_LENGTH {
        return Err("exceeds 128 bytes");
    }
    let bytes = value.as_bytes();
    let valid = bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    valid.then_some(()).ok_or(
        "must start and end with an ASCII letter or digit and contain only ASCII letters, digits, '-', '_', or '.'",
    )
}
