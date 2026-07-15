use super::TrustedTempDirectoryError;

const RANDOM_NAME_BYTES: usize = 16;
const MAX_PREFIX_BYTES: usize = 64;
const HEX: &[u8; 16] = b"0123456789abcdef";

pub(super) fn validate_prefix(prefix: &str) -> Result<(), TrustedTempDirectoryError> {
    if prefix.is_empty()
        || prefix.len() > MAX_PREFIX_BYTES
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(TrustedTempDirectoryError::InvalidPrefix);
    }
    Ok(())
}

pub(super) fn validate_generated_name(
    prefix: &str,
    name: &str,
) -> Result<(), TrustedTempDirectoryError> {
    let Some(random_suffix) = name.strip_prefix(prefix) else {
        return Err(TrustedTempDirectoryError::InvalidGeneratedName);
    };
    if random_suffix.len() != RANDOM_NAME_BYTES * 2
        || !random_suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(TrustedTempDirectoryError::InvalidGeneratedName);
    }
    Ok(())
}

pub(super) fn random_name(prefix: &str) -> Result<String, TrustedTempDirectoryError> {
    let mut bytes = [0_u8; RANDOM_NAME_BYTES];
    getrandom::fill(&mut bytes).map_err(|source| TrustedTempDirectoryError::Random { source })?;
    let mut name = String::with_capacity(prefix.len() + RANDOM_NAME_BYTES * 2);
    name.push_str(prefix);
    for byte in bytes {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(name)
}
