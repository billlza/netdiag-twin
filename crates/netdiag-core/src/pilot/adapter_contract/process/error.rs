use crate::reliability::redact_string;

const ADAPTER_STDERR_EXCERPT_BYTES: usize = 8 * 1024;

pub(in crate::pilot) fn adapter_stderr_excerpt(
    bytes: &[u8],
    redaction_values: &[String],
) -> String {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    for secret in redaction_values.iter().filter(|value| !value.is_empty()) {
        text = text.replace(secret, "[redacted]");
    }
    let text = redact_string(text.trim());
    let mut excerpt = String::new();
    for character in text.chars() {
        if excerpt.len() + character.len_utf8() > ADAPTER_STDERR_EXCERPT_BYTES {
            excerpt.push_str("...[truncated]");
            break;
        }
        excerpt.push(character);
    }
    excerpt
}
