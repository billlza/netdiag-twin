const MAX_PERCENT_DECODE_PASSES: usize = 8;

pub(crate) fn is_sensitive_parameter_key(key: &str) -> bool {
    let (key, ambiguous_encoding) = normalized_key(key);
    if ambiguous_encoding {
        return true;
    }
    has_sensitive_marker(&key)
        || ["sig", "key", "auth"]
            .iter()
            .any(|marker| key == *marker || key.starts_with(marker) || key.ends_with(marker))
}

pub(super) fn is_sensitive_document_key(key: &str) -> bool {
    let (key, ambiguous_encoding) = normalized_key(key);
    if ambiguous_encoding {
        return true;
    }
    has_sensitive_marker(&key)
        || [
            "accesskey",
            "authkey",
            "privatekey",
            "signingkey",
            "encryptionkey",
            "decryptionkey",
            "sessionkey",
            "sshkey",
        ]
        .iter()
        .any(|marker| key.contains(marker))
        || matches!(key.as_str(), "auth" | "authheader")
}

fn has_sensitive_marker(key: &str) -> bool {
    [
        "token",
        "secret",
        "password",
        "passwd",
        "credential",
        "authorization",
        "authentication",
        "bearer",
        "apikey",
        "signature",
    ]
    .iter()
    .any(|marker| key.contains(marker))
}

pub(crate) fn query_contains_sensitive_or_ambiguous_syntax(query: &str) -> bool {
    let (decoded, ambiguous_encoding) = percent_decode_bounded(query.as_bytes());
    if ambiguous_encoding {
        return true;
    }
    decoded
        .split(|byte| matches!(byte, b'&' | b';'))
        .filter_map(|parameter| parameter.split(|byte| *byte == b'=').next())
        .any(|key| {
            let key = String::from_utf8_lossy(key);
            is_sensitive_parameter_key(&key)
        })
}

fn normalized_key(key: &str) -> (String, bool) {
    let (decoded, ambiguous_encoding) = percent_decode_bounded(key.as_bytes());
    let normalized = decoded
        .into_iter()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect();
    (normalized, ambiguous_encoding)
}

fn percent_decode_bounded(value: &[u8]) -> (Vec<u8>, bool) {
    let mut decoded = value.to_vec();
    for _ in 0..MAX_PERCENT_DECODE_PASSES {
        let next = percent_decode(&decoded);
        if next == decoded {
            return (decoded, false);
        }
        decoded = next;
    }
    let next = percent_decode(&decoded);
    let ambiguous_encoding = next != decoded;
    (decoded, ambiguous_encoding)
}

fn percent_decode(value: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'%'
            && index + 2 < value.len()
            && let (Some(high), Some(low)) = (hex(value[index + 1]), hex(value[index + 2]))
        {
            decoded.push(high * 16 + low);
            index += 3;
        } else {
            decoded.push(value[index]);
            index += 1;
        }
    }
    decoded
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
