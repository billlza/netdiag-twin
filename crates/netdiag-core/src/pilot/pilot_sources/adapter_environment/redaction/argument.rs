pub(super) fn is_flag(value: &str) -> bool {
    value.starts_with("--")
        || (value.starts_with('-')
            && value
                .as_bytes()
                .get(1)
                .is_some_and(|byte| byte.is_ascii_alphabetic()))
}

pub(super) fn is_separated_option_name(value: &str) -> bool {
    value
        .strip_prefix("--")
        .is_some_and(|name| !name.is_empty())
        || (value.len() == 2
            && value.starts_with('-')
            && value
                .as_bytes()
                .get(1)
                .is_some_and(|byte| byte.is_ascii_alphabetic()))
}

pub(super) fn attached_short_option_value(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    (bytes.len() > 2 && bytes[0] == b'-' && bytes[1].is_ascii_alphabetic()).then(|| &value[2..])
}
