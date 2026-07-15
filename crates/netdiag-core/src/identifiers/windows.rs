pub(super) fn is_reserved_device_name(value: &str) -> bool {
    let stem = value.split('.').next().unwrap_or(value);
    let stem = stem.to_ascii_uppercase();
    let numbered_device = stem.len() == 4
        && matches!(&stem[..3], "COM" | "LPT")
        && matches!(stem.as_bytes()[3], b'1'..=b'9');
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL") || numbered_device
}
