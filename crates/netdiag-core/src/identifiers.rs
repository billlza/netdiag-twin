use crate::error::{NetdiagError, Result};

mod portable_ascii;
mod windows;
use portable_ascii::validate_portable_ascii;
use windows::is_reserved_device_name;

pub fn validate_portable_id(kind: &str, value: &str) -> Result<()> {
    validate_portable_ascii(value)
        .map_err(|requirement| NetdiagError::InvalidTrace(format!("{kind} {requirement}")))?;
    if is_reserved_device_name(value) {
        return Err(NetdiagError::InvalidTrace(format!(
            "{kind} uses a Windows-reserved device name"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_portable_id;

    #[test]
    fn accepts_portable_ids() {
        for value in [
            "pilot-1",
            "lab_run.2026",
            "550e8400-e29b-41d4-a716-446655440000",
        ] {
            validate_portable_id("test id", value).expect("valid id");
        }
    }

    #[test]
    fn rejects_unsafe_or_ambiguous_ids() {
        for value in [
            "",
            ".",
            "..",
            "../outside",
            "nested/path",
            r"nested\\path",
            " leading",
            "trailing ",
            ".hidden",
            "trailing.",
            "unicode-中文",
            "CON",
            "nul.json",
            "COM1",
            "lpt9.log",
        ] {
            assert!(
                validate_portable_id("test id", value).is_err(),
                "unexpectedly accepted {value:?}"
            );
        }
    }
}
