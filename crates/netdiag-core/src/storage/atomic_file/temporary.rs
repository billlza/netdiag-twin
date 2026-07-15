use std::ffi::{OsStr, OsString};
use std::path::Path;

mod staged;
pub(crate) use staged::{NoClobberDisposition, StagedAtomicFile};

pub(super) fn temporary_name(target: &OsStr, default_extension: &str) -> OsString {
    let target = Path::new(target);
    let extension = target.extension().and_then(|value| value.to_str());
    let extension = extension.unwrap_or(default_extension);
    target
        .with_extension(format!("{extension}.{}.tmp", uuid::Uuid::new_v4().simple()))
        .into_os_string()
}

#[cfg(test)]
mod tests;
