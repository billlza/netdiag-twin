#[cfg(unix)]
mod unix;
#[cfg(not(any(unix, windows)))]
mod unsupported;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub(in crate::trusted_temp_directory) use unix::*;
#[cfg(not(any(unix, windows)))]
pub(in crate::trusted_temp_directory) use unsupported::*;
#[cfg(windows)]
pub(in crate::trusted_temp_directory) use windows::*;

pub(in crate::trusted_temp_directory::create) fn trusted_root_path()
-> Result<std::path::PathBuf, super::TrustedTempDirectoryError> {
    match crate::system_temporary_root_path() {
        Ok(path) => Ok(path),
        Err(crate::SystemTemporaryRootError::UnsupportedPlatform) => {
            Err(super::TrustedTempDirectoryError::UnsupportedPlatform)
        }
        Err(source) => Err(super::TrustedTempDirectoryError::SystemTemporaryRoot { source }),
    }
}
