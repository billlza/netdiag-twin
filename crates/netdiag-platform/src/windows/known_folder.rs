use std::ffi::{OsString, c_void};
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::{ptr, slice};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath};
use windows_sys::core::PWSTR;

mod error;
pub use error::{CurrentUserLocalAppDataError, WindowsHresultError};

#[cfg(test)]
mod tests;

const MAX_PATH_UNITS: usize = 32_767;

/// Returns the current process user's LocalAppData known-folder path.
///
/// The returned path is not canonicalized: consumers must pass it through the
/// trusted-directory boundary so reparse components remain visible and fail closed.
pub fn current_user_local_app_data_path() -> Result<PathBuf, CurrentUserLocalAppDataError> {
    let mut raw_path: PWSTR = ptr::null_mut();
    // SAFETY: `raw_path` is writable; a null token requests the current user;
    // the returned allocation is immediately owned by `KnownFolderAllocation`.
    let hresult =
        unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, ptr::null_mut(), &mut raw_path) };
    let allocation = KnownFolderAllocation(raw_path);
    if hresult < 0 {
        return Err(CurrentUserLocalAppDataError::Query {
            source: WindowsHresultError::new(hresult),
        });
    }
    let path = allocation.path()?;
    if !path.is_absolute() {
        return Err(CurrentUserLocalAppDataError::NotAbsolute { path });
    }
    Ok(path)
}

struct KnownFolderAllocation(PWSTR);

impl KnownFolderAllocation {
    fn path(&self) -> Result<PathBuf, CurrentUserLocalAppDataError> {
        if self.0.is_null() {
            return Err(CurrentUserLocalAppDataError::MissingPath);
        }
        // SAFETY: a successful SHGetKnownFolderPath call guarantees a live,
        // null-terminated allocation owned by `self`.
        let length = unsafe { bounded_wide_length(self.0) }?;
        if length == 0 {
            return Err(CurrentUserLocalAppDataError::MissingPath);
        }
        // SAFETY: SHGetKnownFolderPath returned a live null-terminated
        // allocation and `bounded_wide_length` found its terminator.
        let wide = unsafe { slice::from_raw_parts(self.0, length) };
        Ok(PathBuf::from(OsString::from_wide(wide)))
    }
}

unsafe fn bounded_wide_length(raw_path: PWSTR) -> Result<usize, CurrentUserLocalAppDataError> {
    for length in 0..=MAX_PATH_UNITS {
        // SAFETY: callers provide a live null-terminated Windows API allocation
        // or a test buffer containing at least MAX_PATH_UNITS + 1 code units.
        if unsafe { *raw_path.add(length) } == 0 {
            return Ok(length);
        }
    }
    Err(CurrentUserLocalAppDataError::PathTooLong {
        max_units: MAX_PATH_UNITS,
    })
}

impl Drop for KnownFolderAllocation {
    fn drop(&mut self) {
        // SAFETY: SHGetKnownFolderPath allocated this pointer with the COM task
        // allocator. CoTaskMemFree accepts null and is required on every path.
        unsafe { CoTaskMemFree(self.0.cast::<c_void>()) };
    }
}
