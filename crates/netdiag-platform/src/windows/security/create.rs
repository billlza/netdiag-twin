use super::descriptor::PrivateSecurityDescriptor;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::{fs::File, io, path::Path, ptr};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS,
};

pub(crate) fn create_private_directory(path: &Path) -> io::Result<bool> {
    let path = nul_terminated_path(path)?;
    let mut security = PrivateSecurityDescriptor::new()?;
    let attributes = security.attributes();
    // SAFETY: the UTF-16 path is NUL-terminated and all security-descriptor
    // allocations remain alive for the duration of CreateDirectoryW.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } != 0 {
        return Ok(true);
    }
    let source = io::Error::last_os_error();
    if source.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) {
        Ok(false)
    } else {
        Err(source)
    }
}

pub(super) fn open_private_file(path: &Path) -> io::Result<File> {
    private_file(path, OPEN_ALWAYS, FILE_SHARE_READ | FILE_SHARE_WRITE)
}

pub(super) fn create_new_private_file(path: &Path) -> io::Result<File> {
    private_file(path, CREATE_NEW, 0)
}

fn private_file(path: &Path, disposition: u32, share_mode: u32) -> io::Result<File> {
    let path = nul_terminated_path(path)?;
    let mut security = PrivateSecurityDescriptor::new()?;
    let attributes = security.attributes();
    // SAFETY: the path and security attributes remain valid for the entire
    // call. Opening the final component itself prevents following a reparse.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            share_mode,
            &attributes,
            disposition,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a unique owned handle, which is transferred
    // exactly once into File for RAII closure.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn nul_terminated_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows private-object path contains an interior NUL",
        ));
    }
    encoded.push(0);
    Ok(encoded)
}
