use std::io;
use std::path::Path;
use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};

mod path;
use path::nul_terminated_path;

/// Replaces `target` with `temporary` and waits for the Windows move operation
/// to reach durable storage before returning success.
pub fn replace_file_write_through(temporary: &Path, target: &Path) -> io::Result<()> {
    move_file_write_through(temporary, target, MOVEFILE_REPLACE_EXISTING)
}

/// Publishes `temporary` only when `target` does not exist and waits for the
/// Windows move operation to reach durable storage before returning success.
pub fn move_file_noreplace_write_through(temporary: &Path, target: &Path) -> io::Result<()> {
    move_file_write_through(temporary, target, 0)
}

fn move_file_write_through(temporary: &Path, target: &Path, behavior: u32) -> io::Result<()> {
    let temporary = nul_terminated_path(temporary)?;
    let target = nul_terminated_path(target)?;
    let flags = behavior | MOVEFILE_WRITE_THROUGH;

    // SAFETY: both buffers are NUL-terminated UTF-16 paths and remain alive for
    // the entire call. The flags are a documented MoveFileExW combination.
    let result = unsafe { MoveFileExW(temporary.as_ptr(), target.as_ptr(), flags) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
