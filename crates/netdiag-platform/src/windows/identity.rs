use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
};

pub(crate) fn same_file(left: &File, right: &File) -> io::Result<bool> {
    Ok(identity_bytes(left)? == identity_bytes(right)?)
}

pub(crate) fn identity_bytes(file: &File) -> io::Result<[u8; 32]> {
    let mut information = FILE_ID_INFO::default();
    // SAFETY: `information` is valid writable storage and `file` keeps the
    // borrowed operating-system handle alive for the duration of the call.
    let result = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileIdInfo,
            (&mut information as *mut FILE_ID_INFO).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut identity = [0_u8; 32];
    identity[..8].copy_from_slice(b"winfid01");
    identity[8..16].copy_from_slice(&information.VolumeSerialNumber.to_le_bytes());
    identity[16..].copy_from_slice(&information.FileId.Identifier);
    Ok(identity)
}
