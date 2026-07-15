use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

pub(super) fn nul_terminated_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows atomic-publish path contains an interior NUL",
        ));
    }
    encoded.push(0);
    Ok(encoded)
}
