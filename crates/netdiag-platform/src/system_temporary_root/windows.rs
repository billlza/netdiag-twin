use super::SystemTemporaryRootError;
use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use windows_sys::Win32::Storage::FileSystem::GetTempPathW;

const INITIAL_BUFFER_UNITS: usize = 261;
const MAX_PATH_UNITS: usize = 32_767;

pub(super) fn configured_path() -> Result<PathBuf, SystemTemporaryRootError> {
    let mut buffer = vec![0_u16; INITIAL_BUFFER_UNITS];
    loop {
        let capacity =
            u32::try_from(buffer.len()).map_err(|_| SystemTemporaryRootError::InvalidLength {
                units: buffer.len(),
            })?;
        // SAFETY: `buffer` contains `capacity` writable UTF-16 code units and
        // remains allocated for the duration of the Windows API call.
        let returned = unsafe { GetTempPathW(capacity, buffer.as_mut_ptr()) };
        let returned = classify_returned_length(returned, buffer.len())?;
        match returned {
            QueryLength::Complete(length) => return decode_path(&buffer, length),
            QueryLength::Resize(required) => buffer.resize(required, 0),
        }
    }
}

#[derive(Debug)]
enum QueryLength {
    Complete(usize),
    Resize(usize),
}

fn classify_returned_length(
    returned: u32,
    capacity: usize,
) -> Result<QueryLength, SystemTemporaryRootError> {
    if returned == 0 {
        return Err(SystemTemporaryRootError::Query {
            source: io::Error::last_os_error(),
        });
    }
    let returned = usize::try_from(returned)
        .map_err(|_| SystemTemporaryRootError::InvalidLength { units: usize::MAX })?;
    if returned < capacity {
        return Ok(QueryLength::Complete(returned));
    }
    let required = returned
        .checked_add(1)
        .filter(|required| *required <= MAX_PATH_UNITS + 1)
        .ok_or(SystemTemporaryRootError::InvalidLength { units: returned })?;
    Ok(QueryLength::Resize(required))
}

fn decode_path(buffer: &[u16], length: usize) -> Result<PathBuf, SystemTemporaryRootError> {
    if buffer.get(length) != Some(&0) {
        return Err(SystemTemporaryRootError::MissingTerminator {
            units: buffer.len(),
        });
    }
    let path = PathBuf::from(OsString::from_wide(&buffer[..length]));
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(SystemTemporaryRootError::InvalidPath {
            path,
            detail: "the path must be non-empty and absolute",
        });
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_failure_is_structured_instead_of_panicking() {
        let error = classify_returned_length(0, INITIAL_BUFFER_UNITS)
            .expect_err("zero result must be a query error");
        assert!(matches!(error, SystemTemporaryRootError::Query { .. }));
    }

    #[test]
    fn query_resize_is_bounded() {
        assert!(matches!(
            classify_returned_length(300, INITIAL_BUFFER_UNITS),
            Ok(QueryLength::Resize(301))
        ));
        assert!(matches!(
            classify_returned_length((MAX_PATH_UNITS + 1) as u32, INITIAL_BUFFER_UNITS),
            Err(SystemTemporaryRootError::InvalidLength { .. })
        ));
    }

    #[test]
    fn decoded_path_requires_termination_and_an_absolute_nonempty_value() {
        assert!(matches!(
            decode_path(&[b'C' as u16], 0),
            Err(SystemTemporaryRootError::MissingTerminator { .. })
        ));
        assert!(matches!(
            decode_path(&[0], 0),
            Err(SystemTemporaryRootError::InvalidPath { .. })
        ));
        assert!(matches!(
            decode_path(&[b'r' as u16, b'e' as u16, b'l' as u16, 0], 3),
            Err(SystemTemporaryRootError::InvalidPath { .. })
        ));
    }
}
