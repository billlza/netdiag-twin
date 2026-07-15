use super::*;
use std::error::Error;

#[test]
fn local_app_data_path_is_absolute_without_environment_fallback() {
    let path = current_user_local_app_data_path().expect("current-user LocalAppData");
    assert!(path.is_absolute());
}

#[test]
fn query_errors_preserve_the_hresult_source() {
    let source = WindowsHresultError::new(unchecked_hresult(0x8007_0005));
    let error = CurrentUserLocalAppDataError::Query { source };
    assert_eq!(source.code(), unchecked_hresult(0x8007_0005));
    assert!(matches!(error.source(), Some(inner) if inner.to_string().contains("80070005")));
}

#[test]
fn missing_and_overlong_known_folder_paths_fail_explicitly() {
    let missing = KnownFolderAllocation(std::ptr::null_mut());
    assert!(matches!(
        missing.path(),
        Err(CurrentUserLocalAppDataError::MissingPath)
    ));

    let mut overlong = vec![b'x' as u16; MAX_PATH_UNITS + 1];
    overlong.push(0);
    assert!(matches!(
        // SAFETY: the test buffer has MAX_PATH_UNITS + 2 live code units.
        unsafe { bounded_wide_length(overlong.as_mut_ptr()) },
        Err(CurrentUserLocalAppDataError::PathTooLong { .. })
    ));
}

fn unchecked_hresult(value: u32) -> i32 {
    i32::from_ne_bytes(value.to_ne_bytes())
}
