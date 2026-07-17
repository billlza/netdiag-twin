use std::path::PathBuf;

mod display;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowsHresultError {
    code: i32,
}

impl WindowsHresultError {
    pub(super) fn new(code: i32) -> Self {
        Self { code }
    }

    pub fn code(self) -> i32 {
        self.code
    }
}

#[derive(Debug)]
pub enum CurrentUserLocalAppDataError {
    Query { source: WindowsHresultError },
    MissingPath,
    PathTooLong { max_units: usize },
    NotAbsolute { path: PathBuf },
}
