#[cfg(unix)]
mod unix;
#[cfg(not(any(unix, windows)))]
mod unsupported;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub(super) use unix::*;
#[cfg(not(any(unix, windows)))]
pub(super) use unsupported::*;
#[cfg(windows)]
pub(super) use windows::*;
