#[cfg(unix)]
mod schema_validation;
#[cfg(unix)]
mod unix;
#[cfg(not(unix))]
mod unsupported;

#[cfg(unix)]
pub(super) use unix::run_adapter_validation_section;
#[cfg(not(unix))]
pub(super) use unsupported::run_adapter_validation_section;

#[cfg(all(test, unix))]
mod tests;
