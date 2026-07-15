use super::super::BenchmarkSection;
use crate::error::{NetdiagError, Result};

pub(in crate::benchmark) fn run_adapter_validation_section() -> Result<BenchmarkSection> {
    Err(NetdiagError::Connector(
        "adapter validation is unavailable on this platform because process-group termination and nonblocking output capture cannot yet be proven"
            .to_string(),
    ))
}
