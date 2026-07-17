#[cfg(any(unix, windows))]
use crate::error::IoContext;
#[cfg(not(any(unix, windows)))]
use crate::error::NetdiagError;
use crate::error::Result;
#[cfg(any(unix, windows))]
use crate::ml::model_bundle::trust::trust_error;
use std::path::Path;

pub(in crate::ml::model_bundle::publication) fn prepare(path: &Path) -> Result<()> {
    #[cfg(any(unix, windows))]
    {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .with_path(Path::new("."))?
                .join(path)
        };
        let directory = netdiag_platform::open_or_create_durable_trusted_directory_chain(&absolute)
            .map_err(trust_error)?;
        directory.validate_identity().map_err(trust_error)?;
        directory.validate_private_security().map_err(trust_error)?;
        directory.validate_identity().map_err(trust_error)?;
        directory.validate_private_security().map_err(trust_error)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(NetdiagError::Ml(
            "model bundle parent directory trust validation is unavailable on this platform"
                .to_string(),
        ))
    }
}
