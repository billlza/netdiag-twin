use crate::error::{NetdiagError, Result};
#[cfg(unix)]
use crate::{error::IoContext, storage::atomic_file::target::BoundAtomicFileTarget};
use std::path::Path;

mod bound;
pub(crate) use bound::{BoundFileRemovalFailure, remove_bound_file_durably};

pub(crate) fn remove_file_durably(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let target = BoundAtomicFileTarget::bind_existing_parent(path)?;
        match netdiag_platform::remove_file_at(target.directory(), target.target_name()) {
            Ok(()) => target
                .directory()
                .as_file()
                .sync_all()
                .with_path(target.directory().resolved_path()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(NetdiagError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }
    #[cfg(windows)]
    {
        Err(NetdiagError::InvalidTrace(format!(
            "crash-durable file removal is unavailable on Windows: {}",
            path.display()
        )))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(NetdiagError::InvalidTrace(format!(
            "crash-durable file removal is unsupported on this platform: {}",
            path.display()
        )))
    }
}
