use crate::error::NetdiagError;
use netdiag_platform::DirectoryTrustError;
use std::path::Path;

pub(super) fn open_error(path: &Path, source: DirectoryTrustError) -> NetdiagError {
    let path = path.display();
    match source {
        DirectoryTrustError::UntrustedSymlink { .. } => NetdiagError::InvalidTrace(format!(
            "adapter endpoint must not contain symbolic links: {path}"
        )),
        DirectoryTrustError::Inspect {
            source: inspect_source,
            ..
        } if inspect_source.kind() == std::io::ErrorKind::NotFound => {
            NetdiagError::InvalidTrace(format!("adapter file does not exist: {path}"))
        }
        DirectoryTrustError::NotRegularFile { .. } => {
            NetdiagError::InvalidTrace(format!("adapter endpoint is not a regular file: {path}"))
        }
        source => NetdiagError::FilesystemTrust {
            context: "adapter source path",
            source,
        },
    }
}
