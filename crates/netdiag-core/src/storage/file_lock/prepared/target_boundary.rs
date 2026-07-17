use super::super::errors::trust_error;
use crate::error::{NetdiagError, Result};
use netdiag_platform::{DirectoryTrustError, TrustedDirectory, open_trusted_directory_chain};
use std::io::ErrorKind;
use std::path::Path;

pub(super) fn ensure_outside_namespace(
    target_parent: &Path,
    namespace: &TrustedDirectory,
) -> Result<()> {
    let namespace_identity = namespace.coordination_identity().map_err(trust_error)?;
    let mut candidate = Some(target_parent);
    while let Some(path) = candidate {
        match open_trusted_directory_chain(path) {
            Ok(existing) => {
                let same_identity =
                    existing.coordination_identity().map_err(trust_error)? == namespace_identity;
                if same_identity
                    || existing
                        .resolved_path()
                        .starts_with(namespace.resolved_path())
                {
                    return Err(NetdiagError::InvalidTrace(format!(
                        "coordination lock targets must not be inside the private lock namespace: {}",
                        target_parent.display()
                    )));
                }
            }
            Err(DirectoryTrustError::Inspect { source, .. })
                if source.kind() == ErrorKind::NotFound => {}
            Err(source) => return Err(trust_error(source)),
        }
        candidate = path.parent();
    }
    Ok(())
}
