use super::super::trust::TrustedModelDirectory;
use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use crate::ml::MODEL_CURRENT_FILE_NAME;
use std::ffi::OsStr;
use std::path::Path;

pub(super) fn create_directory_durably(path: &Path) -> Result<TrustedModelDirectory> {
    TrustedModelDirectory::open_or_create_durable(path)
}

pub(super) fn create_child_directory_durably(
    parent: &TrustedModelDirectory,
    name: &OsStr,
) -> Result<TrustedModelDirectory> {
    parent.open_or_create_durable_child(name)
}

pub(super) fn ensure_publication_durability(model_dir: &Path) -> Result<()> {
    validate_publication_durability(cfg!(unix), model_dir)
}

fn validate_publication_durability(supported: bool, model_dir: &Path) -> Result<()> {
    if supported {
        Ok(())
    } else {
        Err(NetdiagError::AtomicPublish {
            path: model_dir.join(MODEL_CURRENT_FILE_NAME),
            phase: AtomicPublishPhase::NotPublished,
            source: Box::new(NetdiagError::InvalidTrace(
                "model generation publication is disabled on this platform because durable directory creation and flush are unavailable"
                    .to_string(),
            )),
        })
    }
}

#[cfg(unix)]
pub(super) fn sync_directory(directory: &TrustedModelDirectory) -> Result<()> {
    directory.sync()
}

#[cfg(not(unix))]
pub(super) fn sync_directory(directory: &TrustedModelDirectory) -> Result<()> {
    ensure_publication_durability(directory.path())
}

#[cfg(unix)]
pub(super) fn sync_parent_directory(directory: &TrustedModelDirectory) -> Result<()> {
    directory.sync_parent()
}

#[cfg(not(unix))]
pub(super) fn sync_parent_directory(directory: &TrustedModelDirectory) -> Result<()> {
    ensure_publication_durability(directory.path())
}

mod parent;

pub(super) use parent::prepare as prepare_parent_directory_durably;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_durability_fails_before_publication_with_the_pointer_path() {
        let model_dir = Path::new("model-root");

        let error = validate_publication_durability(false, model_dir)
            .expect_err("unsupported durability must fail");

        assert!(matches!(
            error,
            NetdiagError::AtomicPublish {
                path,
                phase: AtomicPublishPhase::NotPublished,
                source,
            } if path == model_dir.join(MODEL_CURRENT_FILE_NAME)
                && matches!(*source, NetdiagError::InvalidTrace(_))
        ));
    }
}
