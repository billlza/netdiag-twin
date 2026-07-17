use super::super::error::{AtomicPublicationError, published_uncertain};
use crate::TrustedDirectory;

pub(super) fn sync_parent(directory: &TrustedDirectory) -> Result<(), AtomicPublicationError> {
    directory.as_file().sync_all().map_err(published_uncertain)
}
