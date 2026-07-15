use super::super::errors::trust_error;
use super::super::platform::validate_namespace;
use crate::error::Result;
use netdiag_platform::{TrustedDirectory, open_or_create_trusted_directory_chain};
use std::path::Path;

pub(super) fn open(path: &Path) -> Result<TrustedDirectory> {
    let namespace = open_or_create_trusted_directory_chain(path).map_err(trust_error)?;
    validate_namespace(&namespace)?;
    Ok(namespace)
}
