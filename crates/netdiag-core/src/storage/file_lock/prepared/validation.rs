use super::super::errors::trust_error;
use super::super::platform::{validate_coordination_file, validate_namespace};
use super::PreparedLock;
use crate::error::Result;
use std::fs::File;

pub(super) fn validate(prepared: &PreparedLock) -> Result<()> {
    prepared
        .target_parent
        .validate_identity()
        .map_err(trust_error)?;
    prepared
        .target_parent
        .validate_private_security()
        .map_err(trust_error)?;
    prepared
        .namespace
        .validate_identity()
        .map_err(trust_error)?;
    validate_namespace(&prepared.namespace)
}

pub(super) fn validate_lock_file(prepared: &PreparedLock, file: &File) -> Result<()> {
    validate_coordination_file(&prepared.namespace, &prepared.lock_path, file)
}
