use super::super::super::error::AtomicPublicationLocationObservation;
use crate::{OpenedFileIdentity, TrustedDirectory, opened_file_identity};
use std::ffi::OsStr;
use std::io;

pub(super) fn observe_location(
    result: io::Result<Option<OpenedFileIdentity>>,
    expected: OpenedFileIdentity,
) -> AtomicPublicationLocationObservation {
    match result {
        Ok(Some(current)) if current == expected => {
            AtomicPublicationLocationObservation::SourceFile
        }
        Ok(Some(_)) => AtomicPublicationLocationObservation::DifferentIdentity,
        Ok(None) => AtomicPublicationLocationObservation::Missing,
        Err(source) => AtomicPublicationLocationObservation::InspectionFailed { source },
    }
}

pub(super) fn identity_at(
    directory: &TrustedDirectory,
    name: &OsStr,
) -> io::Result<Option<OpenedFileIdentity>> {
    let file = match super::super::open_read_only(directory, name) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(source),
    };
    opened_file_identity(&file).map(Some)
}
