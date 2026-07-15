use super::super::preserve_failed_noclobber_state;
use crate::dataset::DatasetManifest;
use crate::error::{AtomicPublishPhase, IoContext, NetdiagError, Result};
use crate::storage::{self, BoundAtomicFileTarget, NoClobberDisposition};
use std::io::Write;

pub(in crate::dataset::split_publication) fn verify(
    target: &BoundAtomicFileTarget,
    expected: &DatasetManifest,
) -> Result<()> {
    let actual = storage::typed_json::read_required_stable_json_bounded_at::<DatasetManifest>(
        target,
        storage::typed_json::MAX_DATASET_MANIFEST_BYTES,
        "committed dataset split manifest",
    )?;
    if actual != *expected {
        return Err(NetdiagError::InvalidTrace(format!(
            "committed dataset split manifest conflicts with its transaction receipt at {}",
            target.resolved_path().display()
        )));
    }
    Ok(())
}

pub(in crate::dataset::split_publication) fn publish(
    target: &BoundAtomicFileTarget,
    expected: &DatasetManifest,
) -> Result<()> {
    let prepared = storage::typed_json::prepare_json_bounded(
        expected,
        storage::typed_json::MAX_DATASET_MANIFEST_BYTES,
        "dataset split manifest",
    )?;
    let publication =
        storage::write_file_atomically_noclobber_or_existing_to_bound(target, "json", |file| {
            file.write_all(prepared.as_bytes())
                .with_path(target.resolved_path())
        });
    match publication {
        Ok((NoClobberDisposition::Created, ())) => {
            created_verification(target, verify(target, expected))
        }
        Ok((NoClobberDisposition::Existing, ())) => verify(target, expected),
        Err(error) => Err(preserve_failed_noclobber_state(target, error, || {
            verify(target, expected)
        })),
    }
}

fn created_verification(target: &BoundAtomicFileTarget, result: Result<()>) -> Result<()> {
    result.map_err(|error| {
        NetdiagError::atomic_publish(
            target.resolved_path().to_path_buf(),
            AtomicPublishPhase::Published,
            error,
        )
    })
}

#[cfg(test)]
mod tests;
