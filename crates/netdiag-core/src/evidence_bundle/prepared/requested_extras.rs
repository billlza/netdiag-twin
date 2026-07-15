use super::super::snapshot::MAX_SNAPSHOT_SOURCES;
use super::super::source::open_required_source;
use super::super::stream::{MAX_BUNDLE_BYTES, MAX_SOURCE_FILE_BYTES};
use super::super::{EvidenceBundleExtraFile, MANIFEST_ZIP_PATH, README_ZIP_PATH, reserve_zip_path};
use crate::error::{NetdiagError, Result};
use std::collections::BTreeSet;

pub(in crate::evidence_bundle) fn validate(extras: &[EvidenceBundleExtraFile]) -> Result<()> {
    let mut used_paths =
        BTreeSet::from([README_ZIP_PATH.to_string(), MANIFEST_ZIP_PATH.to_string()]);
    let mut bytes = 0_u64;
    for (index, extra) in extras.iter().enumerate() {
        if index >= MAX_SNAPSHOT_SOURCES {
            return Err(NetdiagError::InvalidTrace(format!(
                "evidence bundle source count limit exceeded: {} > {MAX_SNAPSHOT_SOURCES}",
                index + 1
            )));
        }
        reserve_zip_path(&extra.zip_path, &mut used_paths)?;
        let source = open_required_source(&extra.path, None)?;
        let source_bytes = source.opened_metadata.len();
        if source_bytes > MAX_SOURCE_FILE_BYTES {
            return Err(NetdiagError::InvalidTrace(format!(
                "evidence bundle single source file byte limit exceeded for {}: {source_bytes} > {MAX_SOURCE_FILE_BYTES}",
                source.canonical_path.display()
            )));
        }
        bytes = bytes.checked_add(source_bytes).ok_or_else(|| {
            NetdiagError::InvalidTrace("evidence snapshot byte count overflowed".to_string())
        })?;
        if bytes > MAX_BUNDLE_BYTES {
            return Err(NetdiagError::InvalidTrace(format!(
                "evidence bundle total source snapshot byte limit exceeded for {}: {bytes} > {MAX_BUNDLE_BYTES}",
                source.canonical_path.display()
            )));
        }
    }
    Ok(())
}
