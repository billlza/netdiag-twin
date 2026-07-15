use super::prepared::PreparedSnapshotFile;
use super::snapshot::SourceSnapshot;
use super::{BundleArchive, EvidenceBundleFile, record_file, reserve_zip_path, zip_error};
use crate::error::{IoContext, NetdiagError, Result};
use crate::models::TopologyModel;
use crate::report::Report;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

impl BundleArchive {
    pub(in crate::evidence_bundle) fn add_snapshot_files(
        &mut self,
        files: &mut [PreparedSnapshotFile],
    ) -> Result<()> {
        for prepared in files {
            self.add_snapshot(&prepared.key, &mut prepared.source, &prepared.zip_path)?;
        }
        Ok(())
    }

    fn add_snapshot(
        &mut self,
        key: &str,
        source: &mut SourceSnapshot,
        raw_zip_path: &str,
    ) -> Result<()> {
        self.budget
            .validate_declared_source(&source.source_path, source.digest.bytes)?;
        source
            .file
            .seek(SeekFrom::Start(0))
            .with_path(&source.source_path)?;
        let zip_path = reserve_zip_path(raw_zip_path, &mut self.used_paths)?;
        self.zip
            .start_file(&zip_path, self.options)
            .map_err(zip_error)?;
        let archived =
            self.budget
                .copy_source(&mut source.file, &source.source_path, &mut self.zip)?;
        if archived.bytes != source.digest.bytes || archived.sha256 != source.digest.sha256_hex() {
            return Err(NetdiagError::InvalidTrace(format!(
                "immutable evidence snapshot changed while it was archived: {}",
                source.source_path.display()
            )));
        }
        record_file(&mut self.manifest, key, source, zip_path, archived);
        Ok(())
    }

    pub(in crate::evidence_bundle) fn add_topology_snapshots(
        &mut self,
        report_snapshot: &mut SourceSnapshot,
    ) -> Result<()> {
        let report_bytes = read_snapshot_bytes(report_snapshot)?;
        let report: Report = crate::strict_json::from_slice(&report_bytes).map_err(|source| {
            NetdiagError::InvalidTrace(format!(
                "evidence report snapshot is invalid at {}: {}",
                report_snapshot.source_path.display(),
                crate::strict_json::error_summary(&source)
            ))
        })?;
        if let Some(what_if) = report.what_if {
            if let Some(topology) = what_if.topology_snapshot {
                self.add_virtual_topology("topology", "topology.json", &topology)?;
            }
            if let Some(topology) = what_if.modified_topology_snapshot {
                self.add_virtual_topology(
                    "modified_topology",
                    "modified_topology.json",
                    &topology,
                )?;
            }
        }
        Ok(())
    }

    fn add_virtual_topology(
        &mut self,
        key: &str,
        raw_zip_path: &str,
        topology: &TopologyModel,
    ) -> Result<()> {
        let zip_path = reserve_zip_path(raw_zip_path, &mut self.used_paths)?;
        let bytes = serde_json::to_vec_pretty(topology)?;
        self.zip
            .start_file(&zip_path, self.options)
            .map_err(zip_error)?;
        let digest = self
            .budget
            .write_bytes(&bytes, Path::new("report.what_if"), &mut self.zip)?;
        self.manifest.files.push(EvidenceBundleFile {
            key: key.to_string(),
            source_path: "report.what_if".to_string(),
            zip_path,
            bytes: digest.bytes,
            sha256: digest.sha256,
        });
        Ok(())
    }
}

fn read_snapshot_bytes(snapshot: &mut SourceSnapshot) -> Result<Vec<u8>> {
    snapshot
        .file
        .seek(SeekFrom::Start(0))
        .with_path(&snapshot.source_path)?;
    let expected = usize::try_from(snapshot.digest.bytes).map_err(|_| {
        NetdiagError::InvalidTrace(format!(
            "evidence report snapshot is too large for this platform: {}",
            snapshot.source_path.display()
        ))
    })?;
    let limit = snapshot.digest.bytes.checked_add(1).ok_or_else(|| {
        NetdiagError::InvalidTrace("evidence report snapshot byte limit overflowed".to_string())
    })?;
    let mut bytes = Vec::with_capacity(expected);
    snapshot
        .file
        .by_ref()
        .take(limit)
        .read_to_end(&mut bytes)
        .with_path(&snapshot.source_path)?;
    if bytes.len() != expected {
        return Err(NetdiagError::InvalidTrace(format!(
            "immutable evidence report snapshot changed before inspection: {}",
            snapshot.source_path.display()
        )));
    }
    Ok(bytes)
}
