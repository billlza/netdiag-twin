use super::DatasetInputSnapshot;
use crate::dataset::registration_snapshot::RegistrationSnapshot;
use crate::dataset::trusted_root::TrustedDatasetRoot;
use crate::error::Result;
use crate::managed_temp_directory::ManagedTempDirectory;
use std::path::Path;

pub(super) fn capture(
    source: &Path,
    after_staging_created: impl FnOnce(&Path),
) -> Result<DatasetInputSnapshot> {
    let staging =
        ManagedTempDirectory::create("dataset input snapshot staging", "netdiag-dataset-input-")?;
    after_staging_created(staging.path());
    let captured = (|| {
        let trusted_root = TrustedDatasetRoot::open(staging.path())?;
        let snapshot = RegistrationSnapshot::capture(source, &trusted_root, || {}, || {})?;
        trusted_root.validate()?;
        Ok((snapshot, trusted_root))
    })();
    match captured {
        Ok((snapshot, trusted_root)) => Ok(DatasetInputSnapshot {
            snapshot,
            trusted_root,
            staging,
        }),
        Err(error) => staging.finish(Err(error)),
    }
}
