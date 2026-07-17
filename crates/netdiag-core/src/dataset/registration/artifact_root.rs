use super::super::DatasetRegisterOptions;
use super::super::registration_snapshot::RegistrationSnapshot;
use super::super::trusted_root::TrustedDatasetRoot;
use crate::error::Result;
use crate::storage::{
    ArtifactRootCapability, prepare_artifact_root, with_artifact_root_capability,
};

pub(super) fn open(
    options: &DatasetRegisterOptions,
) -> Result<(ArtifactRootCapability, TrustedDatasetRoot)> {
    let capability = prepare_artifact_root(&options.artifacts)?;
    let root = with_artifact_root_capability(&capability, |_| {
        TrustedDatasetRoot::open_durable(&options.artifacts.join("datasets"))
    })?;
    Ok((capability, root))
}

pub(super) fn finish<T>(
    capability: &ArtifactRootCapability,
    trusted_root: &TrustedDatasetRoot,
    snapshot: RegistrationSnapshot,
    result: Result<T>,
) -> Result<T> {
    let result = snapshot.finish_registration(result);
    let result = trusted_root.finish(result);
    with_artifact_root_capability(capability, |_| result)
}
