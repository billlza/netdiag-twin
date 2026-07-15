use super::super::registration_snapshot::RegistrationSnapshot;
use super::super::{
    DatasetRegisterOptions, DatasetRegistration, DatasetRegistry, manifest_dataset_id,
    manifest_for_summary_with_identity, read_dataset_registry_at, read_dataset_summary_from_reader,
};
use super::{manifest, registry_publish};
use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use crate::storage::{BoundAtomicFileTarget, NoClobberDisposition, with_exclusive_bound_file_lock};
use chrono::Utc;
use std::io::BufReader;
use std::path::Path;

mod failure;

pub(super) fn run(
    dataset: &Path,
    options: DatasetRegisterOptions,
    source_opened: impl FnOnce(),
    copy_completed: impl FnOnce(),
    publish_registry: impl FnOnce(
        &BoundAtomicFileTarget,
        &DatasetRegistry,
        registry_publish::PreparedRegistry,
    ) -> Result<()>,
) -> Result<DatasetRegistration> {
    super::super::ensure_publication_supported(&options.artifacts)?;
    let dataset_id = manifest_dataset_id(dataset, &options.metadata)?;
    let (root_capability, registry_root) = super::artifact_root::open(&options)?;
    let registry_target = registry_root.target("registry.json")?;
    with_exclusive_bound_file_lock(&registry_target, || {
        let trusted_root = super::super::trusted_root::TrustedDatasetRoot::open_child(
            &registry_target,
            &dataset_id,
        )?;
        let mut registry_published = false;
        let mut snapshot =
            RegistrationSnapshot::capture(dataset, &trusted_root, source_opened, copy_completed)?;
        let result = (|| {
            let summary =
                read_dataset_summary_from_reader(dataset, BufReader::new(snapshot.reopen()?))?;
            let mut manifest = manifest_for_summary_with_identity(
                dataset,
                summary,
                options.metadata,
                dataset_id,
                snapshot.hash_sha256.clone(),
            );
            let (dataset_target, manifest_target) =
                trusted_root.immutable_targets(&manifest.hash_sha256)?;
            let registered_at = Utc::now();
            let mut registry = read_dataset_registry_at(&registry_target)?;
            registry_publish::ensure_dataset_id_available(&registry, &manifest.dataset_id)?;
            let dataset_path = dataset_target.resolved_path().display().to_string();
            let manifest_path = manifest_target.resolved_path().display().to_string();
            let dataset_was_referenced = registry
                .datasets
                .iter()
                .any(|entry| entry.dataset_path == dataset_path);
            let manifest_was_referenced = registry
                .datasets
                .iter()
                .any(|entry| entry.manifest_path == manifest_path);
            registry_publish::upsert(
                &mut registry,
                &manifest,
                dataset_target.resolved_path(),
                manifest_target.resolved_path(),
                registered_at,
            );
            let prepared_manifest = manifest::prepare(&manifest)?;
            let prepared_registry = registry_publish::prepare(&registry)?;
            snapshot.validate_existing_target_if_present(&dataset_target)?;
            manifest::ensure_existing_compatible_if_present(&manifest_target, &manifest)?;
            trusted_root.validate()?;
            let mut created = Vec::new();
            if snapshot.publish(&trusted_root, &dataset_target, &manifest.hash_sha256)?
                == NoClobberDisposition::Created
                && !dataset_was_referenced
            {
                created.push(dataset_target.clone());
            }
            match manifest::publish_prepared(&manifest_target, &prepared_manifest) {
                Ok(NoClobberDisposition::Created) => {
                    if !manifest_was_referenced {
                        created.push(manifest_target.clone());
                    }
                }
                Ok(NoClobberDisposition::Existing) => {
                    manifest = manifest::existing_compatible(&manifest_target, &manifest)
                        .map_err(|error| trusted_root.rollback_created_files(&created, error))?;
                }
                Err(error) => {
                    return Err(failure::preserve_after_publication_failure(
                        &trusted_root,
                        &manifest_target,
                        &created,
                        error,
                    ));
                }
            }
            trusted_root
                .validate()
                .map_err(|error| trusted_root.rollback_created_files(&created, error))?;
            publish_registry(&registry_target, &registry, prepared_registry).map_err(|error| {
                failure::preserve_after_publication_failure(
                    &trusted_root,
                    &registry_target,
                    &created,
                    error,
                )
            })?;
            registry_published = true;
            Ok(DatasetRegistration {
                schema: "netdiag-dataset-registration/v1".to_string(),
                registered_at,
                dataset_path,
                manifest_path,
                registry_path: registry_target.resolved_path().display().to_string(),
                manifest,
            })
        })();
        let result =
            super::artifact_root::finish(&root_capability, &trusted_root, snapshot, result);
        if registry_published {
            result.map_err(|source| NetdiagError::AtomicPublish {
                path: registry_target.resolved_path().to_path_buf(),
                phase: AtomicPublishPhase::Published,
                source: Box::new(source),
            })
        } else {
            result
        }
    })
}
