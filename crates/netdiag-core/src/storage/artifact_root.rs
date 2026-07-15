mod clear;
mod migration;
mod ownership;
mod path_validation;
mod run_publication;
mod staging;

pub use clear::clear_run_history;
pub use ownership::ensure_artifact_root_owned;
pub(crate) use ownership::{
    ArtifactRootCapability, OwnedArtifactRoot, migrate_legacy_artifact_root_with_validator,
    prepare_artifact_root, with_artifact_root_capability, with_owned_artifact_root,
};
pub use path_validation::validate_artifact_root_path;
pub(crate) use run_publication::{
    abandon_not_published as abandon_run_publication_not_published, begin as begin_run_publication,
    complete as complete_run_publication, reconcile_index as reconcile_run_publication_index,
    reconcile_nested_index as reconcile_nested_run_publication_index,
};
pub(crate) use staging::{
    create as create_root_bound_staged_directory, discard as discard_root_bound_staged_directory,
    finish as finish_root_bound_staged_directory,
};

#[cfg(test)]
mod tests;
