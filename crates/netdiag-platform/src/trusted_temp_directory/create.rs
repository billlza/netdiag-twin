use super::identity::ChildDirectory;
use super::{TrustedDirectory, TrustedTempDirectory, TrustedTempDirectoryError, cleanup, identity};
use crate::open_trusted_directory_chain;
use std::path::Path;

mod name;
pub(in crate::trusted_temp_directory) mod platform;
use name::{random_name, validate_generated_name, validate_prefix};
use platform::trusted_root_path;
pub(in crate::trusted_temp_directory) use platform::{create_candidate, validate_root};

const MAX_CREATE_ATTEMPTS: usize = 128;

pub(super) fn create(prefix: &str) -> Result<TrustedTempDirectory, TrustedTempDirectoryError> {
    let root_path = trusted_root_path()?;
    let mut next_name = || random_name(prefix);
    let mut create_entry = |path: &Path| create_candidate(path);
    let mut after_create = |_: &Path| {};
    create_with(
        prefix,
        &root_path,
        &mut next_name,
        &mut create_entry,
        &mut after_create,
    )
}

pub(super) fn create_with(
    prefix: &str,
    root_path: &Path,
    next_name: &mut dyn FnMut() -> Result<String, TrustedTempDirectoryError>,
    create_entry: &mut dyn FnMut(&Path) -> Result<bool, TrustedTempDirectoryError>,
    after_create: &mut dyn FnMut(&Path),
) -> Result<TrustedTempDirectory, TrustedTempDirectoryError> {
    validate_prefix(prefix)?;
    let root = open_trusted_directory_chain(root_path).map_err(|source| {
        TrustedTempDirectoryError::Trust {
            context: "trusted temporary root open",
            path: root_path.to_path_buf(),
            source,
        }
    })?;
    validate_root(&root)?;

    for _ in 0..MAX_CREATE_ATTEMPTS {
        let name = next_name()?;
        validate_generated_name(prefix, &name)?;
        let path = root.resolved_path().join(name);
        if !create_entry(&path)? {
            continue;
        }
        after_create(&path);
        let prepared = prepare_child(&root, &path);
        return match prepared {
            Ok(child) => Ok(TrustedTempDirectory {
                path,
                root: Some(root),
                child: Some(child),
            }),
            Err(error) => {
                drop(root);
                Err(cleanup::after_creation_failure(path, error))
            }
        };
    }
    Err(TrustedTempDirectoryError::NameCollisionLimit {
        root: root.resolved_path().to_path_buf(),
    })
}

fn prepare_child(
    root: &TrustedDirectory,
    path: &Path,
) -> Result<ChildDirectory, TrustedTempDirectoryError> {
    let mut after_open = || {};
    prepare_child_with(root, path, &mut after_open)
}

pub(super) fn prepare_child_with(
    root: &TrustedDirectory,
    path: &Path,
    after_open: &mut dyn FnMut(),
) -> Result<ChildDirectory, TrustedTempDirectoryError> {
    let child = identity::open(root, path)?;
    after_open();
    identity::validate(root, &child, path)?;
    Ok(child)
}
