mod current;
mod resolution;

use crate::error::{NetdiagError, Result};
#[cfg(test)]
use crate::ml::MODEL_GENERATIONS_DIR_NAME;
#[cfg(test)]
use std::path::{Path, PathBuf};

pub(super) use current::CurrentDescriptor;
pub(super) use resolution::{
    BundlePaths, resolve as resolve_bundle_paths, resolve_in as resolve_bundle_paths_in,
};

const GENERATION_PREFIX: &str = "generation-";
const UUID_SIMPLE_LENGTH: usize = 32;

#[cfg(test)]
pub(super) fn generation_root(model_dir: &Path) -> PathBuf {
    model_dir.join(MODEL_GENERATIONS_DIR_NAME)
}

pub(super) fn new_generation_name() -> String {
    format!("{GENERATION_PREFIX}{}", uuid::Uuid::new_v4().simple())
}

pub(super) fn validate_generation_name(name: &str) -> Result<()> {
    let Some(uuid) = name.strip_prefix(GENERATION_PREFIX) else {
        return Err(invalid_generation(name));
    };
    if uuid.len() != UUID_SIMPLE_LENGTH
        || !uuid
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_generation(name));
    }
    Ok(())
}

fn invalid_generation(name: &str) -> NetdiagError {
    NetdiagError::Ml(format!(
        "model current descriptor contains invalid generation name {name:?}"
    ))
}
