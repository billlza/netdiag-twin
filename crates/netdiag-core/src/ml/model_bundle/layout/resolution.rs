use super::super::trust::TrustedModelDirectory;
use super::super::{MAX_MODEL_FILE_BYTES, MAX_MODEL_MANIFEST_BYTES};
use super::current;
use crate::error::{NetdiagError, Result};
use crate::ml::{
    MODEL_CURRENT_FILE_NAME, MODEL_FILE_NAME, MODEL_GENERATIONS_DIR_NAME, MODEL_MANIFEST_FILE_NAME,
};
use crate::storage::read_stable_regular_file_bounded;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub(in crate::ml::model_bundle) struct BundlePaths {
    pub(in crate::ml::model_bundle) model_path: PathBuf,
    pub(in crate::ml::model_bundle) manifest_path: PathBuf,
    pub(in crate::ml::model_bundle) generation: Option<String>,
    bundle_root: TrustedModelDirectory,
    generations_root: Option<TrustedModelDirectory>,
    generation_root: Option<TrustedModelDirectory>,
}

impl BundlePaths {
    pub(in crate::ml::model_bundle) fn root_path(&self) -> &Path {
        self.bundle_root.path()
    }

    pub(in crate::ml::model_bundle) fn validate(&self) -> Result<()> {
        let result = (|| {
            self.bundle_root.validate()?;
            if let Some(directory) = &self.generations_root {
                directory.validate()?;
            }
            if let Some(directory) = &self.generation_root {
                directory.validate()?;
            }
            Ok(())
        })();
        self.finish(result)
    }

    pub(in crate::ml::model_bundle) fn finish<T>(&self, result: Result<T>) -> Result<T> {
        let result = match &self.generation_root {
            Some(directory) => directory.finish(result),
            None => result,
        };
        let result = match &self.generations_root {
            Some(directory) => directory.finish(result),
            None => result,
        };
        self.bundle_root.finish(result)
    }
}

pub(in crate::ml::model_bundle) fn resolve(model_dir: &Path) -> Result<Option<BundlePaths>> {
    match fs::symlink_metadata(model_dir) {
        Ok(_) => resolve_in(TrustedModelDirectory::open(model_dir)?),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(crate::error::NetdiagError::Io {
            path: model_dir.to_path_buf(),
            source,
        }),
    }
}

pub(in crate::ml::model_bundle) fn resolve_in(
    bundle_root: TrustedModelDirectory,
) -> Result<Option<BundlePaths>> {
    bundle_root.validate()?;
    let result = (|| {
        let current_path = bundle_root.path().join(MODEL_CURRENT_FILE_NAME);
        let Some(descriptor) = current::read(&bundle_root, &current_path)? else {
            return resolve_legacy(bundle_root.clone());
        };
        let generations =
            bundle_root.open_existing_child(OsStr::new(MODEL_GENERATIONS_DIR_NAME))?;
        let generation = generations.open_existing_child(OsStr::new(&descriptor.generation))?;
        Ok(Some(BundlePaths {
            model_path: generation.path().join(MODEL_FILE_NAME),
            manifest_path: generation.path().join(MODEL_MANIFEST_FILE_NAME),
            generation: Some(descriptor.generation),
            bundle_root: bundle_root.clone(),
            generations_root: Some(generations),
            generation_root: Some(generation),
        }))
    })();
    bundle_root.finish(result)
}

fn resolve_legacy(bundle_root: TrustedModelDirectory) -> Result<Option<BundlePaths>> {
    bundle_root.validate()?;
    let model_path = bundle_root.path().join(MODEL_FILE_NAME);
    let manifest_path = bundle_root.path().join(MODEL_MANIFEST_FILE_NAME);
    let result = (|| match (
        read_stable_regular_file_bounded(&model_path, MAX_MODEL_FILE_BYTES)?.is_some(),
        read_stable_regular_file_bounded(&manifest_path, MAX_MODEL_MANIFEST_BYTES)?.is_some(),
    ) {
        (false, false) => Ok(None),
        (true, true) => Ok(Some(BundlePaths {
            model_path,
            manifest_path,
            generation: None,
            bundle_root: bundle_root.clone(),
            generations_root: None,
            generation_root: None,
        })),
        (true, false) => Err(incomplete_legacy("model manifest", &manifest_path)),
        (false, true) => Err(incomplete_legacy("model file", &model_path)),
    })();
    bundle_root.finish(result)
}

fn incomplete_legacy(missing: &str, path: &Path) -> NetdiagError {
    NetdiagError::Ml(format!(
        "legacy model bundle is incomplete: {missing} is missing: {}",
        path.display()
    ))
}
