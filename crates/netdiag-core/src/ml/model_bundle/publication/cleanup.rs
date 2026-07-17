use super::super::layout::validate_generation_name;
use super::super::trust::TrustedModelDirectory;
use super::MAX_GENERATION_ENTRIES;
use super::durability::{sync_directory, sync_parent_directory};
use crate::error::{IoContext, NetdiagError, Result};
use crate::ml::{MODEL_FILE_NAME, MODEL_MANIFEST_FILE_NAME};
use crate::storage::remove_file_durably;
use std::ffi::OsStr;
use std::fs;

pub(super) fn failed_generation(
    generation_dir: &TrustedModelDirectory,
    error: NetdiagError,
) -> NetdiagError {
    let cleanup =
        generation_dir
            .validate()
            .and_then(|()| match fs::remove_dir_all(generation_dir.path()) {
                Ok(()) => sync_parent_directory(generation_dir),
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(NetdiagError::Io {
                    path: generation_dir.path().to_path_buf(),
                    source,
                }),
            });
    match cleanup {
        Ok(()) => error,
        Err(cleanup) => error.with_secondary_failure(
            "model generation write failed",
            "cleanup of the incomplete model generation also failed",
            cleanup,
        ),
    }
}

pub(super) fn noncurrent_generations(
    generations: &TrustedModelDirectory,
    current_generation: Option<&str>,
) -> Result<()> {
    generations.validate()?;
    let result = (|| {
        let mut entries = Vec::new();
        for entry in fs::read_dir(generations.path()).with_path(generations.path())? {
            if entries.len() == MAX_GENERATION_ENTRIES {
                return Err(NetdiagError::Ml(format!(
                    "model generations root {} exceeds the strict {} entry cleanup bound",
                    generations.path().display(),
                    MAX_GENERATION_ENTRIES
                )));
            }
            let entry = entry.with_path(generations.path())?;
            let name = entry.file_name().into_string().map_err(|_| {
                NetdiagError::Ml(format!(
                    "model generation entry is not valid UTF-8 under {}",
                    generations.path().display()
                ))
            })?;
            validate_generation_name(&name)?;
            let directory = generations.open_existing_child(OsStr::new(&name))?;
            entries.push((name, directory));
        }
        let mut removed = false;
        for (name, directory) in entries {
            if Some(name.as_str()) != current_generation {
                directory.validate()?;
                fs::remove_dir_all(directory.path()).with_path(directory.path())?;
                generations.validate()?;
                removed = true;
            }
        }
        if removed {
            sync_directory(generations)?;
        }
        Ok(())
    })();
    generations.finish(result)
}

pub(super) fn legacy_files(model_dir: &TrustedModelDirectory) -> Result<()> {
    model_dir.validate()?;
    let result = (|| {
        for path in [
            model_dir.path().join(MODEL_FILE_NAME),
            model_dir.path().join(MODEL_MANIFEST_FILE_NAME),
        ] {
            remove_file_durably(&path)?;
        }
        Ok(())
    })();
    model_dir.finish(result)
}
