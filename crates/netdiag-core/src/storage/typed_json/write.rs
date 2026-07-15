use super::PreparedJson;
use crate::error::{IoContext, Result};
use crate::storage::{
    BoundAtomicFileTarget, write_file_atomically, write_file_atomically_to_bound,
};
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

pub(crate) fn save_json_atomic_bounded<T: Serialize + ?Sized>(
    path: impl AsRef<Path>,
    value: &T,
    max_bytes: u64,
    kind: &str,
) -> Result<PathBuf> {
    save_prepared_json_atomic(path, super::prepare_json_bounded(value, max_bytes, kind)?)
}

pub(crate) fn save_prepared_json_atomic(
    path: impl AsRef<Path>,
    prepared: PreparedJson,
) -> Result<PathBuf> {
    let path = path.as_ref();
    write_file_atomically(path, "json", |file| {
        file.write_all(prepared.as_bytes()).with_path(path)
    })
    .map(|(path, ())| path)
}

pub(crate) fn save_prepared_json_atomic_to_bound(
    target: &BoundAtomicFileTarget,
    prepared: PreparedJson,
) -> Result<()> {
    write_file_atomically_to_bound(target, target.resolved_path(), "json", |file| {
        file.write_all(prepared.as_bytes())
            .with_path(target.resolved_path())
    })
    .map(|_| ())
}
