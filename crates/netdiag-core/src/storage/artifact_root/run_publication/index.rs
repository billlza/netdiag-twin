use crate::error::Result;
use crate::models::RunIndexEntry;
use crate::storage::typed_json::{
    MAX_RUN_INDEX_BYTES, MAX_RUN_INDEX_ENTRIES, ensure_collection_limit, prepare_json_bounded,
    read_optional_stable_json_bounded_at, save_prepared_json_atomic_to_bound,
};
use crate::storage::{BoundAtomicFileTarget, with_exclusive_bound_file_lock};
use std::ffi::OsStr;
use std::sync::Arc;

pub(super) fn upsert_at(
    directory: &Arc<netdiag_platform::TrustedDirectory>,
    entry: &RunIndexEntry,
) -> Result<()> {
    let target =
        BoundAtomicFileTarget::from_directory(Arc::clone(directory), OsStr::new("run_index.json"))?;
    with_exclusive_bound_file_lock(&target, || {
        let mut entries = match read_optional_stable_json_bounded_at::<Vec<RunIndexEntry>>(
            &target,
            MAX_RUN_INDEX_BYTES,
            "run index",
        )? {
            Some(entries) => {
                ensure_collection_limit("run index", entries.len(), MAX_RUN_INDEX_ENTRIES)?;
                entries
            }
            None => Vec::new(),
        };
        entries.retain(|existing| existing.run_id != entry.run_id);
        entries.insert(0, entry.clone());
        entries.truncate(MAX_RUN_INDEX_ENTRIES);
        save_prepared_json_atomic_to_bound(
            &target,
            prepare_json_bounded(&entries, MAX_RUN_INDEX_BYTES, "run index")?,
        )
    })
}
