use crate::error::{IoContext, Result};
use crate::storage::{
    BoundAtomicFileTarget, NoClobberDisposition, typed_json::PreparedJson,
    write_file_atomically_noclobber_or_existing_to_bound,
};
use std::io::Write;

pub(in crate::dataset::registration) fn publish_prepared(
    target: &BoundAtomicFileTarget,
    prepared: &PreparedJson,
) -> Result<NoClobberDisposition> {
    write_file_atomically_noclobber_or_existing_to_bound(target, "json", |file| {
        file.write_all(prepared.as_bytes())
            .with_path(target.resolved_path())
    })
    .map(|(disposition, ())| disposition)
}
