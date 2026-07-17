use crate::error::{NetdiagError, Result};
use crate::storage::BoundAtomicFileTarget;

pub(in crate::dataset::split_publication) fn exists(
    target: &BoundAtomicFileTarget,
) -> Result<bool> {
    exists_with(target, || {
        netdiag_platform::open_file_read_only_at(target.directory(), target.target_name()).map(drop)
    })
}

pub(in crate::dataset::split_publication) fn ensure_absent(
    targets: &[&BoundAtomicFileTarget],
    kind: &str,
) -> Result<()> {
    for target in targets {
        if exists(target)? {
            return Err(NetdiagError::InvalidTrace(format!(
                "dataset split refuses to overwrite {kind}: {}",
                target.resolved_path().display()
            )));
        }
    }
    Ok(())
}

fn exists_with(
    target: &BoundAtomicFileTarget,
    inspect: impl FnOnce() -> std::io::Result<()>,
) -> Result<bool> {
    match inspect() {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(NetdiagError::Io {
            path: target.resolved_path().to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspection_propagates_permission_denied() {
        let temp = tempfile::tempdir().expect("temporary directory");
        let directory = netdiag_platform::open_or_create_trusted_directory_chain(temp.path())
            .expect("trusted directory");
        let target = BoundAtomicFileTarget::from_directory(
            std::sync::Arc::new(directory),
            std::ffi::OsStr::new("inaccessible-partition.jsonl"),
        )
        .expect("bound target");
        let error = exists_with(&target, || {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected permission failure",
            ))
        })
        .expect_err("permission errors must not be treated as absence");

        match error {
            NetdiagError::Io {
                path: actual,
                source,
            } => {
                assert_eq!(actual, target.resolved_path());
                assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
            }
            other => panic!("unexpected error: {other}"),
        }
    }
}
