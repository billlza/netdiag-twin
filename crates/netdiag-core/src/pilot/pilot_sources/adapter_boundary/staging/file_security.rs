use crate::error::{IoContext, Result};
use std::fs;
use std::path::Path;

pub(super) fn set_read_only(path: &Path) -> Result<()> {
    let mut permissions = path.metadata().with_path(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).with_path(path)
}
