use super::PreparedPilot;
use crate::error::Result;

impl PreparedPilot {
    pub(in crate::pilot) fn finish<T>(self, operation: Result<T>) -> Result<T> {
        let Self {
            manifest,
            manifest_dir,
            adapter_boundary,
        } = self;
        drop((manifest, manifest_dir));
        match adapter_boundary {
            Some(boundary) => boundary.finish(operation),
            None => operation,
        }
    }
}
