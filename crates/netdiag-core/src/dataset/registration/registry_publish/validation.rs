use super::DatasetRegistry;
use crate::error::{NetdiagError, Result};

pub(in crate::dataset::registration) fn ensure_dataset_id_available(
    registry: &DatasetRegistry,
    dataset_id: &str,
) -> Result<()> {
    if let Some(conflict) = registry.datasets.iter().find(|entry| {
        entry.dataset_id.eq_ignore_ascii_case(dataset_id) && entry.dataset_id != dataset_id
    }) {
        return Err(NetdiagError::InvalidTrace(format!(
            "dataset id {dataset_id} conflicts with existing case-insensitive id {}",
            conflict.dataset_id
        )));
    }
    Ok(())
}
