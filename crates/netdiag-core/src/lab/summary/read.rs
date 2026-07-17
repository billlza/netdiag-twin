use super::super::{LabAcceptanceReport, LabRunComparison};
use crate::error::Result;
use crate::storage::typed_json::{
    MAX_LAB_ACCEPTANCE_BYTES, MAX_LAB_COMPARISON_BYTES, read_required_stable_json_bounded,
};
use std::path::Path;

pub(super) fn lab_acceptance(path: &Path) -> Result<LabAcceptanceReport> {
    read_required_stable_json_bounded(path, MAX_LAB_ACCEPTANCE_BYTES, "lab acceptance report")
}

pub(super) fn lab_comparison(path: &Path) -> Result<LabRunComparison> {
    read_required_stable_json_bounded(path, MAX_LAB_COMPARISON_BYTES, "lab run comparison")
}
