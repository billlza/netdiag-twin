use super::EvidenceBundleExtraFile;
use crate::error::{NetdiagError, Result};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceContext {
    /// Export only manifest-declared run artifacts and explicitly requested extras.
    Plain,
    /// Require and bind the complete top-level lab review artifact set.
    Lab,
    /// Require and bind the final redacted pilot result artifact set.
    Pilot,
}

impl EvidenceContext {
    pub(super) fn required_files(
        self,
        context_root: Option<&Path>,
    ) -> Result<Vec<EvidenceBundleExtraFile>> {
        let Some(root) = context_root else {
            return match self {
                Self::Plain => Ok(Vec::new()),
                Self::Lab | Self::Pilot => Err(NetdiagError::InvalidTrace(format!(
                    "{} evidence export requires an explicit run context directory",
                    self.label()
                ))),
            };
        };
        let specs = match self {
            Self::Plain => return Ok(Vec::new()),
            Self::Lab => LAB_REQUIRED_FILES,
            Self::Pilot => PILOT_REQUIRED_FILES,
        };
        Ok(specs
            .iter()
            .map(|spec| EvidenceBundleExtraFile {
                key: spec.key.to_string(),
                path: root.join(spec.file_name),
                zip_path: spec.zip_path.to_string(),
            })
            .collect())
    }

    fn label(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Lab => "lab",
            Self::Pilot => "pilot",
        }
    }
}

struct RequiredFile {
    key: &'static str,
    file_name: &'static str,
    zip_path: &'static str,
}

const LAB_REQUIRED_FILES: &[RequiredFile] = &[
    RequiredFile {
        key: "scenario",
        file_name: "scenario.yaml",
        zip_path: "scenario.yaml",
    },
    RequiredFile {
        key: "acceptance",
        file_name: "acceptance.json",
        zip_path: "acceptance.json",
    },
    RequiredFile {
        key: "comparison",
        file_name: "comparison.json",
        zip_path: "comparison.json",
    },
    RequiredFile {
        key: "multi_source_evidence",
        file_name: "multi_source_evidence.json",
        zip_path: "multi_source_evidence.json",
    },
    RequiredFile {
        key: "lab_connector_health",
        file_name: "connector_health.json",
        zip_path: "lab_connector_health.json",
    },
];

const PILOT_REQUIRED_FILES: &[RequiredFile] = &[
    RequiredFile {
        key: "pilot_manifest",
        file_name: "pilot.yaml",
        zip_path: "pilot.yaml",
    },
    RequiredFile {
        key: "pilot_connector_health",
        file_name: "connector_health.json",
        zip_path: "pilot_connector_health.json",
    },
    RequiredFile {
        key: "pilot_report",
        file_name: "pilot_evidence_report.json",
        zip_path: "pilot_report.json",
    },
    RequiredFile {
        key: "pilot_summary",
        file_name: "pilot_summary.md",
        zip_path: "pilot_summary.md",
    },
];
