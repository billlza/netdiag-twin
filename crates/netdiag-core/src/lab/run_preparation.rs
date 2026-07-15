use super::{
    LabScenarioSnapshot, LabWhatIf, LoadedLabSource, build_what_if_request,
    load_lab_sources_bounded,
};
use crate::connectors::authentication::ResolvedBearerTokens;
use crate::error::{NetdiagError, Result};
use crate::pipeline::WhatIfRequest;
use crate::storage::{ArtifactRootCapability, prepare_artifact_root};
use std::path::Path;

pub(super) struct PreparedLabInputs {
    pub(super) snapshot: LabScenarioSnapshot,
    pub(super) what_if: Option<WhatIfRequest>,
    pub(super) loaded_sources: Vec<LoadedLabSource>,
}

pub(super) fn prepare(
    scenario_path: &Path,
    snapshot: LabScenarioSnapshot,
    resolved_tokens: &ResolvedBearerTokens,
) -> Result<PreparedLabInputs> {
    let scenario_dir = scenario_path.parent().unwrap_or_else(|| Path::new("."));
    let scenario = snapshot.scenario();
    let what_if = what_if_spec(scenario)
        .as_ref()
        .map(|what_if| build_what_if_request(what_if, scenario_dir))
        .transpose()?;
    let loaded_sources = load_lab_sources_bounded(scenario, scenario_dir, resolved_tokens)?;
    Ok(PreparedLabInputs {
        snapshot,
        what_if,
        loaded_sources,
    })
}

fn what_if_spec(scenario: &super::LabScenario) -> Option<LabWhatIf> {
    scenario.what_if.clone().or_else(|| {
        scenario.topology.as_ref().map(|topology| LabWhatIf {
            topology: topology.clone(),
            policy: "reroute_path_b".to_string(),
        })
    })
}

pub(super) enum LabArtifactRootAuthorization {
    Unclaimed,
    Claimed(ArtifactRootCapability),
}

impl LabArtifactRootAuthorization {
    pub(super) fn claim(&mut self, artifact_root: &Path) -> Result<&ArtifactRootCapability> {
        if matches!(self, Self::Unclaimed) {
            *self = Self::Claimed(prepare_artifact_root(artifact_root)?);
        }
        match self {
            Self::Claimed(capability) => Ok(capability),
            Self::Unclaimed => Err(NetdiagError::InvalidTrace(
                "lab artifact root authorization was not retained after preparation".to_string(),
            )),
        }
    }
}
