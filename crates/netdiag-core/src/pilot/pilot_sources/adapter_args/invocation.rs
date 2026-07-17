use super::super::super::adapter_contract::{validate_adapter_options, validated_adapter_contract};
use super::super::super::{PilotAdapterMode, PilotSource};
use crate::error::{NetdiagError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::pilot::pilot_sources) struct AdapterInvocation {
    pub(in crate::pilot::pilot_sources) mode: PilotAdapterMode,
    pub(in crate::pilot::pilot_sources) args: Vec<String>,
}

pub(in crate::pilot::pilot_sources) fn adapter_preflight_invocation(
    source: &PilotSource,
) -> Result<AdapterInvocation> {
    adapter_invocation(source, AdapterPhase::Preflight)
}

pub(in crate::pilot::pilot_sources) fn adapter_runtime_invocation(
    source: &PilotSource,
) -> Result<AdapterInvocation> {
    adapter_invocation(source, AdapterPhase::Runtime)
}

#[derive(Debug, Clone, Copy)]
enum AdapterPhase {
    Preflight,
    Runtime,
}

fn adapter_invocation(source: &PilotSource, phase: AdapterPhase) -> Result<AdapterInvocation> {
    validated_adapter_contract(source)?;
    let mode = source.adapter.mode.ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "adapter source {} must declare adapter.mode as sample or live",
            source.name
        ))
    })?;
    validate_adapter_options(source)?;
    let mut args = match phase {
        AdapterPhase::Preflight => vec!["--preflight".to_string()],
        AdapterPhase::Runtime => vec!["--collect".to_string()],
    };
    if mode == PilotAdapterMode::Sample {
        args.push("--emit-sample".to_string());
    }
    args.extend(source.adapter.args.iter().cloned());
    Ok(AdapterInvocation { mode, args })
}
