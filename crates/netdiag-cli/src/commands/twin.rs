use anyhow::Context;
use netdiag_core::models::{TelemetrySummary, TopologyModel, TwinPolicyAction};
use netdiag_core::storage::{read_report, resolve_run_location, save_json};
use netdiag_core::twin::{
    TopologyFormat, load_policy_action_file, load_topology_file, run_simulated_whatif,
    run_simulated_whatif_with_policy, validate_policy_action_for_topology,
};
use netdiag_core::validate_portable_id;
use std::path::{Path, PathBuf};

pub(crate) fn run_whatif(
    run_id: &str,
    topology: &str,
    action: &str,
    artifacts: PathBuf,
) -> anyhow::Result<()> {
    let dir = resolve_run_location(&artifacts, run_id)?.run_dir;
    let summary: TelemetrySummary = read_report(&artifacts, run_id)?.trace_summary;
    let whatif = run_simulated_whatif(&summary.overall, topology, action)?;
    validate_portable_id("what-if action id", &whatif.action_id)?;
    let saved = save_json(
        dir.join(format!("whatif_{}.json", whatif.action_id)),
        &whatif,
    )?;
    println!("{}", serde_json::to_string_pretty(&whatif)?);
    eprintln!("saved {}", saved.display());
    Ok(())
}

pub(crate) fn run_whatif_policy(
    run_id: &str,
    topology: &Path,
    policy: &Path,
    artifacts: PathBuf,
) -> anyhow::Result<()> {
    let dir = resolve_run_location(&artifacts, run_id)?.run_dir;
    let summary: TelemetrySummary = read_report(&artifacts, run_id)?.trace_summary;
    let topology = read_topology(topology)?;
    let policy = read_policy(policy)?;
    validate_policy_action_for_topology(&policy, &topology)?;
    let whatif = run_simulated_whatif_with_policy(&summary.overall, &topology, &policy)?;
    validate_portable_id("what-if action id", &whatif.action_id)?;
    let saved = save_json(
        dir.join(format!("whatif_{}.json", whatif.action_id)),
        &whatif,
    )?;
    println!("{}", serde_json::to_string_pretty(&whatif)?);
    eprintln!("saved {}", saved.display());
    Ok(())
}

pub(crate) fn read_topology(path: &Path) -> anyhow::Result<TopologyModel> {
    load_topology_file(path).with_context(|| format!("failed to load topology {}", path.display()))
}

pub(crate) fn read_policy(path: &Path) -> anyhow::Result<TwinPolicyAction> {
    load_policy_action_file(path)
        .with_context(|| format!("failed to load policy {}", path.display()))
}

pub(crate) fn format_for_path(path: &Path) -> TopologyFormat {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "yaml" | "yml" => TopologyFormat::Yaml,
        _ => TopologyFormat::Json,
    }
}

#[cfg(test)]
mod tests;
