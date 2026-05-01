use crate::error::{NetdiagError, Result};
use crate::models::{
    OverallTelemetry, TopologyLink, TopologyModel, TopologyNode, TwinPolicyAction,
    TwinPolicyActionKind, TwinPolicyImpact, TwinPolicyTarget, WhatIfResult,
};
use petgraph::algo::dijkstra;
use petgraph::graph::{NodeIndex, UnGraph};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct Topology {
    pub key: &'static str,
    pub name: &'static str,
    pub nodes: &'static [&'static str],
    pub edges: &'static [(&'static str, &'static str)],
    pub base_latency_ms: f64,
    pub base_loss_pct: f64,
    pub base_throughput: f64,
}

pub type WhatIfAction = TwinPolicyAction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyFormat {
    Json,
    Yaml,
}

pub fn topology_names() -> Vec<&'static str> {
    vec!["line", "mesh", "star"]
}

pub fn action_names() -> Vec<&'static str> {
    vec!["reroute_path_b", "increase_queue", "reduce_bandwidth"]
}

pub fn topology(key: &str) -> Result<Topology> {
    match key {
        "line" => Ok(Topology {
            key: "line",
            name: "Line Topology",
            nodes: &["Client", "Switch", "Server"],
            edges: &[("Client", "Switch"), ("Switch", "Server")],
            base_latency_ms: 60.0,
            base_loss_pct: 0.6,
            base_throughput: 80.0,
        }),
        "mesh" => Ok(Topology {
            key: "mesh",
            name: "Mesh Topology",
            nodes: &["Client", "Node-A", "Node-B", "Server"],
            edges: &[
                ("Client", "Node-A"),
                ("Client", "Node-B"),
                ("Node-A", "Node-B"),
                ("Node-A", "Server"),
                ("Node-B", "Server"),
            ],
            base_latency_ms: 45.0,
            base_loss_pct: 0.25,
            base_throughput: 120.0,
        }),
        "star" => Ok(Topology {
            key: "star",
            name: "Star Topology",
            nodes: &["Client", "Core", "Server", "Edge-1", "Edge-2"],
            edges: &[
                ("Client", "Core"),
                ("Server", "Core"),
                ("Edge-1", "Core"),
                ("Edge-2", "Core"),
            ],
            base_latency_ms: 55.0,
            base_loss_pct: 0.4,
            base_throughput: 100.0,
        }),
        other => Err(NetdiagError::UnknownTopology(other.to_string())),
    }
}

pub fn policy_action_presets() -> Vec<TwinPolicyAction> {
    vec![
        reroute_path_b_policy(),
        increase_queue_policy(),
        reduce_bandwidth_policy(),
    ]
}

pub fn policy_action(key: &str) -> Result<TwinPolicyAction> {
    match key {
        "reroute_path_b" => Ok(reroute_path_b_policy()),
        "increase_queue" => Ok(increase_queue_policy()),
        "reduce_bandwidth" => Ok(reduce_bandwidth_policy()),
        other => Err(NetdiagError::UnknownAction(other.to_string())),
    }
}

pub fn action(key: &str) -> Result<WhatIfAction> {
    policy_action(key)
}

fn reroute_path_b_policy() -> TwinPolicyAction {
    TwinPolicyAction {
        id: "reroute_path_b".to_string(),
        kind: TwinPolicyActionKind::Reroute,
        target: TwinPolicyTarget {
            path_id: Some("path_b".to_string()),
            ..TwinPolicyTarget::default()
        },
        parameters: BTreeMap::from([("candidate_path".to_string(), json!("path_b"))]),
        impact: TwinPolicyImpact {
            latency_delta_pct: -0.25,
            loss_delta_pct: -0.45,
            throughput_delta_pct: 0.25,
        },
        qoe_risk: "low".to_string(),
        notes: "Reroute to less-loaded path B".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn increase_queue_policy() -> TwinPolicyAction {
    TwinPolicyAction {
        id: "increase_queue".to_string(),
        kind: TwinPolicyActionKind::QueueLimit,
        target: TwinPolicyTarget::default(),
        parameters: BTreeMap::from([("queue_limit_multiplier".to_string(), json!(1.25))]),
        impact: TwinPolicyImpact {
            latency_delta_pct: -0.08,
            loss_delta_pct: -0.15,
            throughput_delta_pct: 0.10,
        },
        qoe_risk: "low".to_string(),
        notes: "Increase queue limit at bottleneck router".to_string(),
        metadata: BTreeMap::new(),
    }
}

fn reduce_bandwidth_policy() -> TwinPolicyAction {
    TwinPolicyAction {
        id: "reduce_bandwidth".to_string(),
        kind: TwinPolicyActionKind::CapacityChange,
        target: TwinPolicyTarget::default(),
        parameters: BTreeMap::from([("capacity_delta_pct".to_string(), json!(-0.10))]),
        impact: TwinPolicyImpact {
            latency_delta_pct: 0.15,
            loss_delta_pct: 0.35,
            throughput_delta_pct: -0.10,
        },
        qoe_risk: "high".to_string(),
        notes: "Artificial throttling, usually for compliance but may degrade QoE".to_string(),
        metadata: BTreeMap::new(),
    }
}

pub fn import_topology(input: &str, format: TopologyFormat) -> Result<TopologyModel> {
    match format {
        TopologyFormat::Json => import_topology_json(input),
        TopologyFormat::Yaml => {
            let model: TopologyModel = serde_yaml::from_str(input).map_err(|err| {
                NetdiagError::InvalidTrace(format!("invalid topology YAML: {err}"))
            })?;
            validate_topology_model(&model)?;
            Ok(model)
        }
    }
}

pub fn export_topology(model: &TopologyModel, format: TopologyFormat) -> Result<String> {
    match format {
        TopologyFormat::Json => export_topology_json(model),
        TopologyFormat::Yaml => serde_yaml::to_string(model).map_err(|err| {
            NetdiagError::InvalidTrace(format!("failed to encode topology YAML: {err}"))
        }),
    }
}

pub fn import_topology_json(input: &str) -> Result<TopologyModel> {
    let model: TopologyModel = serde_json::from_str(input)?;
    validate_topology_model(&model)?;
    Ok(model)
}

pub fn export_topology_json(model: &TopologyModel) -> Result<String> {
    validate_topology_model(model)?;
    serde_json::to_string_pretty(model).map_err(NetdiagError::from)
}

pub fn topology_graph(key: &str) -> Result<UnGraph<String, ()>> {
    let topology = topology(key)?;
    let mut graph = UnGraph::<String, ()>::new_undirected();
    let mut indices = BTreeMap::new();
    for node in topology.nodes {
        indices.insert(*node, graph.add_node((*node).to_string()));
    }
    for (left, right) in topology.edges {
        if let (Some(left_idx), Some(right_idx)) = (indices.get(left), indices.get(right)) {
            graph.add_edge(*left_idx, *right_idx, ());
        }
    }
    Ok(graph)
}

pub fn topology_model(key: &str) -> Result<TopologyModel> {
    topology(key).map(|topology| topology.to_model())
}

pub fn validate_topology_model(model: &TopologyModel) -> Result<()> {
    if model.nodes.is_empty() {
        return Err(NetdiagError::InvalidTrace(
            "topology has no nodes".to_string(),
        ));
    }
    let mut node_ids = BTreeSet::new();
    for node in &model.nodes {
        if node.id.trim().is_empty() {
            return Err(NetdiagError::InvalidTrace(
                "topology node id is empty".to_string(),
            ));
        }
        if !node_ids.insert(node.id.as_str()) {
            return Err(NetdiagError::InvalidTrace(format!(
                "duplicate topology node id: {}",
                node.id
            )));
        }
    }
    if model.links.is_empty() {
        return Err(NetdiagError::InvalidTrace(
            "topology has no links".to_string(),
        ));
    }
    let mut link_ids = BTreeSet::new();
    for link in &model.links {
        if link.id.trim().is_empty() {
            return Err(NetdiagError::InvalidTrace(
                "topology link id is empty".to_string(),
            ));
        }
        if !link_ids.insert(link.id.as_str()) {
            return Err(NetdiagError::InvalidTrace(format!(
                "duplicate topology link id: {}",
                link.id
            )));
        }
        if !node_ids.contains(link.source.as_str()) || !node_ids.contains(link.target.as_str()) {
            return Err(NetdiagError::InvalidTrace(format!(
                "topology link {} references an unknown node",
                link.id
            )));
        }
        for (name, value) in [
            ("latency_ms", link.latency_ms),
            ("loss_pct", link.loss_pct),
            ("capacity_mbps", link.capacity_mbps),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(NetdiagError::InvalidTrace(format!(
                    "topology link {} has invalid {name}",
                    link.id
                )));
            }
        }
        if link.capacity_mbps <= 0.0 {
            return Err(NetdiagError::InvalidTrace(format!(
                "topology link {} capacity must be greater than 0",
                link.id
            )));
        }
    }
    Ok(())
}

pub fn run_simulated_whatif(
    telemetry: &OverallTelemetry,
    topology_key: &str,
    action_id: &str,
) -> Result<WhatIfResult> {
    let topology = topology_model(topology_key)?;
    run_simulated_whatif_with_model(telemetry, &topology, action_id)
}

pub fn run_simulated_whatif_with_model(
    telemetry: &OverallTelemetry,
    topology: &TopologyModel,
    action_id: &str,
) -> Result<WhatIfResult> {
    let action = policy_action(action_id)?;
    run_simulated_whatif_with_policy(telemetry, topology, &action)
}

pub fn run_simulated_whatif_with_policy(
    telemetry: &OverallTelemetry,
    topology: &TopologyModel,
    action: &TwinPolicyAction,
) -> Result<WhatIfResult> {
    validate_topology_model(topology)?;
    validate_policy_action(action, topology)?;
    let stats = topology_stats(topology)?;
    let baseline_latency = (telemetry.latency.mean + stats.path_latency_ms * 0.15).max(1.0);
    let baseline_loss = (telemetry.packet_loss_rate + stats.path_loss_pct * 0.2).max(0.0);
    let telemetry_throughput = telemetry.throughput_mbps.mean.max(0.0);
    let baseline_throughput = if telemetry_throughput > 0.0 {
        telemetry_throughput.min(stats.bottleneck_mbps)
    } else {
        (stats.bottleneck_mbps * 0.5).max(1.0)
    };

    let action_deltas = action_deltas(action, &stats, baseline_throughput);

    let proposed_latency = (baseline_latency * (1.0 + action_deltas.latency_pct)).max(1.0);
    let proposed_jitter =
        (telemetry.jitter_ms.mean * (1.0 + 0.5 * action_deltas.latency_pct)).max(0.0);
    let proposed_loss = (baseline_loss * (1.0 + action_deltas.loss_pct)).max(0.0);
    let proposed_throughput = (baseline_throughput * (1.0 + action_deltas.throughput_pct))
        .clamp(1.0, stats.bottleneck_mbps);

    let baseline = BTreeMap::from([
        ("latency_ms".to_string(), json!(baseline_latency)),
        ("jitter_ms".to_string(), json!(telemetry.jitter_ms.mean)),
        ("loss_rate".to_string(), json!(baseline_loss)),
        ("throughput_mbps".to_string(), json!(baseline_throughput)),
        ("path_latency_ms".to_string(), json!(stats.path_latency_ms)),
        ("bottleneck_mbps".to_string(), json!(stats.bottleneck_mbps)),
        ("redundant_paths".to_string(), json!(stats.redundant_paths)),
        ("qoe_risk".to_string(), json!("medium")),
    ]);
    let proposed = BTreeMap::from([
        ("latency_ms".to_string(), json!(proposed_latency)),
        ("jitter_ms".to_string(), json!(proposed_jitter)),
        ("loss_rate".to_string(), json!(proposed_loss)),
        ("throughput_mbps".to_string(), json!(proposed_throughput)),
        ("bottleneck_mbps".to_string(), json!(stats.bottleneck_mbps)),
        ("policy_kind".to_string(), json!(action.kind)),
        ("qoe_risk".to_string(), json!(action.qoe_risk.as_str())),
    ]);
    let delta = BTreeMap::from([
        (
            "latency_pct".to_string(),
            pct_delta(proposed_latency, baseline_latency),
        ),
        (
            "loss_pct".to_string(),
            pct_delta(proposed_loss, baseline_loss),
        ),
        (
            "throughput_pct".to_string(),
            pct_delta(proposed_throughput, baseline_throughput),
        ),
    ]);

    Ok(WhatIfResult {
        action_id: action.id.clone(),
        action_notes: action.notes.clone(),
        policy_action: Some(action.clone()),
        topology: topology.key.to_string(),
        topology_snapshot: Some(topology.clone()),
        baseline,
        proposed,
        delta,
    })
}

#[derive(Debug, Clone, Copy)]
struct ActionDeltas {
    latency_pct: f64,
    loss_pct: f64,
    throughput_pct: f64,
}

fn validate_policy_action(action: &TwinPolicyAction, topology: &TopologyModel) -> Result<()> {
    if action.id.trim().is_empty() {
        return Err(NetdiagError::InvalidTrace(
            "policy action id is empty".to_string(),
        ));
    }
    if action.qoe_risk.trim().is_empty() {
        return Err(NetdiagError::InvalidTrace(format!(
            "policy action {} qoe_risk is empty",
            action.id
        )));
    }
    for (name, value) in [
        ("latency_delta_pct", action.impact.latency_delta_pct),
        ("loss_delta_pct", action.impact.loss_delta_pct),
        ("throughput_delta_pct", action.impact.throughput_delta_pct),
    ] {
        if !value.is_finite() {
            return Err(NetdiagError::InvalidTrace(format!(
                "policy action {} has invalid {name}",
                action.id
            )));
        }
    }

    if let Some(node_id) = &action.target.node_id {
        let known = topology.nodes.iter().any(|node| node.id == *node_id);
        if !known {
            return Err(NetdiagError::InvalidTrace(format!(
                "policy action {} targets unknown node {}",
                action.id, node_id
            )));
        }
    }
    if let Some(link_id) = &action.target.link_id {
        let known = topology.links.iter().any(|link| link.id == *link_id);
        if !known {
            return Err(NetdiagError::InvalidTrace(format!(
                "policy action {} targets unknown link {}",
                action.id, link_id
            )));
        }
    }
    if action.kind == TwinPolicyActionKind::LinkDisable && action.target.link_id.is_none() {
        return Err(NetdiagError::InvalidTrace(format!(
            "policy action {} must target a link",
            action.id
        )));
    }
    Ok(())
}

fn action_deltas(
    action: &TwinPolicyAction,
    stats: &TopologyStats,
    baseline_throughput: f64,
) -> ActionDeltas {
    let redundancy_factor = if stats.redundant_paths { 0.85 } else { 1.0 };
    let capacity_headroom = (stats.bottleneck_mbps / baseline_throughput.max(1.0)).clamp(1.0, 3.0);
    let mut latency_pct = action.impact.latency_delta_pct * redundancy_factor;
    let mut loss_pct = action.impact.loss_delta_pct * redundancy_factor;
    let mut throughput_pct = action.impact.throughput_delta_pct * capacity_headroom.sqrt();

    match action.kind {
        TwinPolicyActionKind::Reroute
        | TwinPolicyActionKind::QueueLimit
        | TwinPolicyActionKind::CapacityChange => {}
        TwinPolicyActionKind::LinkDisable => {
            if stats.redundant_paths {
                latency_pct *= 0.75;
                loss_pct *= 0.75;
            } else {
                latency_pct = latency_pct.max(0.20);
                loss_pct = loss_pct.max(0.50);
                throughput_pct = throughput_pct.min(-0.50);
            }
        }
        TwinPolicyActionKind::TrafficShift => {
            let shifted_share = action_parameter_f64(action, "traffic_shift_pct")
                .unwrap_or(100.0)
                .clamp(0.0, 100.0)
                / 100.0;
            latency_pct *= shifted_share;
            loss_pct *= shifted_share;
            throughput_pct *= shifted_share;
        }
    }

    ActionDeltas {
        latency_pct: latency_pct.clamp(-0.95, 2.0),
        loss_pct: loss_pct.clamp(-0.95, 5.0),
        throughput_pct: throughput_pct.clamp(-0.95, 1.5),
    }
}

fn action_parameter_f64(action: &TwinPolicyAction, key: &str) -> Option<f64> {
    action
        .parameters
        .get(key)
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
}

impl Topology {
    fn to_model(&self) -> TopologyModel {
        let nodes = self
            .nodes
            .iter()
            .map(|node| TopologyNode {
                id: (*node).to_string(),
                label: (*node).to_string(),
                role: if node.eq_ignore_ascii_case("client") {
                    "client".to_string()
                } else if node.eq_ignore_ascii_case("server") {
                    "server".to_string()
                } else {
                    "network".to_string()
                },
                metadata: BTreeMap::new(),
            })
            .collect();
        let links = self
            .edges
            .iter()
            .enumerate()
            .map(|(idx, (source, target))| TopologyLink {
                id: format!("link-{}", idx + 1),
                source: (*source).to_string(),
                target: (*target).to_string(),
                latency_ms: (self.base_latency_ms / self.edges.len().max(1) as f64).max(1.0),
                loss_pct: (self.base_loss_pct / self.edges.len().max(1) as f64).max(0.0),
                capacity_mbps: self.base_throughput.max(1.0),
                metadata: BTreeMap::new(),
            })
            .collect();
        TopologyModel {
            key: self.key.to_string(),
            name: self.name.to_string(),
            nodes,
            links,
            metadata: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct TopologyStats {
    path_latency_ms: f64,
    path_loss_pct: f64,
    bottleneck_mbps: f64,
    redundant_paths: bool,
}

fn topology_stats(model: &TopologyModel) -> Result<TopologyStats> {
    let mut graph = UnGraph::<&str, f64>::new_undirected();
    let mut indices = BTreeMap::<&str, NodeIndex>::new();
    for node in &model.nodes {
        indices.insert(node.id.as_str(), graph.add_node(node.id.as_str()));
    }
    for link in &model.links {
        let source = *indices.get(link.source.as_str()).ok_or_else(|| {
            NetdiagError::InvalidTrace(format!("unknown source node {}", link.source))
        })?;
        let target = *indices.get(link.target.as_str()).ok_or_else(|| {
            NetdiagError::InvalidTrace(format!("unknown target node {}", link.target))
        })?;
        graph.add_edge(source, target, link.latency_ms.max(0.1));
    }
    let start = graph
        .node_indices()
        .next()
        .ok_or_else(|| NetdiagError::InvalidTrace("topology has no nodes".to_string()))?;
    let end = graph
        .node_indices()
        .next_back()
        .ok_or_else(|| NetdiagError::InvalidTrace("topology has no nodes".to_string()))?;
    let distances = dijkstra(&graph, start, Some(end), |edge| *edge.weight());
    let path_latency_ms = distances.get(&end).copied().unwrap_or_else(|| {
        model
            .links
            .iter()
            .map(|link| link.latency_ms)
            .sum::<f64>()
            .max(1.0)
    });
    let path_loss_pct = if model.links.is_empty() {
        0.0
    } else {
        model.links.iter().map(|link| link.loss_pct).sum::<f64>() / model.links.len() as f64
    };
    let bottleneck_mbps = model
        .links
        .iter()
        .map(|link| link.capacity_mbps)
        .fold(f64::INFINITY, f64::min)
        .max(1.0);
    let redundant_paths = model.links.len() >= model.nodes.len();
    Ok(TopologyStats {
        path_latency_ms,
        path_loss_pct,
        bottleneck_mbps,
        redundant_paths,
    })
}

fn pct_delta(proposed: f64, baseline: f64) -> f64 {
    (((proposed - baseline) / baseline.max(1e-6)) * 100.0 * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        DistributionStats, OverallTelemetry, ThroughputStats, TwinPolicyActionKind,
    };
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn built_in_topology_models_are_valid() {
        for name in topology_names() {
            validate_topology_model(&topology_model(name).expect("topology")).expect("valid");
        }
    }

    #[test]
    fn custom_topology_changes_what_if_output() {
        let telemetry = telemetry();
        let mut line = topology_model("line").expect("line");
        line.key = "custom_line".to_string();
        line.links[0].capacity_mbps = 25.0;

        let result =
            run_simulated_whatif_with_model(&telemetry, &line, "reroute_path_b").expect("whatif");

        assert_eq!(result.topology, "custom_line");
        assert!(result.topology_snapshot.is_some());
        assert!(
            result
                .baseline
                .get("bottleneck_mbps")
                .and_then(|value| value.as_f64())
                .is_some_and(|value| (value - 25.0).abs() < f64::EPSILON)
        );
    }

    #[test]
    fn invalid_topology_rejects_unknown_link_node() {
        let mut model = topology_model("line").expect("line");
        model.links[0].target = "missing".to_string();
        let err = validate_topology_model(&model).expect_err("invalid");
        assert!(err.to_string().contains("unknown node"));
    }

    #[test]
    fn topology_json_import_export_round_trips_and_validates() {
        let model = topology_model("mesh").expect("mesh");

        let exported = export_topology(&model, TopologyFormat::Json).expect("export");
        let imported = import_topology(&exported, TopologyFormat::Json).expect("import");

        assert_eq!(imported, model);

        let yaml = export_topology(&model, TopologyFormat::Yaml).expect("yaml export");
        let imported_yaml = import_topology(&yaml, TopologyFormat::Yaml).expect("yaml import");

        assert_eq!(imported_yaml, model);
    }

    #[test]
    fn topology_json_import_rejects_invalid_model() {
        let mut model = topology_model("line").expect("line");
        model.links[0].capacity_mbps = 0.0;
        let invalid_json = serde_json::to_string(&model).expect("json");

        let err = import_topology_json(&invalid_json).expect_err("invalid topology");

        assert!(err.to_string().contains("capacity must be greater than 0"));
    }

    #[test]
    fn policy_action_traffic_shift_scales_deltas() {
        let telemetry = telemetry();
        let line = topology_model("line").expect("line");
        let action = TwinPolicyAction {
            id: "shift_half_to_path_b".to_string(),
            kind: TwinPolicyActionKind::TrafficShift,
            target: TwinPolicyTarget {
                path_id: Some("path_b".to_string()),
                ..TwinPolicyTarget::default()
            },
            parameters: BTreeMap::from([("traffic_shift_pct".to_string(), json!(50.0))]),
            impact: TwinPolicyImpact {
                latency_delta_pct: -0.20,
                loss_delta_pct: -0.30,
                throughput_delta_pct: 0.20,
            },
            qoe_risk: "medium".to_string(),
            notes: "Shift half of matching traffic to path B".to_string(),
            metadata: BTreeMap::new(),
        };

        let result = run_simulated_whatif_with_policy(&telemetry, &line, &action).expect("whatif");

        assert_eq!(result.action_id, "shift_half_to_path_b");
        assert_eq!(
            result.policy_action.as_ref().map(|action| action.kind),
            Some(TwinPolicyActionKind::TrafficShift)
        );
        assert_eq!(result.delta["latency_pct"], -10.0);
        assert!(result.delta["throughput_pct"] > 0.0);
    }

    #[test]
    fn policy_presets_keep_legacy_action_ids() {
        let presets = policy_action_presets();

        assert_eq!(presets.len(), action_names().len());
        assert_eq!(
            action("reroute_path_b").expect("action").id,
            "reroute_path_b"
        );
        assert_eq!(
            action("increase_queue").expect("action").kind,
            TwinPolicyActionKind::QueueLimit
        );
        assert_eq!(
            action("reduce_bandwidth").expect("action").kind,
            TwinPolicyActionKind::CapacityChange
        );
    }

    fn telemetry() -> OverallTelemetry {
        OverallTelemetry {
            duration_s: 30.0,
            samples: 10,
            latency: DistributionStats {
                mean: 80.0,
                ..DistributionStats::default()
            },
            jitter_ms: DistributionStats {
                mean: 5.0,
                ..DistributionStats::default()
            },
            packet_loss_rate: 1.0,
            retransmission_rate: 0.5,
            timeout_events: 0.0,
            retry_events: 0.0,
            throughput_mbps: ThroughputStats {
                mean: 20.0,
                p95: 22.0,
                min: Some(18.0),
            },
            dns_failure_events: 0.0,
            tls_failure_events: 0.0,
            quic_blocked_ratio: 0.0,
            window_count: 1,
        }
    }
}
