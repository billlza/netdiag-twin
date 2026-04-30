use crate::error::{NetdiagError, Result};
use crate::models::{OverallTelemetry, TopologyLink, TopologyModel, TopologyNode, WhatIfResult};
use petgraph::algo::dijkstra;
use petgraph::graph::{NodeIndex, UnGraph};
use serde_json::json;
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

#[derive(Debug, Clone)]
pub struct WhatIfAction {
    pub key: &'static str,
    pub latency_delta_pct: f64,
    pub loss_delta_pct: f64,
    pub throughput_delta_pct: f64,
    pub qoe_risk: &'static str,
    pub notes: &'static str,
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

pub fn action(key: &str) -> Result<WhatIfAction> {
    match key {
        "reroute_path_b" => Ok(WhatIfAction {
            key: "reroute_path_b",
            latency_delta_pct: -0.25,
            loss_delta_pct: -0.45,
            throughput_delta_pct: 0.25,
            qoe_risk: "low",
            notes: "Reroute to less-loaded path B",
        }),
        "increase_queue" => Ok(WhatIfAction {
            key: "increase_queue",
            latency_delta_pct: -0.08,
            loss_delta_pct: -0.15,
            throughput_delta_pct: 0.10,
            qoe_risk: "low",
            notes: "Increase queue limit at bottleneck router",
        }),
        "reduce_bandwidth" => Ok(WhatIfAction {
            key: "reduce_bandwidth",
            latency_delta_pct: 0.15,
            loss_delta_pct: 0.35,
            throughput_delta_pct: -0.10,
            qoe_risk: "high",
            notes: "Artificial throttling, usually for compliance but may degrade QoE",
        }),
        other => Err(NetdiagError::UnknownAction(other.to_string())),
    }
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
    for link in &model.links {
        if link.id.trim().is_empty() {
            return Err(NetdiagError::InvalidTrace(
                "topology link id is empty".to_string(),
            ));
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
    validate_topology_model(topology)?;
    let action = action(action_id)?;
    let stats = topology_stats(topology)?;
    let baseline_latency = (telemetry.latency.mean + stats.path_latency_ms * 0.15).max(1.0);
    let baseline_loss = (telemetry.packet_loss_rate + stats.path_loss_pct * 0.2).max(0.0);
    let telemetry_throughput = telemetry.throughput_mbps.mean.max(0.0);
    let baseline_throughput = if telemetry_throughput > 0.0 {
        telemetry_throughput.min(stats.bottleneck_mbps)
    } else {
        (stats.bottleneck_mbps * 0.5).max(1.0)
    };

    let redundancy_factor = if stats.redundant_paths { 0.85 } else { 1.0 };
    let capacity_headroom = (stats.bottleneck_mbps / baseline_throughput.max(1.0)).clamp(1.0, 3.0);
    let action_latency_delta = action.latency_delta_pct * redundancy_factor;
    let action_loss_delta = action.loss_delta_pct * redundancy_factor;
    let action_throughput_delta =
        (action.throughput_delta_pct * capacity_headroom.sqrt()).clamp(-0.95, 1.5);

    let proposed_latency = (baseline_latency * (1.0 + action_latency_delta)).max(1.0);
    let proposed_jitter = (telemetry.jitter_ms.mean * (1.0 + 0.5 * action_latency_delta)).max(0.0);
    let proposed_loss = (baseline_loss * (1.0 + action_loss_delta)).max(0.0);
    let proposed_throughput =
        (baseline_throughput * (1.0 + action_throughput_delta)).clamp(1.0, stats.bottleneck_mbps);

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
        ("qoe_risk".to_string(), json!(action.qoe_risk)),
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
        action_id: action.key.to_string(),
        action_notes: action.notes.to_string(),
        topology: topology.key.to_string(),
        topology_snapshot: Some(topology.clone()),
        baseline,
        proposed,
        delta,
    })
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
    use crate::models::{DistributionStats, OverallTelemetry, ThroughputStats};

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
