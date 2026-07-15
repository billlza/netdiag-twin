use super::topology_endpoints;
use crate::error::{NetdiagError, Result};
use crate::models::TopologyModel;
use petgraph::algo::{astar, connected_components};
use petgraph::graph::{NodeIndex, UnGraph};
use std::collections::BTreeMap;

/// Returns the stable model indices of the links on the minimum-latency path.
/// Parallel links are represented by the lowest-latency link, with link id and
/// model order providing deterministic tie breaks.
pub(super) fn shortest_path_link_indices(model: &TopologyModel) -> Result<Vec<usize>> {
    let mut graph = UnGraph::<&str, f64>::new_undirected();
    let mut indices = BTreeMap::<&str, NodeIndex>::new();
    for node in &model.nodes {
        indices.insert(node.id.as_str(), graph.add_node(node.id.as_str()));
    }

    let mut selected_links = BTreeMap::<(usize, usize), usize>::new();
    for (link_index, link) in model.links.iter().enumerate() {
        let source = *indices.get(link.source.as_str()).ok_or_else(|| {
            NetdiagError::InvalidTrace(format!("unknown source node {}", link.source))
        })?;
        let target = *indices.get(link.target.as_str()).ok_or_else(|| {
            NetdiagError::InvalidTrace(format!("unknown target node {}", link.target))
        })?;
        let key = ordered_pair(source, target);
        match selected_links.get_mut(&key) {
            Some(selected) if link_precedes(model, link_index, *selected) => *selected = link_index,
            Some(_) => {}
            None => {
                selected_links.insert(key, link_index);
            }
        }
    }
    for (&(source, target), &link_index) in &selected_links {
        graph.add_edge(
            NodeIndex::new(source),
            NodeIndex::new(target),
            model.links[link_index].latency_ms.max(0.1),
        );
    }

    let (start, end) = topology_endpoints(model, &indices)?;
    let Some((_, nodes)) = astar(
        &graph,
        start,
        |candidate| candidate == end,
        |edge| *edge.weight(),
        |_| 0.0,
    ) else {
        return Err(NetdiagError::InvalidTrace(format!(
            "topology {} has no connected client-to-server path",
            model.key
        )));
    };
    nodes
        .windows(2)
        .map(|pair| {
            selected_links
                .get(&ordered_pair(pair[0], pair[1]))
                .copied()
                .ok_or_else(|| {
                    NetdiagError::InvalidTrace(format!(
                        "topology {} shortest path contains an unidentified link",
                        model.key
                    ))
                })
        })
        .collect()
}

/// Validates that every topology node belongs to the same connected component.
/// Endpoint reachability alone is insufficient because it can leave orphaned
/// infrastructure hidden from simulation and calibration.
pub(super) fn validate_connected(model: &TopologyModel) -> Result<()> {
    let mut graph = UnGraph::<(), ()>::new_undirected();
    let mut indices = BTreeMap::<&str, NodeIndex>::new();
    for node in &model.nodes {
        indices.insert(node.id.as_str(), graph.add_node(()));
    }
    for link in &model.links {
        let source = *indices.get(link.source.as_str()).ok_or_else(|| {
            NetdiagError::InvalidTrace(format!("unknown source node {}", link.source))
        })?;
        let target = *indices.get(link.target.as_str()).ok_or_else(|| {
            NetdiagError::InvalidTrace(format!("unknown target node {}", link.target))
        })?;
        graph.add_edge(source, target, ());
    }
    let components = connected_components(&graph);
    if components != 1 {
        return Err(NetdiagError::InvalidTrace(format!(
            "topology {} is disconnected: all nodes must belong to one connected component, found {components}",
            model.key
        )));
    }
    Ok(())
}

fn ordered_pair(left: NodeIndex, right: NodeIndex) -> (usize, usize) {
    let left = left.index();
    let right = right.index();
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn link_precedes(model: &TopologyModel, candidate: usize, selected: usize) -> bool {
    let candidate_link = &model.links[candidate];
    let selected_link = &model.links[selected];
    candidate_link
        .latency_ms
        .total_cmp(&selected_link.latency_ms)
        .then_with(|| candidate_link.id.cmp(&selected_link.id))
        .then_with(|| candidate.cmp(&selected))
        .is_lt()
}
