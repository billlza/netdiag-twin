use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TopologyModel {
    pub key: String,
    pub name: String,
    pub nodes: Vec<TopologyNode>,
    pub links: Vec<TopologyLink>,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TopologyLink {
    pub id: String,
    pub source: String,
    pub target: String,
    pub latency_ms: f64,
    pub loss_pct: f64,
    pub capacity_mbps: f64,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}
