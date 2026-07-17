use super::*;
use crate::models::{
    DistributionStats, OverallTelemetry, TelemetrySummary, ThroughputStats, TwinPolicyActionKind,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;

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
    let mut model = topology_model("mesh").expect("mesh");
    model
        .metadata
        .insert("model_extension".to_string(), json!({"enabled": true}));
    model.nodes[0]
        .metadata
        .insert("node_extension".to_string(), json!([1, 2, 3]));
    model.links[0]
        .metadata
        .insert("link_extension".to_string(), json!({"policy": "bounded"}));

    let exported = export_topology(&model, TopologyFormat::Json).expect("export");
    let imported = import_topology(&exported, TopologyFormat::Json).expect("import");

    assert_eq!(imported, model);

    let yaml = export_topology(&model, TopologyFormat::Yaml).expect("yaml export");
    let imported_yaml = import_topology(&yaml, TopologyFormat::Yaml).expect("yaml import");

    assert_eq!(imported_yaml, model);
}

#[test]
fn topology_import_rejects_unknown_fields_at_every_structural_layer() {
    for layer in ["model", "node", "link"] {
        let mut value =
            serde_json::to_value(topology_model("line").expect("line")).expect("topology value");
        let target = match layer {
            "model" => &mut value,
            "node" => &mut value["nodes"][0],
            "link" => &mut value["links"][0],
            _ => unreachable!("bounded topology layer"),
        };
        target
            .as_object_mut()
            .expect("topology object")
            .insert("future_behavior".to_string(), json!(true));
        let input = serde_json::to_string(&value).expect("topology JSON");

        let error = import_topology(&input, TopologyFormat::Json)
            .expect_err("unknown topology field must fail");

        assert!(
            error.to_string().contains("invalid topology JSON"),
            "{layer}: {error}"
        );
    }

    let mut yaml = export_topology(&topology_model("line").expect("line"), TopologyFormat::Yaml)
        .expect("topology YAML");
    yaml.push_str("future_behavior: true\n");
    let error = import_topology(&yaml, TopologyFormat::Yaml)
        .expect_err("unknown YAML topology field must fail");
    assert!(
        error.to_string().contains("invalid topology YAML"),
        "{error}"
    );
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
fn topology_and_policy_json_reject_duplicate_mapping_keys() {
    let mut topology = topology_model("line").expect("line");
    topology
        .metadata
        .insert("private-key".to_string(), json!("first"));
    let topology_json = serde_json::to_string(&topology)
        .expect("topology JSON")
        .replacen(
            r#""private-key":"first""#,
            r#""private-key":"first","private-key":"second""#,
            1,
        );
    let topology_error = import_topology_json(&topology_json)
        .expect_err("duplicate topology metadata key must fail");
    assert!(topology_error.to_string().contains("duplicate key"));

    let mut policy = action("reroute_path_b").expect("policy");
    policy
        .parameters
        .insert("private-key".to_string(), json!("first"));
    let policy_json = serde_json::to_string(&policy)
        .expect("policy JSON")
        .replacen(
            r#""private-key":"first""#,
            r#""private-key":"first","private-key":"second""#,
            1,
        );
    let policy_error = import_policy_action(&policy_json, TopologyFormat::Json)
        .expect_err("duplicate policy parameter key must fail");
    assert!(policy_error.to_string().contains("duplicate key"));
}

#[test]
fn topology_validation_rejects_any_disconnected_component() {
    let mut model = topology_model("line").expect("line");
    let mut orphan = model.nodes[1].clone();
    orphan.id = "Orphan".to_string();
    orphan.label = "Orphan".to_string();
    model.nodes.push(orphan);

    let err = validate_topology_model(&model).expect_err("disconnected topology");

    assert!(err.to_string().contains("all nodes"), "{err}");
    assert!(err.to_string().contains("2"), "{err}");
}

#[test]
fn topology_validation_rejects_self_loops() {
    let mut model = topology_model("line").expect("line");
    model.links[0].target = model.links[0].source.clone();

    let error = validate_topology_model(&model).expect_err("self-loop must fail");

    assert!(error.to_string().contains("self-loop"), "{error}");
}

#[test]
fn topology_and_policy_file_loaders_round_trip_supported_formats() {
    let temp = tempfile::tempdir().expect("tempdir");
    let topology = topology_model("mesh").expect("mesh");
    let json_path = temp.path().join("topology.json");
    let yaml_path = temp.path().join("topology.yaml");
    fs::write(
        &json_path,
        export_topology(&topology, TopologyFormat::Json).expect("json export"),
    )
    .expect("json topology");
    fs::write(
        &yaml_path,
        export_topology(&topology, TopologyFormat::Yaml).expect("yaml export"),
    )
    .expect("yaml topology");
    assert_eq!(load_topology_file(&json_path).expect("json load"), topology);
    assert_eq!(load_topology_file(&yaml_path).expect("yaml load"), topology);

    let policy = action("reroute_path_b").expect("policy");
    let policy_path = temp.path().join("policy.json");
    fs::write(
        &policy_path,
        serde_json::to_vec_pretty(&policy).expect("policy JSON"),
    )
    .expect("policy file");
    assert_eq!(
        load_policy_action_file(&policy_path).expect("policy load"),
        policy
    );
}

#[test]
fn topology_loader_accepts_exact_size_boundary_and_rejects_one_byte_over() {
    let temp = tempfile::tempdir().expect("tempdir");
    let topology = topology_model("line").expect("line");
    let mut exact = export_topology(&topology, TopologyFormat::Json)
        .expect("topology JSON")
        .into_bytes();
    exact.resize(input::MAX_TOPOLOGY_FILE_BYTES as usize, b' ');
    let exact_path = temp.path().join("exact.json");
    fs::write(&exact_path, exact).expect("exact-size topology");
    assert_eq!(
        load_topology_file(&exact_path).expect("exact load"),
        topology
    );

    let oversized_path = temp.path().join("oversized.json");
    let oversized = fs::File::create(&oversized_path).expect("oversized topology");
    oversized
        .set_len(input::MAX_TOPOLOGY_FILE_BYTES + 1)
        .expect("set oversized length");
    let error = load_topology_file(&oversized_path).expect_err("one byte over must fail");
    assert!(error.to_string().contains("read limit"), "{error}");
}

#[cfg(unix)]
#[test]
fn topology_and_policy_file_loaders_reject_symbolic_links() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let topology_target = temp.path().join("topology-target.json");
    fs::write(
        &topology_target,
        export_topology(&topology_model("line").expect("line"), TopologyFormat::Json)
            .expect("topology JSON"),
    )
    .expect("topology target");
    let topology_link = temp.path().join("topology.json");
    symlink(&topology_target, &topology_link).expect("topology link");
    let topology_error = load_topology_file(&topology_link).expect_err("link must fail");
    assert!(
        topology_error.to_string().contains("non-symlink"),
        "{topology_error}"
    );

    let policy_target = temp.path().join("policy-target.json");
    fs::write(
        &policy_target,
        serde_json::to_vec(&action("reroute_path_b").expect("policy")).expect("policy JSON"),
    )
    .expect("policy target");
    let policy_link = temp.path().join("policy.json");
    symlink(&policy_target, &policy_link).expect("policy link");
    let policy_error = load_policy_action_file(&policy_link).expect_err("link must fail");
    assert!(
        policy_error.to_string().contains("non-symlink"),
        "{policy_error}"
    );
}

#[test]
fn topology_calibration_updates_link_metrics_from_run_summaries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir = temp.path().join("runs").join("run-1");
    std::fs::create_dir_all(&run_dir).expect("run dir");
    let summary = TelemetrySummary {
        overall: telemetry(),
        windows: Vec::new(),
        metric_provenance: Vec::new(),
    };
    std::fs::write(
        run_dir.join("telemetry_summary.json"),
        serde_json::to_vec_pretty(&summary).expect("summary"),
    )
    .expect("write summary");

    let report = calibrate_topology_from_runs(&topology_model("line").expect("line"), temp.path())
        .expect("calibration");

    assert_eq!(report.source_runs, 1);
    assert!(
        report
            .updated_metrics
            .contains(&"capacity_mbps".to_string())
    );
    assert!(report.calibrated_topology.links[0].latency_ms > 0.0);
    assert!(
        report.calibrated_topology.links[0]
            .metadata
            .contains_key("calibrated_from_runs")
    );
}

#[test]
fn topology_calibration_selects_parallel_link_by_stable_identity() {
    let temp = tempfile::tempdir().expect("tempdir");
    let summary_path = temp.path().join("telemetry_summary.json");
    write_summary(&summary_path, telemetry());
    let mut topology = topology_model("line").expect("line");
    topology.links[0].latency_ms = 100.0;
    let mut fast_link = topology.links[0].clone();
    fast_link.id = "fast-link".to_string();
    fast_link.latency_ms = 1.0;
    topology.links.push(fast_link);

    let report = calibrate_topology_from_runs(&topology, &summary_path).expect("calibration");
    let slow = report
        .calibrated_topology
        .links
        .iter()
        .find(|link| link.id == "link-1")
        .expect("slow link");
    let fast = report
        .calibrated_topology
        .links
        .iter()
        .find(|link| link.id == "fast-link")
        .expect("fast link");

    assert_eq!(
        slow.metadata.get("calibration_role"),
        Some(&json!("off_shortest_path"))
    );
    assert!(fast.metadata.contains_key("calibrated_from_runs"));
}

#[test]
fn topology_calibration_rejects_invalid_metric_ranges_and_extreme_capacity() {
    let temp = tempfile::tempdir().expect("tempdir");
    let summary_path = temp.path().join("telemetry_summary.json");
    let mut invalid_loss = telemetry();
    invalid_loss.packet_loss_rate = 100.1;
    write_summary(&summary_path, invalid_loss);
    let error = calibrate_topology_from_runs(&topology_model("line").expect("line"), &summary_path)
        .expect_err("out-of-range loss must fail");
    assert!(error.to_string().contains("between 0 and 100"), "{error}");

    let mut extreme = telemetry();
    extreme.throughput_mbps.mean = 1.6e308;
    write_summary(&summary_path, extreme);
    let error = calibrate_topology_from_runs(&topology_model("line").expect("line"), &summary_path)
        .expect_err("capacity overflow must fail");
    assert!(error.to_string().contains("capacity overflowed"), "{error}");
}

#[test]
fn topology_calibration_rejects_oversized_summary() {
    let temp = tempfile::tempdir().expect("tempdir");
    let summary_path = temp.path().join("telemetry_summary.json");
    let summary = fs::File::create(&summary_path).expect("summary");
    summary
        .set_len(crate::storage::typed_json::MAX_RUN_REPORT_BYTES + 1)
        .expect("set summary length");

    let error = calibrate_topology_from_runs(&topology_model("line").expect("line"), temp.path())
        .expect_err("oversized summary must fail");

    assert!(error.to_string().contains("scan limit"), "{error}");
}

#[cfg(unix)]
#[test]
fn topology_calibration_rejects_summary_symbolic_link() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let runs = temp.path().join("runs");
    fs::create_dir(&runs).expect("runs");
    let outside = temp.path().join("outside.json");
    write_summary(&outside, telemetry());
    symlink(&outside, runs.join("telemetry_summary.json")).expect("summary link");

    let error = calibrate_topology_from_runs(&topology_model("line").expect("line"), &runs)
        .expect_err("summary links must fail");

    assert!(error.to_string().contains("symbolic link"), "{error}");
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
    assert!(result.delta["latency_pct"] < 0.0);
    assert!(result.delta["throughput_pct"] > 0.0);
    assert!(result.modified_topology_snapshot.is_some());
}

#[test]
fn policy_action_rejects_path_like_ids() {
    for id in [
        "../../escape",
        "nested/path",
        r"nested\path",
        ".hidden",
        "tail.",
    ] {
        let mut action = action("reroute_path_b").expect("preset");
        action.id = id.to_string();
        let error = validate_policy_action_shape(&action).expect_err("unsafe id must fail");
        assert!(error.to_string().contains("policy action id"));
    }
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
            p95: 90.0,
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

fn write_summary(path: &std::path::Path, overall: OverallTelemetry) {
    let summary = TelemetrySummary {
        overall,
        windows: Vec::new(),
        metric_provenance: Vec::new(),
    };
    fs::write(
        path,
        serde_json::to_vec_pretty(&summary).expect("summary JSON"),
    )
    .expect("summary file");
}
