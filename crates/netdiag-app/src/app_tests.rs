use super::*;
use netdiag_core::NetdiagError;
use netdiag_core::twin::topology_model;

#[test]
fn failed_history_clear_preserves_loaded_timeline_and_selection() {
    let mut timeline = vec!["run-1"];
    let mut loaded = true;
    let mut selected = Some("run-1");
    let result = Err(NetdiagError::InvalidTrace(
        "injected history clear failure".to_string(),
    ));

    apply_run_history_clear_state(&result, &mut timeline, &mut loaded, &mut selected);

    assert_eq!(timeline, vec!["run-1"]);
    assert!(loaded);
    assert_eq!(selected, Some("run-1"));
}

#[test]
fn successful_history_clear_resets_loaded_timeline_and_selection() {
    let mut timeline = vec!["run-1"];
    let mut loaded = false;
    let mut selected = Some("run-1");
    let result = Ok(());

    apply_run_history_clear_state(&result, &mut timeline, &mut loaded, &mut selected);

    assert!(timeline.is_empty());
    assert!(loaded);
    assert_eq!(selected, None);
}

#[test]
fn capture_completion_uses_the_typed_cancellation_variant_only() {
    let cancelled = capture_session_completion(
        Err(NetdiagError::CaptureCancelled {
            context: "native pcap capture",
        }),
        ConnectorKind::NativePcap,
        "Captured",
        "test".to_string(),
    );
    assert!(matches!(cancelled, CaptureSessionCompletion::Cancelled));

    let ordinary_failure = capture_session_completion(
        Err(NetdiagError::Connector(
            "device returned a not-cancelled hardware fault".to_string(),
        )),
        ConnectorKind::NativePcap,
        "Captured",
        "test".to_string(),
    );
    assert!(matches!(
        ordinary_failure,
        CaptureSessionCompletion::Failed(_)
    ));
}

#[test]
fn rejected_startup_settings_cannot_be_overwritten_by_ui_persistence() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "netdiag-app-rejected-settings-{}-{unique}",
        std::process::id()
    ));
    let path = root.join("settings.json");
    std::fs::create_dir_all(&root).expect("settings fixture directory");
    let original = b"{invalid settings}";
    std::fs::write(&path, original).expect("rejected settings fixture");
    let store = SettingsStore::new(path.clone());
    let mut outcome = store.load_for_startup();
    assert!(!outcome.startup_authorized());

    let error = save_settings_if_authorized(&store, &mut outcome.settings, false)
        .expect_err("rejected startup settings must not be overwritten");
    assert!(error.to_string().contains("rejected at startup"));
    assert_eq!(
        std::fs::read(&path).expect("original rejected settings"),
        original
    );
    std::fs::remove_dir_all(root).expect("settings fixture cleanup");
}

#[test]
fn bundled_cjk_font_contains_required_chinese_glyphs() {
    use skrifa::{FontRef, MetadataProvider};

    let font = FontRef::new(CJK_FONT_BYTES).expect("bundled CJK font parses");

    for ch in "概览诊断规则数字孪生设置导入仿真真实拥塞实验室".chars() {
        assert!(
            font.charmap().map(ch).is_some(),
            "bundled CJK font is missing {ch}"
        );
    }
}

#[test]
fn compact_text_middle_truncates_long_values() {
    let text = compact_text("sim.congestion.long.trace.name", 14);
    assert!(text.contains('…'));
    assert!(text.len() < "sim.congestion.long.trace.name".len());
}

#[test]
fn summary_card_rows_center_value_with_icon_when_no_caption() {
    let rows = summary_card_text_rows(80.0, false);
    assert_eq!(rows.caption_y, None);
    assert_eq!(rows.label_y, 58.0);
    assert_eq!(rows.value_y, 80.0);
}

#[test]
fn summary_card_rows_keep_trace_text_group_balanced() {
    let rows = summary_card_text_rows(80.0, true);
    assert_eq!(rows.label_y, 54.0);
    assert_eq!(rows.value_y, 80.0);
    assert_eq!(rows.caption_y, Some(106.0));
    let group_center = (rows.label_y + rows.caption_y.unwrap()) / 2.0;
    assert!((group_center - 80.0).abs() < 0.1);
}

#[test]
fn startup_tab_round_trip_includes_lab() {
    assert!(StartupTab::ALL.contains(&StartupTab::Lab));
    assert_eq!(Tab::from(StartupTab::Lab), Tab::Lab);
    assert_eq!(StartupTab::from(Tab::Lab), StartupTab::Lab);
    assert_eq!(title_for_tab(Tab::Lab, Language::En), "Lab");
}

#[test]
fn pilot_run_center_records_pending_verification_when_after_run_is_empty() {
    let state = pilot_run_center::PilotRunCenterState::default();
    assert!(state.verification_options().is_none());
}

#[test]
fn pilot_run_center_builds_after_run_verification_options() {
    let mut state = pilot_run_center::PilotRunCenterState::default();
    state.verification_after_run_id = " after-run-1 ".to_string();
    state.verification_recommendation_id = " rec-1 ".to_string();
    state.verification_policy_path = " examples/policies/reroute-path-b.yaml ".to_string();
    state.verification_objective_path =
        " examples/policies/verification-objective.yaml ".to_string();

    let options = state.verification_options().expect("verification options");
    assert_eq!(options.after_run_id, "after-run-1");
    assert_eq!(options.recommendation_id.as_deref(), Some("rec-1"));
    assert_eq!(
        options.policy_path.as_deref(),
        Some(std::path::Path::new(
            "examples/policies/reroute-path-b.yaml"
        ))
    );
    assert_eq!(
        options.objective_path.as_deref(),
        Some(std::path::Path::new(
            "examples/policies/verification-objective.yaml"
        ))
    );
}

#[test]
fn app_model_reset_publishes_a_hash_bound_v2_bundle() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "netdiag-app-model-reset-{}-{unique}",
        std::process::id()
    ));
    let model_dir = root.join("model");

    let missing = ModelCacheState::load(&root);
    assert_eq!(missing.status(LanguageSetting::En), "Unavailable");

    rebuild_model_bundle(&model_dir).expect("first app model reset");
    rebuild_model_bundle(&model_dir).expect("second app model reset");

    let identity =
        netdiag_core::ml::load_existing_model_bundle_identity(&model_dir).expect("model identity");
    let manifest = identity.manifest;
    assert_eq!(
        manifest.schema_version,
        netdiag_core::ml::MODEL_MANIFEST_SCHEMA
    );
    assert_eq!(
        manifest.model_file_hash_sha256,
        identity.model_file_hash_sha256
    );
    assert!(
        model_dir
            .join(netdiag_core::ml::MODEL_CURRENT_FILE_NAME)
            .is_file()
    );
    assert!(!model_dir.join(netdiag_core::ml::MODEL_FILE_NAME).exists());
    let state = ModelCacheState::load(&root);
    let status = state.status(LanguageSetting::En);
    assert!(status.contains("Available"), "{status}");
    assert!(!status.contains("Unavailable"), "{status}");

    std::fs::remove_dir_all(root).expect("cleanup model reset test");
}

#[cfg(unix)]
#[test]
fn topology_export_replaces_symlink_without_overwriting_its_target() {
    use std::os::unix::fs::symlink;

    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "netdiag-app-topology-export-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&root).expect("create test root");
    let victim = root.join("victim.txt");
    let output = root.join("line_topology.json");
    std::fs::write(&victim, "preserve me").expect("victim fixture");
    symlink(&victim, &output).expect("output symlink fixture");

    let topology = topology_model("line").expect("built-in topology");
    write_topology_export(&output, &topology).expect("safe topology export");

    assert_eq!(
        std::fs::read_to_string(&victim).expect("victim remains readable"),
        "preserve me"
    );
    assert!(
        std::fs::symlink_metadata(&output)
            .expect("published output metadata")
            .file_type()
            .is_file()
    );
    let stored: TopologyModel =
        serde_json::from_slice(&std::fs::read(&output).expect("read exported topology"))
            .expect("parse exported topology");
    assert_eq!(stored.key, topology.key);

    std::fs::remove_dir_all(root).expect("cleanup topology export test");
}

#[test]
fn topology_export_rejects_invalid_custom_model_before_writing() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "netdiag-app-invalid-topology-export-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&root).expect("create test root");
    let output = root.join("invalid.json");
    let mut topology = topology_model("line").expect("built-in topology");
    topology.links.truncate(1);

    let error = write_topology_export(&output, &topology)
        .expect_err("disconnected topology must not be exported");

    assert!(error.to_string().contains("disconnected"));
    assert!(!output.exists(), "validation must precede publication");
    std::fs::remove_dir_all(root).expect("cleanup invalid topology export test");
}

#[test]
fn topology_selection_preserves_unknown_topology_error() {
    let error = selected_topology_model("unknown-topology", None)
        .expect_err("unknown topology must remain an explicit error");

    assert!(error.to_string().contains("unknown topology"));
}

#[test]
fn optional_metadata_treats_only_not_found_as_absent() {
    let missing = optional_path_metadata(Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "missing",
    )))
    .expect("not found is an absent optional path");
    assert!(missing.is_none());

    let error = optional_path_metadata(Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "denied",
    )))
    .expect_err("permission errors must remain visible");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn model_cache_status_exposes_bundle_read_errors() {
    let model_dir = std::path::Path::new("model");
    let state = ModelCacheState::from_identity_result(
        model_dir,
        Err(NetdiagError::Io {
            path: model_dir.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied by fixture"),
        }),
    );
    let status = state.status(LanguageSetting::En);

    assert!(status.contains("Open failed"), "{status}");
    assert!(status.contains("denied by fixture"), "{status}");
    assert!(
        status.contains(&model_dir.display().to_string()),
        "{status}"
    );
}

#[test]
fn connector_payload_flow_bytes_accept_boundary_and_reject_overflow() {
    let portable_flow_count = u64::from(u32::MAX) + 1;
    let count_summary = connector_flow::connector_payload_flow_summary(
        &serde_json::json!({ "flow_count": portable_flow_count }),
        "PCAP",
        2,
    )
    .expect("connector flow count must remain platform independent");
    assert_eq!(count_summary.flows, Some(portable_flow_count));

    let exact = serde_json::json!({
        "top_talkers": [
            { "label": "maximum", "bytes": u64::MAX },
            { "label": "zero", "bytes": 0 }
        ]
    });
    let summary = connector_flow::connector_payload_flow_summary(&exact, "PCAP", 2)
        .expect("exact connector byte boundary");
    assert_eq!(summary.total_bytes, Some(u64::MAX));

    let overflowing = serde_json::json!({
        "top_talkers": [
            { "label": "maximum", "bytes": u64::MAX },
            { "label": "one-more", "bytes": 1 }
        ]
    });
    let error = connector_flow::connector_payload_flow_summary(&overflowing, "PCAP", 2)
        .expect_err("overflowing connector bytes must fail");
    assert!(error.to_string().contains("exceeds u64::MAX"), "{error}");
}

#[test]
fn connector_payload_flow_summary_rejects_malformed_or_inconsistent_metadata() {
    for (payload, expected) in [
        (
            serde_json::json!({ "top_talkers": [{ "label": "flow" }] }),
            "bytes must be",
        ),
        (
            serde_json::json!({ "total_bytes": "100" }),
            "total_bytes must be",
        ),
        (
            serde_json::json!({ "total_bytes": 100, "bytes": 101 }),
            "fields disagree",
        ),
        (
            serde_json::json!({
                "flow_count": 0,
                "top_talkers": [{ "label": "flow", "bytes": 1 }]
            }),
            "smaller than 1 listed",
        ),
        (
            serde_json::json!({
                "total_bytes": 0,
                "top_talkers": [{ "label": "flow", "bytes": 1 }]
            }),
            "smaller than top-talker bytes",
        ),
    ] {
        let error = connector_flow::connector_payload_flow_summary(&payload, "PCAP", 1)
            .expect_err("malformed flow metadata must fail closed");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn open_path_exposes_the_native_macos_workspace_boundary() {
    let native_open: fn(&std::path::Path) -> std::io::Result<()> = open_path;
    std::hint::black_box(native_open);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn open_path_fails_explicitly_on_unsupported_platforms() {
    let error = open_path(std::path::Path::new("report.json"))
        .expect_err("unsupported platforms must not search PATH for a helper");
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
}
