use super::*;

#[test]
fn settings_load_rejects_duplicate_mapping_keys_without_echoing_them() {
    let path = temp_settings_path();
    let mut settings = AppSettings::default();
    settings
        .data_connectors
        .prometheus_query
        .mapping
        .insert("private-metric".to_string(), "first".to_string());
    let ambiguous = serde_json::to_string(&settings)
        .expect("settings JSON")
        .replacen(
            r#""private-metric":"first""#,
            r#""private-metric":"first","private-metric":"second""#,
            1,
        );
    fs::create_dir_all(path.parent().expect("settings parent")).expect("settings directory");
    fs::write(&path, ambiguous).expect("ambiguous settings");

    let error = SettingsStore::new(path.clone())
        .load()
        .expect_err("duplicate settings mapping key must fail");
    let message = error.to_string();
    assert!(message.contains("duplicate key"), "{message}");
    assert!(!message.contains("private-metric"), "{message}");
    assert!(!message.contains("first"), "{message}");
    assert!(!message.contains("second"), "{message}");
    cleanup_temp_path(path);
}

#[test]
fn settings_load_rejects_unknown_top_level_fields() {
    let path = temp_settings_path();
    let mut value = serde_json::to_value(AppSettings::default()).expect("settings value");
    value
        .as_object_mut()
        .expect("settings object")
        .insert("future_behavior".to_string(), serde_json::json!(true));
    fs::create_dir_all(path.parent().expect("settings parent")).expect("settings directory");
    fs::write(
        &path,
        serde_json::to_vec(&value).expect("unknown settings fixture"),
    )
    .expect("write unknown settings fixture");

    let outcome = SettingsStore::new(path.clone()).load_for_startup();

    assert_eq!(outcome.state, SettingsLoadState::Rejected);
    assert!(!outcome.startup_authorized());
    cleanup_temp_path(path);
}

#[test]
fn settings_load_rejects_unknown_nested_fields() {
    for (index, nested) in ["api", "profile", "otlp", "startup"]
        .into_iter()
        .enumerate()
    {
        let path = temp_settings_path().with_file_name(format!("settings-unknown-{index}.json"));
        let mut value = serde_json::to_value(AppSettings::default()).expect("settings value");
        let target = match nested {
            "api" => &mut value["api"],
            "profile" => &mut value["data_connectors"]["profiles"][0],
            "otlp" => &mut value["data_connectors"]["profiles"][0]["otlp_grpc"],
            "startup" => &mut value["startup"],
            _ => unreachable!("bounded nested fixture"),
        };
        target
            .as_object_mut()
            .expect("nested settings object")
            .insert("future_behavior".to_string(), serde_json::json!(true));
        fs::create_dir_all(path.parent().expect("settings parent")).expect("settings directory");
        fs::write(
            &path,
            serde_json::to_vec(&value).expect("unknown nested fixture"),
        )
        .expect("write unknown nested fixture");

        let outcome = SettingsStore::new(path.clone()).load_for_startup();

        assert_eq!(outcome.state, SettingsLoadState::Rejected, "{nested}");
        assert!(!outcome.startup_authorized(), "{nested}");
        cleanup_temp_path(path);
    }
}

#[test]
fn settings_load_rejects_unknown_custom_topology_fields_at_every_structural_layer() {
    for (index, layer) in ["model", "node", "link"].into_iter().enumerate() {
        let path = temp_settings_path().with_file_name(format!("settings-topology-{index}.json"));
        let mut value = settings_with_custom_topology();
        let target = match layer {
            "model" => &mut value["what_if"]["custom_topology"],
            "node" => &mut value["what_if"]["custom_topology"]["nodes"][0],
            "link" => &mut value["what_if"]["custom_topology"]["links"][0],
            _ => unreachable!("bounded topology layer"),
        };
        target
            .as_object_mut()
            .expect("topology object")
            .insert("future_behavior".to_string(), serde_json::json!(true));
        fs::create_dir_all(path.parent().expect("settings parent")).expect("settings directory");
        fs::write(&path, serde_json::to_vec(&value).expect("settings fixture"))
            .expect("write settings fixture");

        let outcome = SettingsStore::new(path.clone()).load_for_startup();

        assert_eq!(outcome.state, SettingsLoadState::Rejected, "{layer}");
        assert!(!outcome.startup_authorized(), "{layer}");
        cleanup_temp_path(path);
    }
}

#[test]
fn custom_topology_metadata_remains_an_explicit_round_trip_extension_point() {
    let path = temp_settings_path();
    let mut value = settings_with_custom_topology();
    value["what_if"]["custom_topology"]["metadata"]["model_extension"] =
        serde_json::json!({"enabled": true});
    value["what_if"]["custom_topology"]["nodes"][0]["metadata"]["node_extension"] =
        serde_json::json!([1, 2, 3]);
    value["what_if"]["custom_topology"]["links"][0]["metadata"]["link_extension"] =
        serde_json::json!({"policy": "bounded"});
    let expected = value["what_if"]["custom_topology"].clone();
    fs::create_dir_all(path.parent().expect("settings parent")).expect("settings directory");
    fs::write(&path, serde_json::to_vec(&value).expect("settings fixture"))
        .expect("write settings fixture");
    let store = SettingsStore::new(path.clone());
    let mut loaded = store.load().expect("load strict topology metadata");

    store.save(&mut loaded).expect("save topology metadata");
    let reloaded = SettingsStore::new(path.clone())
        .load()
        .expect("reload topology metadata");

    assert_eq!(
        serde_json::to_value(reloaded.what_if.custom_topology.expect("custom topology"))
            .expect("serialize topology"),
        expected
    );
    cleanup_temp_path(path);
}

fn settings_with_custom_topology() -> serde_json::Value {
    let mut value = serde_json::to_value(AppSettings::default()).expect("settings value");
    value["what_if"]["custom_topology"] = serde_json::json!({
        "key": "strict-topology",
        "name": "Strict topology",
        "nodes": [
            {"id": "edge", "label": "Edge", "role": "client", "metadata": {}},
            {"id": "core", "label": "Core", "role": "router", "metadata": {}}
        ],
        "links": [{
            "id": "edge-core",
            "source": "edge",
            "target": "core",
            "latency_ms": 5.0,
            "loss_pct": 0.0,
            "capacity_mbps": 100.0,
            "metadata": {}
        }],
        "metadata": {}
    });
    value
}
