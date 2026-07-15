use super::*;

#[test]
fn active_pilot_requires_double_opt_in() {
    let manifest = PilotManifest {
        schema: PILOT_SCHEMA.to_string(),
        id: "pilot".to_string(),
        name: "Pilot".to_string(),
        operator: None,
        safety: PilotSafety {
            allow_active: true,
            adapter_execution_root: None,
            adapter_python_interpreter: None,
            retention_days: None,
        },
        sources: vec![PilotSource {
            name: "probe".to_string(),
            kind: PilotSourceKind::TraceFile,
            endpoint: "data/samples/normal.csv".to_string(),
            role: PilotSourceRole::Primary,
            active: true,
            bearer_token_env: None,
            mapping: None,
            collection: PilotCollection::default(),
            adapter: PilotAdapterOptions::default(),
            metadata: BTreeMap::new(),
        }],
        gates: PilotGates::default(),
    };
    let denied = check_pilot_safety(&manifest, false);
    assert_eq!(denied[0].status, ConnectorHealthStatus::Error);
    let allowed = check_pilot_safety(&manifest, true);
    assert_eq!(allowed[0].status, ConnectorHealthStatus::Ok);
}

#[test]
fn requires_exactly_one_primary_source() {
    let mut manifest = PilotManifest {
        schema: PILOT_SCHEMA.to_string(),
        id: "pilot".to_string(),
        name: "Pilot".to_string(),
        operator: None,
        safety: PilotSafety::default(),
        sources: Vec::new(),
        gates: PilotGates::default(),
    };
    assert!(validate_pilot_manifest(&manifest).is_err());
    manifest.sources.push(PilotSource {
        name: "trace".to_string(),
        kind: PilotSourceKind::TraceFile,
        endpoint: "normal.csv".to_string(),
        role: PilotSourceRole::Primary,
        active: false,
        bearer_token_env: None,
        mapping: None,
        collection: PilotCollection::default(),
        adapter: PilotAdapterOptions::default(),
        metadata: BTreeMap::new(),
    });
    assert!(validate_pilot_manifest(&manifest).is_ok());
}
