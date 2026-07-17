use super::*;
use crate::pilot::{PilotAdapterOptions, PilotCollection, PilotGates, PilotSafety, PilotSource};
use std::collections::BTreeMap;

fn source(name: &str, role: PilotSourceRole) -> PilotSource {
    PilotSource {
        name: name.to_string(),
        kind: PilotSourceKind::TraceFile,
        endpoint: "normal.csv".to_string(),
        role,
        active: false,
        bearer_token_env: None,
        mapping: None,
        collection: PilotCollection::default(),
        adapter: PilotAdapterOptions::default(),
        metadata: BTreeMap::new(),
    }
}

fn manifest(sources: Vec<PilotSource>) -> PilotManifest {
    PilotManifest {
        schema: PILOT_SCHEMA.to_string(),
        id: "pilot".to_string(),
        name: "Pilot".to_string(),
        operator: None,
        safety: PilotSafety::default(),
        sources,
        gates: PilotGates::default(),
    }
}

#[test]
fn rejects_unsafe_and_duplicate_source_names() {
    for name in [
        "../outside",
        "nested/path",
        r"nested\path",
        ".hidden",
        "tail.",
    ] {
        let error =
            validate_pilot_manifest(&manifest(vec![source(name, PilotSourceRole::Primary)]))
                .expect_err("unsafe source name must fail");
        assert!(error.to_string().contains("pilot source name"));
    }

    let duplicate = manifest(vec![
        source("trace", PilotSourceRole::Primary),
        source("TRACE", PilotSourceRole::Corroborating),
    ]);
    let error = validate_pilot_manifest(&duplicate)
        .expect_err("case-insensitive filesystem collisions must fail");
    assert!(error.to_string().contains("duplicate source name"));
}

#[test]
fn accepts_distinct_portable_source_names_without_sanitization_collisions() {
    let valid = manifest(vec![
        source("trace.a", PilotSourceRole::Primary),
        source("trace_a", PilotSourceRole::Corroborating),
    ]);
    validate_pilot_manifest(&valid).expect("distinct portable names");
    assert_ne!(valid.sources[0].name, valid.sources[1].name);
}

#[test]
fn rejects_invalid_bearer_token_environment_variable_names() {
    for name in ["", " BAD", "1TOKEN", "TOKEN-NAME", "TOKEN.NAME"] {
        let mut primary = source("trace", PilotSourceRole::Primary);
        primary.kind = PilotSourceKind::HttpJson;
        primary.endpoint = "http://127.0.0.1:8080/source".to_string();
        primary.bearer_token_env = Some(name.to_string());
        let error = validate_pilot_manifest(&manifest(vec![primary]))
            .expect_err("invalid token environment variable name must fail");
        assert!(error.to_string().contains("environment variable name"));
    }
}

#[test]
fn rejects_bearer_declarations_for_non_http_sources() {
    let mut primary = source("trace", PilotSourceRole::Primary);
    primary.bearer_token_env = Some("SOURCE_TOKEN".to_string());
    let error = validate_pilot_manifest(&manifest(vec![primary]))
        .expect_err("non-HTTP bearer declaration must fail");
    assert!(error.to_string().contains("non-HTTP kind trace-file"));
}

#[test]
fn rejects_unbounded_or_inconsistent_collection_settings() {
    let invalid = [
        PilotCollection {
            timeout_secs: 0,
            ..PilotCollection::default()
        },
        PilotCollection {
            timeout_secs: 301,
            ..PilotCollection::default()
        },
        PilotCollection {
            lookback_secs: 0,
            ..PilotCollection::default()
        },
        PilotCollection {
            step_secs: 301,
            lookback_secs: 300,
            ..PilotCollection::default()
        },
        PilotCollection {
            packet_limit: crate::MAX_PCAP_PACKET_LIMIT + 1,
            ..PilotCollection::default()
        },
        PilotCollection {
            interval_secs: 11,
            ..PilotCollection::default()
        },
    ];
    for collection in invalid {
        let mut primary = source("trace", PilotSourceRole::Primary);
        primary.collection = collection;
        let error = validate_pilot_manifest(&manifest(vec![primary]))
            .expect_err("unbounded collection must fail");
        assert!(error.to_string().contains("pilot collection"));
    }
}

#[test]
fn rejects_excessive_source_count_and_total_adapter_execution_budget() {
    let too_many = (0..=MAX_PILOT_SOURCES)
        .map(|index| {
            source(
                &format!("source-{index}"),
                if index == 0 {
                    PilotSourceRole::Primary
                } else {
                    PilotSourceRole::Corroborating
                },
            )
        })
        .collect();
    let error =
        validate_pilot_manifest(&manifest(too_many)).expect_err("source count must be bounded");
    assert!(error.to_string().contains("more than"));

    let mut adapters = vec![
        source("adapter-a", PilotSourceRole::Primary),
        source("adapter-b", PilotSourceRole::Corroborating),
    ];
    for adapter in &mut adapters {
        adapter.kind = PilotSourceKind::AdapterSample;
        adapter.endpoint = format!("{}.py", adapter.name);
        adapter.collection.timeout_secs = 300;
        adapter.adapter.mode = Some(crate::pilot::PilotAdapterMode::Sample);
        adapter.metadata.insert(
            "adapter_contract".to_string(),
            "netdiag-adapter/v1".to_string(),
        );
    }
    let mut excessive_budget = manifest(adapters);
    excessive_budget.safety.adapter_execution_root = Some("adapters".to_string());
    let error = validate_pilot_manifest(&excessive_budget)
        .expect_err("aggregate adapter execution budget must be bounded");
    assert!(error.to_string().contains("budget"));
}

#[test]
fn adapter_boundary_declaration_rejects_missing_or_unbounded_paths() {
    let mut adapter = source("adapter", PilotSourceRole::Primary);
    adapter.kind = PilotSourceKind::AdapterSample;
    adapter.endpoint = "adapters/adapter.py".to_string();
    let mut manifest = manifest(vec![adapter]);

    let missing_root = validate_adapter_boundary_declaration(&manifest)
        .expect_err("adapter execution root is mandatory");
    assert!(missing_root.to_string().contains("must declare"));

    for root in [
        "".to_string(),
        std::env::current_dir()
            .expect("current directory")
            .display()
            .to_string(),
        "x".repeat(4 * 1024 + 1),
    ] {
        manifest.safety.adapter_execution_root = Some(root);
        let error = validate_adapter_boundary_declaration(&manifest)
            .expect_err("unsafe adapter execution root must fail");
        assert!(error.to_string().contains("bounded path relative"));
    }

    manifest.safety.adapter_execution_root = Some("adapters".to_string());
    for endpoint in [
        "".to_string(),
        std::env::current_dir()
            .expect("current directory")
            .join("adapter.py")
            .display()
            .to_string(),
        "x".repeat(4 * 1024 + 1),
    ] {
        manifest.sources[0].endpoint = endpoint;
        let error = validate_adapter_boundary_declaration(&manifest)
            .expect_err("unsafe adapter endpoint must fail");
        assert!(error.to_string().contains("endpoint must be"));
    }

    manifest.sources[0].endpoint = "adapters/adapter.py".to_string();
    validate_adapter_boundary_declaration(&manifest).expect("bounded adapter declaration");
}

#[test]
fn adapter_execution_budget_overflow_fails_explicitly() {
    let mut adapter = source("adapter", PilotSourceRole::Primary);
    adapter.kind = PilotSourceKind::AdapterSample;
    adapter.endpoint = "adapters/adapter.py".to_string();
    adapter.collection.timeout_secs = u64::MAX;
    let mut manifest = manifest(vec![adapter]);
    manifest.safety.adapter_execution_root = Some("adapters".to_string());

    let error = validate_adapter_boundary_declaration(&manifest)
        .expect_err("arithmetic overflow must fail closed");

    assert!(error.to_string().contains("budget overflowed"));
}

#[test]
fn rejects_schema_empty_name_and_non_unique_primary_role() {
    let mut invalid_schema = manifest(vec![source("trace", PilotSourceRole::Primary)]);
    invalid_schema.schema = "netdiag-pilot/v2".to_string();
    let schema_error = validate_pilot_manifest(&invalid_schema).expect_err("schema must fail");
    assert!(
        schema_error
            .to_string()
            .contains("unsupported pilot schema")
    );

    let mut empty_name = manifest(vec![source("trace", PilotSourceRole::Primary)]);
    empty_name.name = "  ".to_string();
    let name_error = validate_pilot_manifest(&empty_name).expect_err("empty name must fail");
    assert!(name_error.to_string().contains("name is empty"));

    let duplicate_primary = manifest(vec![
        source("trace-a", PilotSourceRole::Primary),
        source("trace-b", PilotSourceRole::Primary),
    ]);
    let primary_error =
        validate_pilot_manifest(&duplicate_primary).expect_err("two primaries must fail");
    assert!(primary_error.to_string().contains("exactly one primary"));
}
