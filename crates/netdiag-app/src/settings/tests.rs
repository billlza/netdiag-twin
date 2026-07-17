use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

mod api;
mod store;
mod strict_json;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
const PRIVATE_INVALID_SETTINGS: &str = "{private-settings-sentinel}";

fn rejected_startup_recovery(store: &SettingsStore) -> (AppSettings, Option<String>) {
    let outcome = store.load_for_startup();
    assert_eq!(outcome.state, SettingsLoadState::Rejected);
    assert!(!outcome.startup_authorized());
    (outcome.settings, outcome.warning)
}

#[test]
fn defaults_are_product_safe() {
    let settings = AppSettings::default();
    validate_settings(&settings).expect("default settings must satisfy persistence bounds");
    assert_eq!(settings.language, LanguageSetting::Zh);
    assert_eq!(settings.default_source, DefaultSource::Simulation);
    assert_eq!(settings.last_imported_trace, None);
    assert_eq!(settings.simulation_scenario, SimScenario::Congestion);
    assert_eq!(settings.api.endpoint, "");
    assert_eq!(settings.api.timeout_secs, DEFAULT_API_TIMEOUT_SECS);
    assert!(settings.bearer_credentials.is_empty());
    assert_eq!(
        settings.data_connectors.default_connector,
        ConnectorKind::WebsiteProbe
    );
    assert_eq!(settings.data_connectors.website_probe.targets.len(), 3);
    assert!(settings.artifacts_root.ends_with("artifacts"));
    assert_eq!(settings.what_if.topology, "line");
    assert_eq!(settings.what_if.action, "reroute_path_b");
    assert_eq!(settings.startup.default_tab, StartupTab::Overview);
    assert!(settings.startup.auto_run_diagnosis);
    assert!(default_settings_path().ends_with("NetDiag Twin/settings.json"));
}

#[cfg(unix)]
#[test]
fn artifacts_root_symlink_is_rejected_before_settings_persistence() {
    use std::os::unix::fs::symlink;

    let settings_path = temp_settings_path();
    let parent = settings_path.parent().expect("settings parent");
    fs::create_dir_all(parent).expect("settings fixture root");
    let real_root = parent.join("real-artifacts");
    let linked_root = parent.join("linked-artifacts");
    fs::create_dir(&real_root).expect("real artifact root");
    symlink(&real_root, &linked_root).expect("artifact root symlink");
    let mut settings = AppSettings {
        artifacts_root: linked_root,
        ..AppSettings::default()
    };

    let error = SettingsStore::new(settings_path.clone())
        .save(&mut settings)
        .expect_err("artifact root symlink must be rejected");

    assert!(error.to_string().contains("not a link"), "{error}");
    assert!(!settings_path.exists());
    cleanup_temp_path(settings_path);
}

#[test]
fn default_profiles_cover_every_connector_kind_once() {
    let profiles = default_source_profiles();
    let mut kinds = profiles
        .iter()
        .map(|profile| profile.kind)
        .collect::<Vec<_>>();
    kinds.sort();

    let mut expected = ConnectorKind::ALL.to_vec();
    expected.sort();

    assert_eq!(kinds, expected);
    assert_eq!(profiles.len(), ConnectorKind::ALL.len());
    for profile in profiles {
        assert!(!profile.id.trim().is_empty());
        assert!(!profile.name.trim().is_empty());
        assert_eq!(profile.authentication, ConnectorAuthentication::None);
    }
}

#[test]
fn profile_authentication_is_explicit_and_limited_to_secure_http_sources() {
    let mut settings = AppSettings::default();
    let profile = settings
        .data_connectors
        .profiles
        .iter_mut()
        .find(|profile| profile.kind == ConnectorKind::HttpJson)
        .expect("HTTP profile");
    profile.http_json.endpoint = "https://collector.example.test/traces".to_string();
    profile.authentication = ConnectorAuthentication::BearerToken;
    validate_settings(&settings).expect("HTTPS bearer profile");

    let profile = settings
        .data_connectors
        .profiles
        .iter_mut()
        .find(|profile| profile.kind == ConnectorKind::HttpJson)
        .expect("HTTP profile");
    profile.http_json.endpoint = "http://collector.example.test/traces".to_string();
    let error = validate_settings(&settings).expect_err("remote plaintext bearer must fail");
    assert!(error.to_string().contains("requires HTTPS"));

    settings
        .data_connectors
        .profiles
        .iter_mut()
        .find(|profile| profile.kind == ConnectorKind::HttpJson)
        .expect("HTTP profile")
        .http_json
        .endpoint = "https://collector.example.test/traces".to_string();

    let profile = settings
        .data_connectors
        .profiles
        .iter_mut()
        .find(|profile| profile.kind == ConnectorKind::NativePcap)
        .expect("pcap profile");
    profile.authentication = ConnectorAuthentication::BearerToken;
    let error = validate_settings(&settings).expect_err("non-HTTP bearer must fail");
    assert!(
        error
            .to_string()
            .contains("cannot use bearer authentication")
    );
}

#[test]
fn bearer_credential_registry_is_bounded_canonical_and_has_one_active_scope_per_owner() {
    let owner = BearerCredentialOwner::profile("http_json_lab");
    let binding = BearerCredentialBinding {
        owner: owner.clone(),
        connector_kind: ConnectorKind::HttpJson,
        canonical_origin: "https://collector.example.test".to_string(),
        state: BearerCredentialState::Active,
    };
    let mut settings = AppSettings {
        bearer_credentials: vec![binding.clone()],
        ..AppSettings::default()
    };
    validate_settings(&settings).expect("valid non-secret credential registry");

    settings.bearer_credentials.push(BearerCredentialBinding {
        owner: owner.clone(),
        connector_kind: ConnectorKind::PrometheusQueryRange,
        canonical_origin: "https://metrics.example.test".to_string(),
        state: BearerCredentialState::Active,
    });
    let error = validate_settings(&settings).expect_err("one owner cannot have two active scopes");
    assert!(error.to_string().contains("multiple active"));

    settings.bearer_credentials = vec![BearerCredentialBinding {
        canonical_origin: "https://collector.example.test:443".to_string(),
        ..binding.clone()
    }];
    let error = validate_settings(&settings).expect_err("origin must use canonical default port");
    assert!(error.to_string().contains("not canonical"));

    settings.bearer_credentials = vec![binding; 131];
    let error = validate_settings(&settings).expect_err("registry must be bounded");
    assert!(error.to_string().contains("more than 130"));
}

#[test]
fn source_profile_id_cannot_collide_with_the_legacy_credential_scope() {
    let mut settings = AppSettings::default();
    settings.data_connectors.profiles[0].id = LEGACY_LIVE_API_SCOPE_ID.to_string();
    settings.data_connectors.active_profile_id = LEGACY_LIVE_API_SCOPE_ID.to_string();

    let error = validate_settings(&settings).expect_err("reserved credential scope collision");
    assert!(error.to_string().contains("reserved"));
}

#[test]
fn unknown_active_profile_never_selects_or_mutates_the_first_profile() {
    let mut connectors = DataConnectorsSettings::default();
    let first = connectors.profiles[0].clone();
    connectors.active_profile_id = "missing-profile".to_string();

    assert!(connectors.active_profile().is_none());
    assert!(connectors.active_profile_mut().is_none());
    assert_eq!(connectors.profiles[0], first);
}

#[test]
fn persisted_api_timeout_allows_env_fallback_zero_but_rejects_other_invalid_values() {
    let path = temp_settings_path();
    let store = SettingsStore::new(path.clone());
    let mut settings = AppSettings::default();
    settings.api.timeout_secs = 0;
    store
        .save(&mut settings)
        .expect("zero timeout must preserve explicit environment fallback semantics");

    settings.api.timeout_secs = 121;
    let error = store
        .save(&mut settings)
        .expect_err("out-of-range non-zero API timeout must fail before persistence");
    assert!(error.to_string().contains("between 1 and 120"));
    cleanup_temp_path(path);
}

#[test]
fn missing_nested_fields_use_product_defaults() {
    let settings: AppSettings =
        serde_json::from_str(r#"{"api":{},"what_if":{},"startup":{}}"#).expect("partial settings");
    assert_eq!(settings.api.timeout_secs, DEFAULT_API_TIMEOUT_SECS);
    assert_eq!(
        settings.data_connectors.default_connector,
        ConnectorKind::WebsiteProbe
    );
    assert_eq!(settings.what_if.topology, "line");
    assert_eq!(settings.what_if.action, "reroute_path_b");
    assert_eq!(settings.startup.default_tab, StartupTab::Overview);
    assert!(settings.startup.auto_run_diagnosis);
    assert!(settings.artifacts_root.ends_with("artifacts"));
}

#[test]
fn save_and_load_round_trips_without_token() {
    let path = temp_settings_path();
    let store = SettingsStore::new(path.clone());
    let mut settings = AppSettings {
        settings_generation: 0,
        language: LanguageSetting::En,
        default_source: DefaultSource::LiveApi,
        last_imported_trace: Some(PathBuf::from("/tmp/trace.json")),
        simulation_scenario: SimScenario::DnsFailure,
        api: ApiSettings {
            endpoint: "https://example.invalid/trace".to_string(),
            timeout_secs: 12,
        },
        data_connectors: DataConnectorsSettings {
            default_connector: ConnectorKind::HttpJson,
            ..DataConnectorsSettings::default()
        },
        bearer_credentials: Vec::new(),
        credential_cleanup: CredentialCleanupJournal::default(),
        artifacts_root: PathBuf::from("/tmp/netdiag-artifacts"),
        what_if: WhatIfSettings {
            topology: "mesh".to_string(),
            action: "isolate_node_c".to_string(),
            custom_topology: None,
        },
        startup: StartupSettings {
            default_tab: StartupTab::Settings,
            auto_run_diagnosis: false,
        },
    };

    store.save(&mut settings).expect("save settings");
    let raw = fs::read_to_string(&path).expect("settings json");
    assert!(!raw.contains("secret-token"));
    #[cfg(unix)]
    let settings = {
        let mut updated = settings;
        updated.language = LanguageSetting::Zh;
        store
            .save(&mut updated)
            .expect("atomically replace existing settings");
        updated
    };
    let loaded = store.load().expect("load settings");
    assert_eq!(loaded, settings);
    cleanup_temp_path(path);
}

#[test]
fn sensitive_endpoint_queries_are_rejected_before_settings_persistence() {
    let query_secret = "opaque-settings-query-secret";
    let variants = ["api_key", "AcCeSs-ToKeN", "password", "secret", "auth"];

    for (index, key) in variants.into_iter().enumerate() {
        let path = temp_settings_path().with_file_name(format!("settings-{index}.json"));
        let store = SettingsStore::new(path.clone());
        let mut settings = AppSettings::default();
        settings.api.endpoint = format!("https://example.test/source?{key}={query_secret}");

        let debug = format!("{settings:?}");
        assert!(!debug.contains(query_secret));
        assert!(debug.contains("redacted"));
        let error = store
            .save(&mut settings)
            .expect_err("sensitive endpoint query must fail before publication");
        assert!(error.to_string().contains("query parameters"));
        assert!(!error.to_string().contains(query_secret));
        assert!(!path.exists(), "invalid settings must not be persisted");

        write_settings_fixture(&path, &settings);
        let load_error = store
            .load()
            .expect_err("credential-bearing settings input must fail closed");
        assert!(load_error.to_string().contains("query parameters"));
        assert!(!load_error.to_string().contains(query_secret));
        let (loaded, warning) = rejected_startup_recovery(&store);
        assert_eq!(loaded, AppSettings::default());
        assert!(
            !warning
                .expect("visible validation warning")
                .contains(query_secret)
        );
        cleanup_temp_path(path);
    }
}

#[test]
fn every_persisted_connector_endpoint_rejects_sensitive_queries() {
    for endpoint_kind in 0..6 {
        let path = temp_settings_path().with_file_name(format!("settings-{endpoint_kind}.json"));
        let store = SettingsStore::new(path.clone());
        let mut settings = AppSettings::default();
        let endpoint = "https://example.test/source?authorization=opaque".to_string();
        match endpoint_kind {
            0 => settings.api.endpoint = endpoint,
            1 => settings.data_connectors.prometheus_query.base_url = endpoint,
            2 => settings.data_connectors.prometheus_exposition.endpoint = endpoint,
            3 => settings.data_connectors.profiles[0].http_json.endpoint = endpoint,
            4 => {
                settings.data_connectors.profiles[0]
                    .prometheus_query
                    .base_url = endpoint
            }
            5 => {
                settings.data_connectors.profiles[0]
                    .prometheus_exposition
                    .endpoint = endpoint
            }
            _ => unreachable!("bounded endpoint fixture"),
        }

        let error = store
            .save(&mut settings)
            .expect_err("connector endpoint query credential must fail before save");
        assert!(error.to_string().contains("query parameters"));
        assert!(!path.exists());
        cleanup_temp_path(path);
    }
}

#[test]
fn corrupt_json_enters_rejected_startup_recovery() {
    let path = temp_settings_path();
    fs::create_dir_all(path.parent().unwrap()).expect("settings dir");
    fs::write(&path, PRIVATE_INVALID_SETTINGS).expect("write corrupt settings");
    let store = SettingsStore::new(path.clone());

    let (settings, warning) = rejected_startup_recovery(&store);
    assert_eq!(settings, AppSettings::default());
    let warning = warning.expect("warning");
    assert!(
        warning.contains("not syntactically valid JSON"),
        "{warning}"
    );
    assert!(!warning.contains("private-settings-sentinel"), "{warning}");
    cleanup_temp_path(path);
}

#[test]
fn a_missing_settings_file_uses_defaults_without_an_error_warning() {
    let path = temp_settings_path();
    let store = SettingsStore::new(path.clone());

    let outcome = store.load_for_startup();

    assert_eq!(outcome.settings, AppSettings::default());
    assert_eq!(outcome.warning, None);
    assert_eq!(outcome.state, SettingsLoadState::Missing);
    assert!(outcome.startup_authorized());
    cleanup_temp_path(path);
}

#[test]
fn a_non_regular_settings_path_enters_rejected_startup_recovery() {
    let path = temp_settings_path();
    fs::create_dir_all(&path).expect("directory at settings path");
    let store = SettingsStore::new(path.clone());

    let (settings, warning) = rejected_startup_recovery(&store);

    assert_eq!(settings, AppSettings::default());
    assert!(
        warning
            .expect("non-regular settings warning")
            .contains("regular, non-symlink")
    );
    cleanup_temp_path(path);
}

#[test]
fn app_settings_load_from_path_rejects_corrupt_json() {
    let path = temp_settings_path();
    fs::create_dir_all(path.parent().unwrap()).expect("settings dir");
    fs::write(&path, PRIVATE_INVALID_SETTINGS).expect("write corrupt settings");

    let error = AppSettings::load_from_path(path.clone()).expect_err("corrupt settings must fail");
    let message = error.to_string();
    assert!(
        message.contains("not syntactically valid JSON"),
        "{message}"
    );
    assert!(!message.contains("private-settings-sentinel"), "{message}");
    cleanup_temp_path(path);
}

#[test]
fn oversized_settings_file_enters_rejected_startup_recovery_without_reading_it() {
    use std::fs::OpenOptions;

    let path = temp_settings_path();
    fs::create_dir_all(path.parent().expect("settings parent")).expect("settings dir");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("oversized settings fixture");
    file.set_len((MAX_SETTINGS_FILE_BYTES + 1) as u64)
        .expect("sparse oversized settings fixture");
    let store = SettingsStore::new(path.clone());

    let (settings, warning) = rejected_startup_recovery(&store);

    assert_eq!(settings, AppSettings::default());
    let warning = warning.expect("oversized settings warning");
    assert!(
        warning.contains("read limit"),
        "unexpected warning: {warning}"
    );
    cleanup_temp_path(path);
}

#[cfg(unix)]
#[test]
fn settings_symlink_enters_rejected_startup_recovery() {
    use std::os::unix::fs::symlink;

    let path = temp_settings_path();
    fs::create_dir_all(path.parent().expect("settings parent")).expect("settings dir");
    let target = path.with_file_name("target.json");
    fs::write(&target, b"{}").expect("settings target");
    symlink(&target, &path).expect("settings symlink");
    let store = SettingsStore::new(path.clone());

    let (settings, warning) = rejected_startup_recovery(&store);

    assert_eq!(settings, AppSettings::default());
    assert!(
        warning
            .expect("symlink settings warning")
            .contains("regular, non-symlink")
    );
    cleanup_temp_path(path);
}

#[test]
fn settings_profile_count_is_bounded_on_load_and_save() {
    let path = temp_settings_path();
    fs::create_dir_all(path.parent().expect("settings parent")).expect("settings dir");
    let mut settings = AppSettings::default();
    settings.data_connectors.profiles = vec![SourceProfile::default(); 65];
    fs::write(
        &path,
        serde_json::to_vec(&settings).expect("oversized profile settings JSON"),
    )
    .expect("oversized profile settings fixture");
    let store = SettingsStore::new(path.clone());

    let (loaded, warning) = rejected_startup_recovery(&store);

    assert_eq!(loaded, AppSettings::default());
    assert!(
        warning
            .expect("profile count warning")
            .contains("1..=64 source profiles")
    );
    assert!(
        store.save(&mut settings).is_err(),
        "save must enforce the same structural bound as load"
    );
    cleanup_temp_path(path);
}

#[test]
fn explicit_empty_profiles_are_not_silently_repaired() {
    let path = temp_settings_path();
    let mut settings = AppSettings::default();
    settings.data_connectors.profiles.clear();
    write_settings_fixture(&path, &settings);
    let store = SettingsStore::new(path.clone());

    let (loaded, warning) = rejected_startup_recovery(&store);

    assert_eq!(loaded, AppSettings::default());
    assert!(
        warning
            .expect("empty profile warning")
            .contains("1..=64 source profiles")
    );
    assert!(store.save(&mut settings).is_err());
    cleanup_temp_path(path);
}

#[test]
fn an_unknown_active_profile_is_not_silently_reassigned() {
    let path = temp_settings_path();
    let mut settings = AppSettings::default();
    settings.data_connectors.active_profile_id = "missing-profile".to_string();
    write_settings_fixture(&path, &settings);
    let store = SettingsStore::new(path.clone());

    let (loaded, warning) = rejected_startup_recovery(&store);

    assert_eq!(loaded, AppSettings::default());
    assert!(
        warning
            .expect("active profile warning")
            .contains("does not name a source profile")
    );
    assert!(store.save(&mut settings).is_err());
    cleanup_temp_path(path);
}

#[test]
fn aggregate_website_targets_are_bounded_on_load_and_save() {
    let path = temp_settings_path();
    let mut settings = AppSettings::default();
    settings.data_connectors.profiles = (0..64)
        .map(|index| SourceProfile {
            id: format!("profile-{index}"),
            name: format!("Profile {index}"),
            website_probe: WebsiteProbeSettings {
                targets: (0..64)
                    .map(|target| format!("https://target-{index}-{target}.example.invalid"))
                    .collect(),
                ..WebsiteProbeSettings::default()
            },
            ..SourceProfile::default()
        })
        .collect();
    settings.data_connectors.active_profile_id = "profile-0".to_string();
    write_settings_fixture(&path, &settings);
    let store = SettingsStore::new(path.clone());

    let (loaded, warning) = rejected_startup_recovery(&store);

    assert_eq!(loaded, AppSettings::default());
    assert!(
        warning
            .expect("aggregate target warning")
            .contains("website targets")
    );
    assert!(store.save(&mut settings).is_err());
    cleanup_temp_path(path);
}

#[test]
fn unsupported_mapping_fields_are_rejected_on_load_and_save() {
    let path = temp_settings_path();
    let mut settings = AppSettings::default();
    settings
        .data_connectors
        .prometheus_query
        .mapping
        .insert("unsupported-canonical-field".to_string(), "up".to_string());
    write_settings_fixture(&path, &settings);
    let store = SettingsStore::new(path.clone());

    let (loaded, warning) = rejected_startup_recovery(&store);

    assert_eq!(loaded, AppSettings::default());
    assert!(
        warning
            .expect("mapping semantic warning")
            .contains("unsupported canonical field")
    );
    assert!(store.save(&mut settings).is_err());
    cleanup_temp_path(path);
}

#[test]
fn aggregate_string_bytes_are_bounded_before_serialization() {
    let path = temp_settings_path();
    let mut settings = AppSettings::default();
    settings.data_connectors.profiles = (0..64)
        .map(|index| SourceProfile {
            id: format!("profile-{index}"),
            name: "n".repeat(16 * 1024),
            ..SourceProfile::default()
        })
        .collect();
    settings.data_connectors.active_profile_id = "profile-0".to_string();
    let store = SettingsStore::new(path.clone());

    let error = store
        .save(&mut settings)
        .expect_err("aggregate strings beyond one MiB must be rejected");

    assert!(error.to_string().contains("string bytes"));
    assert!(!path.exists(), "validation must happen before publication");
    cleanup_temp_path(path);
}

#[test]
fn compact_input_that_cannot_be_saved_within_the_limit_is_rejected_symmetrically() {
    let path = temp_settings_path();
    let mut settings = AppSettings::default();
    settings.what_if.custom_topology = Some(TopologyModel {
        key: "bounded-size-test".to_string(),
        name: "Bounded size test".to_string(),
        nodes: Vec::new(),
        links: Vec::new(),
        metadata: std::collections::BTreeMap::from([(
            "padding".to_string(),
            serde_json::Value::Array(vec![serde_json::Value::Bool(true); 100_000]),
        )]),
    });
    let raw = serde_json::to_vec(&settings).expect("compact settings fixture");
    assert!(
        raw.len() <= MAX_SETTINGS_FILE_BYTES,
        "fixture must pass the bounded file read"
    );
    fs::create_dir_all(path.parent().expect("settings parent")).expect("settings dir");
    fs::write(&path, raw).expect("compact settings fixture");
    let store = SettingsStore::new(path.clone());

    let (loaded, warning) = rejected_startup_recovery(&store);

    assert_eq!(loaded, AppSettings::default());
    assert!(
        warning
            .expect("serialized size warning")
            .contains("settings file limit")
    );
    assert!(
        store.save(&mut settings).is_err(),
        "save must enforce the same serialized representation limit"
    );
    cleanup_temp_path(path);
}

#[cfg(unix)]
#[test]
fn non_unicode_paths_are_rejected_instead_of_lossily_persisted() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let path = temp_settings_path();
    let mut settings = AppSettings {
        last_imported_trace: Some(PathBuf::from(OsString::from_vec(vec![0xff]))),
        ..AppSettings::default()
    };
    let store = SettingsStore::new(path.clone());

    let error = store
        .save(&mut settings)
        .expect_err("JSON persistence cannot preserve a non-Unicode path");

    assert!(error.to_string().contains("valid Unicode"));
    assert!(!path.exists());
    cleanup_temp_path(path);
}

#[test]
fn connector_settings_reject_out_of_range_resource_bounds() {
    assert!(LocalProbeSettings { samples: 0 }.validate().is_err());
    assert!(
        WebsiteProbeSettings {
            targets: vec!["https://example.test".to_string(); 65],
            samples_per_target: 1,
        }
        .validate()
        .is_err()
    );
    assert!(
        PrometheusQuerySettings {
            lookback_seconds: 60,
            step_seconds: 61,
            ..PrometheusQuerySettings::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        OtlpGrpcSettings {
            timeout_secs: 0,
            ..OtlpGrpcSettings::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        OtlpGrpcSettings {
            bind_addr: "0.0.0.0:4317".to_string(),
            ..OtlpGrpcSettings::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        NativePcapSettings {
            packet_limit: netdiag_core::MAX_PCAP_PACKET_LIMIT + 1,
            ..NativePcapSettings::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        SystemCountersSettings {
            interval_secs: 11,
            ..SystemCountersSettings::default()
        }
        .validate()
        .is_err()
    );
}

#[test]
fn website_probe_settings_reject_ambiguous_targets_without_echoing_secrets() {
    let target = "https://example.test/probe?access_token=private-value";
    let error = WebsiteProbeSettings {
        targets: vec![target.to_string()],
        samples_per_target: 1,
    }
    .validate()
    .expect_err("sensitive website target must fail before persistence");

    assert!(!error.to_string().contains(target), "{error}");
    assert!(!error.to_string().contains("private-value"), "{error}");
}

#[test]
fn persisted_otlp_bind_addresses_are_loopback_only_for_defaults_and_profiles() {
    let path = temp_settings_path();
    let store = SettingsStore::new(path.clone());
    let mut settings = AppSettings::default();
    settings.data_connectors.otlp_grpc.bind_addr = "192.0.2.1:4317".to_string();

    let default_error = store
        .save(&mut settings)
        .expect_err("non-loopback default OTLP bind must not persist");
    assert!(default_error.to_string().contains("loopback interface"));
    assert!(!path.exists());

    settings.data_connectors.otlp_grpc = OtlpGrpcSettings::default();
    let otlp_profile = settings
        .data_connectors
        .profiles
        .iter_mut()
        .find(|profile| profile.kind == ConnectorKind::OtlpGrpcReceiver)
        .expect("default OTLP profile");
    otlp_profile.otlp_grpc.bind_addr = "[::]:4317".to_string();
    let profile_error = store
        .save(&mut settings)
        .expect_err("non-loopback profile OTLP bind must not persist");
    assert!(profile_error.to_string().contains("loopback interface"));
    assert!(!path.exists());
    cleanup_temp_path(path);
}

fn temp_settings_path() -> PathBuf {
    let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    env::temp_dir()
        .join(format!(
            "netdiag-settings-test-{}-{nanos}-{id}",
            std::process::id()
        ))
        .join("settings.json")
}

fn write_settings_fixture(path: &Path, settings: &AppSettings) {
    fs::create_dir_all(path.parent().expect("settings parent")).expect("settings dir");
    fs::write(
        path,
        serde_json::to_vec(settings).expect("settings JSON fixture"),
    )
    .expect("settings fixture");
}

fn cleanup_temp_path(path: PathBuf) {
    if let Some(parent) = path.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}
