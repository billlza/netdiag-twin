use super::*;
use crate::commands::collect::load_mapping;
use crate::commands::collect_auth::optional_bearer_token_from_lookup;
use netdiag_core::authentication::ValidatedBearerToken;
use netdiag_core::connectors::default_prometheus_mapping;
use netdiag_core::ingest::ingest_trace;
use netdiag_core::ml::train_model_from_jsonl;
#[cfg(unix)]
use std::ffi::OsString;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

fn sample(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/samples")
        .join(format!("{name}.csv"))
}

fn path_str(path: &std::path::Path) -> &str {
    path.to_str().expect("test path is utf-8")
}

fn repo_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

fn provision_test_model(artifacts: &std::path::Path) {
    netdiag_core::storage::ensure_artifact_root_owned(artifacts).expect("owned artifacts dir");
    let dataset_path = artifacts.join("training.jsonl");
    let mut dataset = fs::File::create(&dataset_path).expect("create dataset");
    for name in [
        "normal",
        "congestion",
        "random_loss",
        "dns_failure",
        "tls_failure",
        "udp_quic_blocked",
    ] {
        let ingest = ingest_trace(sample(name)).expect("sample ingest");
        let row = serde_json::json!({
            "label": name,
            "records": ingest.records,
        });
        writeln!(dataset, "{row}").expect("write training row");
    }
    train_model_from_jsonl(&dataset_path, artifacts.join("model")).expect("train model");
}

#[test]
fn artifact_root_initialize_is_idempotent_and_rejects_unowned_content() {
    let root = tempfile::tempdir().expect("temporary parent");
    let artifacts = root.path().join("new-artifacts");

    for _ in 0..2 {
        run(Args::parse_from([
            "netdiag",
            "artifact-root",
            "initialize",
            "--artifacts",
            path_str(&artifacts),
        ]))
        .expect("initialize empty or already-owned artifact root");
    }
    assert!(artifacts.join(".netdiag-artifact-root.json").is_file());

    let unrelated = root.path().join("unrelated");
    fs::create_dir(&unrelated).expect("unrelated directory");
    fs::write(unrelated.join("notes.txt"), b"preserve me").expect("unrelated fixture");
    let error = run(Args::parse_from([
        "netdiag",
        "artifact-root",
        "initialize",
        "--artifacts",
        path_str(&unrelated),
    ]))
    .expect_err("non-empty unowned root must not be initialized");
    assert!(format!("{error:#}").contains("non-empty"), "{error:#}");
    assert!(!unrelated.join(".netdiag-artifact-root.json").exists());
    assert_eq!(
        fs::read(unrelated.join("notes.txt")).expect("preserved unrelated file"),
        b"preserve me"
    );
}

#[cfg(unix)]
#[test]
fn artifact_root_initialize_rejects_non_utf8_path_before_mutation() {
    let root = tempfile::tempdir().expect("temporary parent");
    let artifacts = root
        .path()
        .join(OsString::from_vec(b"non-utf8-artifacts-\xff".to_vec()));

    let error = run(Args::parse_from([
        OsString::from("netdiag"),
        OsString::from("artifact-root"),
        OsString::from("initialize"),
        OsString::from("--artifacts"),
        artifacts.as_os_str().to_owned(),
    ]))
    .expect_err("non-UTF-8 output path must fail before artifact-root initialization");

    assert!(
        error.to_string().contains("must be valid UTF-8"),
        "{error:#}"
    );
    assert!(
        !artifacts.exists(),
        "a path that cannot be represented in the JSON result was mutated"
    );
}

#[test]
fn artifact_root_migrate_claims_a_validated_legacy_root() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    let first_run = netdiag_core::diagnose_file(sample("normal"), root.path(), None)
        .expect("migration fixture");
    fs::remove_file(root.path().join(".netdiag-artifact-root.json"))
        .expect("remove current ownership marker from fixture");

    run(Args::parse_from([
        "netdiag",
        "artifact-root",
        "migrate",
        "--artifacts",
        path_str(root.path()),
    ]))
    .expect("explicit legacy root migration");

    assert!(root.path().join(".netdiag-artifact-root.json").is_file());
    assert!(root.path().join("runs").join(first_run.run_id).is_dir());
    netdiag_core::diagnose_file(sample("normal"), root.path(), None)
        .expect("normal diagnosis after migration");
}

#[test]
fn artifact_root_migrate_rejects_an_arbitrary_directory_without_claiming_it() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    fs::write(root.path().join("notes.txt"), b"not a product artifact")
        .expect("unrelated file fixture");

    let error = run(Args::parse_from([
        "netdiag",
        "artifact-root",
        "migrate",
        "--artifacts",
        path_str(root.path()),
    ]))
    .expect_err("arbitrary root must fail migration");
    let message = format!("{error:#}");

    assert!(message.contains("unsupported entry"), "{message}");
    assert!(!root.path().join(".netdiag-artifact-root.json").exists());
    assert_eq!(
        fs::read(root.path().join("notes.txt")).expect("unrelated file remains"),
        b"not a product artifact"
    );
}

fn write_authenticated_pilot(path: &std::path::Path, environment: &str) {
    fs::write(
        path,
        format!(
            r#"schema: netdiag-pilot/v1
id: cli-auth-pilot
name: CLI authenticated pilot
sources:
  - name: gateway
    kind: http_json
    endpoint: http://127.0.0.1:1/adapter
    role: primary
    bearer_token_env: {environment}
"#
        ),
    )
    .expect("authenticated pilot manifest");
}

fn write_authenticated_lab_scenario(path: &std::path::Path, environment: &str) {
    fs::write(
        path,
        format!(
            r#"schema: netdiag-lab-scenario/v1
id: cli-auth-lab
name: CLI authenticated lab
data_sources:
  - name: gateway
    role: primary
    kind: http-json
    endpoint: http://127.0.0.1:1/adapter
    bearer_token_env: {environment}
"#
        ),
    )
    .expect("authenticated lab scenario");
}

fn bearer_binding_arguments(environment: &str) -> [&str; 6] {
    [
        "--bearer-binding",
        "gateway",
        "http-json",
        "http://127.0.0.1:1",
        environment,
        "--artifacts",
    ]
}

#[test]
fn top_level_pilot_command_dispatches_to_pilot_module() {
    let temp = tempfile::tempdir().expect("tempdir");
    provision_test_model(temp.path());
    let args = Args::parse_from([
        "netdiag",
        "pilot",
        "preflight",
        path_str(&repo_file("examples/pilots/connector-family-readonly.yaml")),
        "--artifacts",
        path_str(temp.path()),
    ]);

    run(args).expect("pilot preflight dispatch");
}

#[test]
fn pilot_static_preflight_accepts_an_exact_cli_bearer_binding_without_environment_access() {
    const ENVIRONMENT: &str = "NETDIAG_CLI_STATIC_PREFLIGHT_TOKEN_05_3";
    assert!(std::env::var_os(ENVIRONMENT).is_none());
    let temp = tempfile::tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    let pilot = temp.path().join("pilot.yaml");
    provision_test_model(&artifacts);
    write_authenticated_pilot(&pilot, ENVIRONMENT);
    let mut arguments = vec![
        "netdiag".to_string(),
        "pilot".to_string(),
        "preflight".to_string(),
        path_str(&pilot).to_string(),
    ];
    arguments.extend(bearer_binding_arguments(ENVIRONMENT).map(str::to_string));
    arguments.push(path_str(&artifacts).to_string());

    run(Args::parse_from(arguments)).expect("static pilot preflight");
}

#[test]
fn pilot_run_and_workflow_resolve_cli_binding_before_network_or_staging() {
    const ENVIRONMENT: &str = "NETDIAG_CLI_MISSING_PILOT_TOKEN_05_3";
    assert!(std::env::var_os(ENVIRONMENT).is_none());
    let temp = tempfile::tempdir().expect("tempdir");
    let pilot = temp.path().join("pilot.yaml");
    write_authenticated_pilot(&pilot, ENVIRONMENT);

    for subcommand in ["run", "workflow"] {
        let artifacts = temp.path().join(format!("{subcommand}-artifacts"));
        provision_test_model(&artifacts);
        let mut arguments = vec![
            "netdiag".to_string(),
            "pilot".to_string(),
            subcommand.to_string(),
            path_str(&pilot).to_string(),
        ];
        arguments.extend(bearer_binding_arguments(ENVIRONMENT).map(str::to_string));
        arguments.push(path_str(&artifacts).to_string());

        let error = run(Args::parse_from(arguments)).expect_err("missing token must fail");
        assert!(format!("{error:#}").contains("is not set"), "{error:#}");
        assert!(
            !artifacts.join("pilot-runs").exists(),
            "{subcommand} must resolve credentials before staging"
        );
    }
}

#[test]
fn lab_preflight_run_and_batch_use_explicit_cli_bearer_bindings() {
    const ENVIRONMENT: &str = "NETDIAG_CLI_MISSING_LAB_TOKEN_05_3";
    assert!(std::env::var_os(ENVIRONMENT).is_none());
    let temp = tempfile::tempdir().expect("tempdir");
    let scenario = temp.path().join("scenario.yaml");
    write_authenticated_lab_scenario(&scenario, ENVIRONMENT);

    let static_artifacts = temp.path().join("static-artifacts");
    let mut preflight_arguments = vec![
        "netdiag".to_string(),
        "lab".to_string(),
        "preflight".to_string(),
        path_str(&scenario).to_string(),
    ];
    preflight_arguments.extend(bearer_binding_arguments(ENVIRONMENT).map(str::to_string));
    preflight_arguments.push(path_str(&static_artifacts).to_string());
    run(Args::parse_from(preflight_arguments)).expect("static lab preflight");

    for subcommand in ["run", "batch"] {
        let artifacts = temp.path().join(format!("{subcommand}-artifacts"));
        let mut arguments = vec![
            "netdiag".to_string(),
            "lab".to_string(),
            subcommand.to_string(),
            path_str(&scenario).to_string(),
        ];
        arguments.extend(bearer_binding_arguments(ENVIRONMENT).map(str::to_string));
        arguments.push(path_str(&artifacts).to_string());

        let error = run(Args::parse_from(arguments)).expect_err("missing token must fail");
        assert!(format!("{error:#}").contains("is not set"), "{error:#}");
        assert!(
            !artifacts.join("lab-runs").exists(),
            "{subcommand} must resolve credentials before staging"
        );
    }
}

#[test]
fn mismatched_cli_bearer_origin_fails_before_environment_lookup() {
    let temp = tempfile::tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    let pilot = temp.path().join("pilot.yaml");
    provision_test_model(&artifacts);
    write_authenticated_pilot(&pilot, "PATH");
    let error = run(Args::parse_from([
        "netdiag",
        "pilot",
        "preflight",
        path_str(&pilot),
        "--bearer-binding",
        "gateway",
        "http-json",
        "https://different.example.test",
        "PATH",
        "--artifacts",
        path_str(&artifacts),
    ]))
    .expect_err("mismatched origin must fail");
    let message = format!("{error:#}");
    assert!(message.contains("not externally authorized"), "{message}");
    assert!(!message.contains(&std::env::var("PATH").expect("PATH")));
}

#[test]
fn explicit_bearer_binding_is_fail_closed_and_never_leaks_token_material() {
    let absent = optional_bearer_token_from_lookup(
        "http-json",
        "https://collector.example.test/traces",
        None,
        |_| panic!("no binding must not read the environment"),
    )
    .expect("absent binding is unauthenticated");
    assert!(absent.is_none());

    let token = optional_bearer_token_from_lookup(
        "http-json",
        "https://collector.example.test/traces",
        Some("SOURCE_TOKEN"),
        |name| {
            assert_eq!(name, "SOURCE_TOKEN");
            Ok("opaque-token".to_string())
        },
    )
    .expect("exact binding");
    assert_eq!(
        token.as_ref().map(ValidatedBearerToken::as_str),
        Some("opaque-token")
    );

    let empty = optional_bearer_token_from_lookup(
        "http-json",
        "https://collector.example.test/traces",
        Some("SOURCE_TOKEN"),
        |_| Ok("   ".to_string()),
    )
    .expect_err("whitespace token must fail");
    assert!(empty.to_string().contains("ASCII whitespace"));

    let secret = "non-unicode-token-sentinel";
    let non_unicode = optional_bearer_token_from_lookup(
        "http-json",
        "https://collector.example.test/traces",
        Some("SOURCE_TOKEN"),
        |_| {
            Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
                secret,
            )))
        },
    )
    .expect_err("non-Unicode token must fail");
    let message = non_unicode.to_string();
    assert!(message.contains("not valid Unicode"));
    assert!(!message.contains(secret));

    let non_http =
        optional_bearer_token_from_lookup("native-pcap", "iface:en0", Some("SOURCE_TOKEN"), |_| {
            panic!("non-HTTP binding must fail before environment lookup")
        })
        .expect_err("non-HTTP connector must reject bearer binding");
    assert!(non_http.to_string().contains("only valid"));

    let invalid_name = optional_bearer_token_from_lookup(
        "http-json",
        "https://collector.example.test/traces",
        Some("INVALID-NAME"),
        |_| panic!("invalid environment name must fail before lookup"),
    )
    .expect_err("invalid environment name");
    assert!(
        invalid_name
            .to_string()
            .contains("environment variable name")
    );
}

#[test]
fn dataset_split_cli_rejects_non_finite_negative_and_out_of_range_ratios() {
    for value in ["NaN", "inf", "-inf", "-0.01", "1", "1.01"] {
        let error = Args::try_parse_from([
            "netdiag",
            "dataset",
            "split",
            "feedback.jsonl",
            "--validation-ratio",
            value,
        ])
        .expect_err("invalid ratio must be rejected while parsing CLI arguments");
        assert!(
            error.to_string().contains("finite and in [0, 1)"),
            "{value}: {error}"
        );
    }

    Args::try_parse_from([
        "netdiag",
        "dataset",
        "split",
        "feedback.jsonl",
        "--validation-ratio",
        "0.99",
        "--test-ratio",
        "0",
    ])
    .expect("valid boundary ratios parse");
}

#[test]
fn collect_cli_enforces_native_pcap_and_counter_bounds_without_clamping() {
    for packet_limit in [
        "0".to_string(),
        (netdiag_core::MAX_PCAP_PACKET_LIMIT + 1).to_string(),
    ] {
        let args = Args::try_parse_from([
            "netdiag",
            "collect",
            "--kind",
            "native-pcap",
            "--endpoint",
            "iface:lo0",
            "--packet-limit",
            &packet_limit,
        ])
        .expect("integer packet limit must parse before Core validation");
        let error = run(args).expect_err("invalid packet limit must fail before source access");
        assert!(error.to_string().contains("packet limit"), "{error}");
    }

    for interval in ["0", "11"] {
        Args::try_parse_from([
            "netdiag",
            "collect",
            "--kind",
            "system-counters",
            "--endpoint",
            "all",
            "--interval-secs",
            interval,
        ])
        .expect_err("invalid system-counter interval must fail during CLI parsing");
    }

    for packet_limit in [
        "1".to_string(),
        netdiag_core::MAX_PCAP_PACKET_LIMIT.to_string(),
    ] {
        Args::try_parse_from([
            "netdiag",
            "collect",
            "--kind",
            "native-pcap",
            "--endpoint",
            "iface:lo0",
            "--packet-limit",
            &packet_limit,
        ])
        .expect("native pcap boundary must parse");
    }
}

#[test]
fn cli_mapping_loader_preserves_default_and_explicit_file_paths() {
    let default = load_mapping(None).expect("default mapping");
    assert_eq!(default, default_prometheus_mapping());

    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("mapping.json");
    fs::write(&path, br#"{"latency_ms":"latency_seconds"}"#).expect("mapping fixture");
    let explicit = load_mapping(Some(path)).expect("explicit mapping");
    assert_eq!(explicit["latency_ms"], "latency_seconds");
}

#[test]
fn cli_mapping_loader_keeps_missing_files_as_errors() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("missing.json");

    let error = load_mapping(Some(path.clone())).expect_err("missing mapping must fail");
    let message = format!("{error:#}");

    assert!(message.contains("failed to load mapping file"), "{message}");
    assert!(
        message.contains("Prometheus mapping file is missing"),
        "{message}"
    );
    assert!(message.contains(&path.display().to_string()), "{message}");
}
