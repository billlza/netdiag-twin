use super::*;
use crate::connectors::authentication::{BearerEnvironmentBinding, BearerEnvironmentBindings};
use crate::pilot::{PilotAdapterOptions, PilotCollection, PilotSourceRole};
use std::collections::BTreeMap;

fn source(
    name: &str,
    kind: PilotSourceKind,
    endpoint: &str,
    bearer_token_env: Option<&str>,
) -> PilotSource {
    PilotSource {
        name: name.to_string(),
        kind,
        endpoint: endpoint.to_string(),
        role: PilotSourceRole::Primary,
        active: false,
        bearer_token_env: bearer_token_env.map(str::to_owned),
        mapping: None,
        collection: PilotCollection::default(),
        adapter: PilotAdapterOptions::default(),
        metadata: BTreeMap::new(),
    }
}

#[test]
fn source_kind_mapping_and_names_cover_every_pilot_source_kind() {
    let cases = [
        (PilotSourceKind::TraceFile, None, "trace-file"),
        (PilotSourceKind::AdapterSample, None, "adapter-sample"),
        (
            PilotSourceKind::HttpJson,
            Some(BearerSourceKind::HttpJson),
            "http-json",
        ),
        (
            PilotSourceKind::PrometheusQuery,
            Some(BearerSourceKind::PrometheusQuery),
            "prometheus-query",
        ),
        (
            PilotSourceKind::PrometheusMetrics,
            Some(BearerSourceKind::PrometheusMetrics),
            "prometheus-metrics",
        ),
        (PilotSourceKind::OtlpGrpc, None, "otlp-grpc"),
        (PilotSourceKind::NativePcap, None, "native-pcap"),
        (PilotSourceKind::SystemCounters, None, "system-counters"),
    ];

    for (kind, expected_bearer_kind, expected_name) in cases {
        assert_eq!(bearer_source_kind(kind), expected_bearer_kind, "{kind:?}");
        assert_eq!(source_kind_name(kind), expected_name, "{kind:?}");
    }
}

#[test]
fn token_lookup_distinguishes_absent_authentication_from_an_exact_resolved_token() {
    let unauthenticated = source(
        "public-metrics",
        PilotSourceKind::PrometheusMetrics,
        "https://metrics.example/public",
        None,
    );
    assert!(
        token_for_source(&unauthenticated, &ResolvedBearerTokens::default())
            .expect("unauthenticated source")
            .is_none()
    );

    let authenticated = source(
        "private-metrics",
        PilotSourceKind::PrometheusMetrics,
        "https://metrics.example/private",
        Some("METRICS_TOKEN"),
    );
    let declaration = declaration(&authenticated)
        .expect("valid declaration")
        .expect("authenticated declaration");
    let bindings = BearerEnvironmentBindings::new([BearerEnvironmentBinding::new(
        "private-metrics",
        BearerSourceKind::PrometheusMetrics,
        "https://metrics.example/another-path",
        "METRICS_TOKEN",
    )
    .expect("binding")])
    .expect("bindings");
    let resolved = bindings
        .resolve_all_with_lookup(std::slice::from_ref(&declaration), |name| {
            assert_eq!(name, "METRICS_TOKEN");
            Ok("opaque-token".to_string())
        })
        .expect("resolved token");

    assert_eq!(
        token_for_source(&authenticated, &resolved)
            .expect("token lookup")
            .map(ValidatedBearerToken::as_str),
        Some("opaque-token")
    );
}

#[test]
fn token_lookup_preserves_declaration_and_resolution_errors() {
    let authenticated = source(
        "private-query",
        PilotSourceKind::PrometheusQuery,
        "https://metrics.example/internal-path?scope=read",
        Some("QUERY_TOKEN"),
    );
    let unresolved = token_for_source(&authenticated, &ResolvedBearerTokens::default())
        .expect_err("declared bearer token must be resolved first");
    let unresolved_message = unresolved.to_string();
    assert!(unresolved_message.contains("bearer token was not resolved"));
    assert!(unresolved_message.contains("private-query"));
    assert!(unresolved_message.contains("QUERY_TOKEN"));
    assert!(!unresolved_message.contains("internal-path"));
    assert!(!unresolved_message.contains("scope=read"));

    let unsupported = source(
        "packet-capture",
        PilotSourceKind::NativePcap,
        "en0",
        Some("PCAP_TOKEN"),
    );
    let declaration_error = token_for_source(&unsupported, &ResolvedBearerTokens::default())
        .expect_err("non-HTTP source must reject bearer authentication");
    let declaration_message = declaration_error.to_string();
    assert!(declaration_message.contains("packet-capture"));
    assert!(declaration_message.contains("non-HTTP kind native-pcap"));
}
