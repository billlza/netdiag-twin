use super::*;
use crate::connector_auth::bearer_scope_for_endpoint;
use crate::secrets::{MemorySecretStore, SecretStore};
use netdiag_core::authentication::BearerSourceKind;

#[test]
fn uses_settings_before_environment_fallbacks() {
    let settings = AppSettings {
        api: ApiSettings {
            endpoint: "https://settings.example.test/traces".to_string(),
            timeout_secs: 14,
        },
        ..AppSettings::default()
    };
    let config = settings
        .api_config_with_env([
            (NETDIAG_API_URL_ENV, "https://env.example.test/traces"),
            (NETDIAG_API_TIMEOUT_SECONDS_ENV, "22"),
        ])
        .expect("api config");

    assert_eq!(config.endpoint, "https://settings.example.test/traces");
    assert_eq!(config.timeout_secs(), 14);
}

#[test]
fn falls_back_to_env_endpoint_and_timeout_without_implicit_authentication() {
    let settings = AppSettings {
        api: ApiSettings {
            endpoint: String::new(),
            timeout_secs: 0,
        },
        ..AppSettings::default()
    };
    let config = settings
        .api_config_with_env([
            (NETDIAG_API_URL_ENV, " https://env.example.test/traces "),
            (NETDIAG_API_TIMEOUT_SECONDS_ENV, "23"),
        ])
        .expect("api config");

    assert_eq!(config.endpoint, "https://env.example.test/traces");
    assert_eq!(config.timeout_secs(), 23);
}

#[test]
fn enforces_transport_and_sensitive_query_policy() {
    let settings = AppSettings::default();

    for endpoint in ["http://192.0.2.1/traces", "http://localhost:8080/traces"] {
        let error = settings
            .api_config_with_env([(NETDIAG_API_URL_ENV, endpoint)])
            .expect_err("remote or name-based plaintext endpoint must fail");
        assert!(error.to_string().contains("loopback IP literal"));
    }

    let query_secret = "opaque-query-secret";
    let error = settings
        .api_config_with_env([(
            NETDIAG_API_URL_ENV,
            format!("https://example.test/traces?token={query_secret}"),
        )])
        .expect_err("query credentials must fail at API config construction");
    assert!(error.to_string().contains("query parameters"));
    assert!(!error.to_string().contains(query_secret));

    let loopback_endpoint = "http://127.0.0.1:8080/traces";
    let loopback = settings
        .api_config_with_env([(NETDIAG_API_URL_ENV, loopback_endpoint)])
        .expect("loopback IP literal is an explicit local-development exception");
    assert_eq!(loopback.endpoint, "http://127.0.0.1:8080/traces");
}

#[test]
fn requires_endpoint_after_fallbacks() {
    let settings = AppSettings::default();
    let error = settings
        .api_config_with_env(std::iter::empty::<(&str, &str)>())
        .expect_err("missing endpoint");
    assert!(error.to_string().contains(NETDIAG_API_URL_ENV));
}

#[test]
fn rejects_invalid_timeout_and_empty_token() {
    let settings = AppSettings {
        api: ApiSettings {
            endpoint: "https://settings.example.test/traces".to_string(),
            timeout_secs: 0,
        },
        ..AppSettings::default()
    };
    let invalid_timeout = settings
        .api_config_with_env([(NETDIAG_API_TIMEOUT_SECONDS_ENV, "not-a-number")])
        .expect_err("invalid timeout must fail");
    assert!(
        invalid_timeout
            .to_string()
            .contains(NETDIAG_API_TIMEOUT_SECONDS_ENV)
    );

    let oversized_timeout = settings
        .api_config_with_env([(NETDIAG_API_TIMEOUT_SECONDS_ENV, "121")])
        .expect_err("oversized timeout must fail");
    assert!(oversized_timeout.to_string().contains("between 1 and 120"));

    let secrets = MemorySecretStore::new();
    let scope = bearer_scope_for_endpoint(
        "legacy_live_api",
        BearerSourceKind::HttpJson,
        "https://settings.example.test/traces",
    )
    .expect("scope");
    let empty_token = secrets
        .set_bearer_token(&scope, "  ")
        .expect_err("empty configured token must fail");
    assert!(empty_token.to_string().contains("ASCII whitespace"));
}

#[test]
fn api_config_never_materializes_or_echoes_a_stored_token() {
    let settings = AppSettings {
        api: ApiSettings {
            endpoint: "https://settings.example.test/traces".to_string(),
            timeout_secs: DEFAULT_API_TIMEOUT_SECS,
        },
        ..AppSettings::default()
    };
    let secrets = MemorySecretStore::new();

    let scope = bearer_scope_for_endpoint(
        "legacy_live_api",
        BearerSourceKind::HttpJson,
        "https://settings.example.test/traces",
    )
    .expect("scope");
    secrets
        .set_bearer_token(&scope, "secret-token")
        .expect("set token");
    let config = settings
        .api_config_with_env(std::iter::empty::<(&str, &str)>())
        .expect("api config");
    let token = secrets
        .get_bearer_token(&scope)
        .expect("read token")
        .expect("stored token");
    assert_eq!(token.as_str(), "secret-token");
    assert!(!format!("{token:?}").contains("secret-token"));
    assert!(!format!("{config:?}").contains("secret-token"));
}
