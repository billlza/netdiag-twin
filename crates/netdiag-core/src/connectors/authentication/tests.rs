use super::*;
use std::env::VarError;
use std::ffi::OsString;

fn declaration() -> BearerSourceDeclaration {
    BearerSourceDeclaration::new(
        "primary",
        BearerSourceKind::HttpJson,
        "https://Example.COM:443/path?safe=value",
        "SOURCE_TOKEN",
    )
    .expect("declaration")
}

fn binding() -> BearerEnvironmentBinding {
    BearerEnvironmentBinding::new(
        "primary",
        BearerSourceKind::HttpJson,
        "https://example.com/other",
        "SOURCE_TOKEN",
    )
    .expect("binding")
}

#[test]
fn canonical_origin_normalizes_host_default_port_and_path() {
    let origin =
        canonical_http_origin("https://Example.COM:443/a?safe=value").expect("canonical origin");
    assert_eq!(origin.as_str(), "https://example.com");
    assert_eq!(
        canonical_http_origin("http://[::1]:8080/path")
            .expect("IPv6 origin")
            .as_str(),
        "http://[::1]:8080"
    );
}

#[test]
fn declaration_alone_cannot_authorize_environment_lookup() {
    let declarations = [declaration()];
    let mut looked_up = false;
    let error = BearerEnvironmentBindings::default()
        .resolve_all_with_lookup(&declarations, |_| {
            looked_up = true;
            Ok("must-not-load".to_string())
        })
        .expect_err("declaration without external binding must fail");
    assert!(!looked_up);
    assert!(error.to_string().contains("not externally authorized"));
    assert!(!error.to_string().contains("must-not-load"));
}

#[test]
fn bindings_match_source_kind_origin_and_environment_exactly() {
    let declarations = [declaration()];
    for mismatched in [
        BearerEnvironmentBinding::new(
            "other",
            BearerSourceKind::HttpJson,
            "https://example.com",
            "SOURCE_TOKEN",
        )
        .expect("source mismatch"),
        BearerEnvironmentBinding::new(
            "primary",
            BearerSourceKind::PrometheusQuery,
            "https://example.com",
            "SOURCE_TOKEN",
        )
        .expect("kind mismatch"),
        BearerEnvironmentBinding::new(
            "primary",
            BearerSourceKind::HttpJson,
            "https://other.example",
            "SOURCE_TOKEN",
        )
        .expect("origin mismatch"),
        BearerEnvironmentBinding::new(
            "primary",
            BearerSourceKind::HttpJson,
            "https://example.com",
            "OTHER_TOKEN",
        )
        .expect("environment mismatch"),
    ] {
        let bindings = BearerEnvironmentBindings::new([mismatched]).expect("bindings");
        let mut looked_up = false;
        bindings
            .resolve_all_with_lookup(&declarations, |_| {
                looked_up = true;
                Ok("must-not-load".to_string())
            })
            .expect_err("mismatched binding must fail");
        assert!(!looked_up);
    }
}

#[test]
fn token_validation_is_exact_bounded_and_redacted() {
    let valid = validate_bearer_token("opaque-token".to_string()).expect("valid token");
    assert_eq!(valid.as_str(), "opaque-token");
    assert!(!format!("{valid:?}").contains("opaque-token"));

    for (invalid, secret_marker) in [
        (String::new(), ""),
        (" leading".to_string(), " leading"),
        ("trailing ".to_string(), "trailing "),
        ("line\nbreak".to_string(), "line\nbreak"),
        ("tab\tvalue".to_string(), "tab\tvalue"),
        ("x".repeat(MAX_BEARER_TOKEN_BYTES + 1), "xxxxxxxx"),
        ("control\u{7f}".to_string(), "control\u{7f}"),
    ] {
        let error = validate_bearer_token(invalid).expect_err("invalid token");
        if !secret_marker.is_empty() {
            assert!(!error.to_string().contains(secret_marker));
        }
    }
}

#[test]
fn token_validation_rejects_header_injection_without_disclosing_input() {
    for (injected, marker) in [
        ("private\r\nx-injected: true", "x-injected"),
        ("private\nset-cookie: secret", "set-cookie"),
        ("private\0suffix", "suffix"),
    ] {
        let error = validate_bearer_token(injected.to_string())
            .expect_err("HTTP header injection must be rejected");
        assert!(!error.to_string().contains(marker));
    }
}

#[test]
fn resolution_rejects_missing_non_unicode_and_invalid_values_without_disclosure() {
    let bindings = BearerEnvironmentBindings::new([binding()]).expect("bindings");
    let declarations = [declaration()];
    for result in [
        Err(VarError::NotPresent),
        Err(VarError::NotUnicode(OsString::from(
            "private-non-unicode-marker",
        ))),
        Ok("secret value".to_string()),
    ] {
        let error = bindings
            .resolve_all_with_lookup(&declarations, |_| result.clone())
            .expect_err("environment failure");
        let message = error.to_string();
        assert!(!message.contains("private-non-unicode-marker"));
        assert!(!message.contains("secret value"));
    }
}

#[test]
fn exact_binding_resolves_without_exposing_token_in_debug_output() {
    let bindings = BearerEnvironmentBindings::new([binding()]).expect("bindings");
    let declarations = [declaration()];
    let resolved = bindings
        .resolve_all_with_lookup(&declarations, |name| {
            assert_eq!(name, "SOURCE_TOKEN");
            Ok("opaque-token".to_string())
        })
        .expect("resolved token");
    assert_eq!(
        resolved
            .token_for(&declarations[0])
            .expect("resolved identity")
            .as_str(),
        "opaque-token"
    );
    assert!(!format!("{resolved:?}").contains("opaque-token"));
}

#[test]
fn bearer_binding_rejects_insecure_remote_transport() {
    let error = BearerEnvironmentBinding::new(
        "primary",
        BearerSourceKind::HttpJson,
        "http://example.com/path",
        "SOURCE_TOKEN",
    )
    .expect_err("remote HTTP bearer binding must fail");
    assert!(error.to_string().contains("requires HTTPS"));
}
