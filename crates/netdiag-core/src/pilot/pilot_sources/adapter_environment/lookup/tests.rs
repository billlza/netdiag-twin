use super::*;
use crate::pilot::{
    PilotAdapterMode, PilotAdapterOptions, PilotCollection, PilotSourceKind, PilotSourceRole,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::path::Path;

const RUNTIME_DIRECTORY: &str = "/private/netdiag-adapter-runtime";

fn source(environment: &[&str]) -> PilotSource {
    PilotSource {
        name: "adapter".to_string(),
        kind: PilotSourceKind::AdapterSample,
        endpoint: "adapter.py".to_string(),
        role: PilotSourceRole::Primary,
        active: false,
        bearer_token_env: None,
        mapping: None,
        collection: PilotCollection::default(),
        adapter: PilotAdapterOptions {
            mode: Some(PilotAdapterMode::Sample),
            args: vec!["--opaque=argument-secret".to_string()],
            env_allowlist: environment.iter().map(|name| (*name).to_string()).collect(),
        },
        metadata: BTreeMap::new(),
    }
}

#[test]
fn explicit_environment_is_bounded_sorted_and_selected_for_redaction() {
    let source = source(&["SHORT_SECRET", "LONG_SECRET", "DUPLICATE_SECRET"]);
    let environment = build_with_lookup(
        &source,
        "/trusted/bin",
        Path::new(RUNTIME_DIRECTORY),
        &mut |name| match name {
            "SHORT_SECRET" => Ok("short".to_string()),
            "LONG_SECRET" => Ok("a-much-longer-secret".to_string()),
            "DUPLICATE_SECRET" => Ok("short".to_string()),
            unexpected => panic!("unexpected lookup: {unexpected}"),
        },
    )
    .expect("bounded allowlisted environment");

    assert!(
        environment
            .entries()
            .contains(&("PATH".to_string(), "/trusted/bin".to_string()))
    );
    for name in SYSTEM_ENVIRONMENT {
        assert!(
            environment
                .entries()
                .contains(&(name.to_string(), RUNTIME_DIRECTORY.to_string()))
        );
    }
    assert_eq!(
        environment.redaction_values(),
        ["a-much-longer-secret", "argument-secret", "short"]
    );
}

#[test]
fn process_environment_wrapper_always_sets_sanitized_path() {
    let environment = build(&source(&[]), "/trusted/bin", Path::new(RUNTIME_DIRECTORY))
        .expect("process environment boundary");
    assert!(
        environment
            .entries()
            .contains(&("PATH".to_string(), "/trusted/bin".to_string()))
    );
}

#[test]
fn parent_temp_environment_is_never_inherited() {
    let source = source(&[]);
    let mut looked_up = Vec::new();
    let environment = build_with_lookup(
        &source,
        "/trusted/bin",
        Path::new(RUNTIME_DIRECTORY),
        &mut |name| {
            looked_up.push(name.to_string());
            Ok(match name {
                "TMPDIR" => "relative/attacker-tmp",
                "TMP" => "/attacker-controlled/tmp",
                "TEMP" => "../escape",
                unexpected => panic!("unexpected lookup: {unexpected}"),
            }
            .to_string())
        },
    )
    .expect("parent temp values must be ignored");

    assert!(looked_up.is_empty(), "parent temp environment was queried");
    for name in SYSTEM_ENVIRONMENT {
        assert_eq!(
            environment
                .entries()
                .iter()
                .find(|(candidate, _)| candidate == name)
                .map(|(_, value)| value.as_str()),
            Some(RUNTIME_DIRECTORY)
        );
    }
}

#[test]
fn relative_runtime_directory_is_rejected() {
    let error = build_with_lookup(
        &source(&[]),
        "/trusted/bin",
        Path::new("relative/runtime"),
        &mut |_| Err(VarError::NotPresent),
    )
    .expect_err("runtime directory must be absolute");
    assert!(error.to_string().contains("must be absolute"), "{error}");
}

#[cfg(unix)]
#[test]
fn non_unicode_runtime_directory_is_rejected() {
    let path = std::path::PathBuf::from(OsString::from_vec(vec![b'/', 0xff]));
    let error = build_with_lookup(&source(&[]), "/trusted/bin", &path, &mut |_| {
        Err(VarError::NotPresent)
    })
    .expect_err("runtime directory must be valid Unicode");
    assert!(error.to_string().contains("not valid Unicode"), "{error}");
}

#[test]
fn allowlisted_environment_rejects_invalid_values() {
    let source = source(&["SECRET"]);
    for (result, expected) in [
        (Err(VarError::NotPresent), "is not set"),
        (
            Err(VarError::NotUnicode(OsString::from("non-unicode"))),
            "not valid Unicode",
        ),
        (Ok(String::new()), "is empty"),
        (Ok("x".repeat(MAX_RUNTIME_ENV_VALUE_BYTES + 1)), "exceeds"),
    ] {
        let error = build_with_lookup(
            &source,
            "/trusted/bin",
            Path::new(RUNTIME_DIRECTORY),
            &mut |_| result.clone(),
        )
        .expect_err("invalid allowlisted environment must fail");
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn allowlisted_environment_total_size_is_bounded() {
    let source = source(&["ONE", "TWO", "THREE", "FOUR", "FIVE"]);
    let error = build_with_lookup(
        &source,
        "/trusted/bin",
        Path::new(RUNTIME_DIRECTORY),
        &mut |_| Ok("x".repeat(60 * 1024)),
    )
    .expect_err("combined allowlisted environment must be bounded");
    assert!(error.to_string().contains("allowed environment exceeds"));
}
