use super::{NetdiagError, PilotSourceKind, contract_sample_source, load_pilot_source};
use std::fs;
use tempfile::tempdir;

#[test]
fn adapter_phases_reject_duplicate_json_keys_without_echoing_them() {
    let temp = tempdir().expect("tempdir");
    let adapter = temp.path().join("adapter.py");
    let source = contract_sample_source(PilotSourceKind::AdapterSample, "adapter.py");

    fs::write(
        &adapter,
        r#"import sys
if "--preflight" in sys.argv:
    print('{"private-token":"first","private-token":"second"}')
    raise SystemExit(0)
raise SystemExit(0)
"#,
    )
    .expect("duplicate preflight adapter");
    let preflight_error = load_pilot_source(&source, temp.path())
        .err()
        .expect("duplicate preflight key must fail");
    assert_duplicate_key_error_is_secret_safe(&preflight_error);

    fs::write(
        &adapter,
        r#"import json
import sys
if "--preflight" in sys.argv:
    print(json.dumps({
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "source",
        "collection_mode": "sample",
        "passed": True,
        "checks": [{"name": "ready", "status": "ok"}],
        "health": {"status": "ok"},
        "redaction": {"fields": []}
    }))
    raise SystemExit(0)
print('{"private-token":"first","private-token":"second"}')
"#,
    )
    .expect("duplicate collection adapter");
    let collection_error = load_pilot_source(&source, temp.path())
        .err()
        .expect("duplicate collection key must fail");
    assert_duplicate_key_error_is_secret_safe(&collection_error);
}

fn assert_duplicate_key_error_is_secret_safe(error: &NetdiagError) {
    let message = error.to_string();
    assert!(message.contains("duplicate key"), "{message}");
    assert!(!message.contains("private-token"), "{message}");
    assert!(!message.contains("first"), "{message}");
    assert!(!message.contains("second"), "{message}");
}
