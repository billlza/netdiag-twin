use super::*;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
struct TypedMapping {
    values: BTreeMap<String, u64>,
}

#[test]
fn valid_nested_json_preserves_its_value() {
    let bytes = br#"{"records":[{"latency_ms":1.25,"healthy":true}],"note":null}"#;

    assert_eq!(
        parse_unique_value(bytes).expect("unique JSON"),
        json!({
            "records": [{"latency_ms": 1.25, "healthy": true}],
            "note": null
        })
    );
}

#[test]
fn duplicate_keys_are_rejected_recursively_without_echoing_them() {
    for bytes in [
        br#"{"private-token":"first","private-token":"second"}"#.as_slice(),
        br#"{"private\u002dtoken":"first","private-token":"second"}"#.as_slice(),
        br#"{"outer":{"private-token":"first","private-token":"second"}}"#.as_slice(),
        br#"[{"private-token":"first","private-token":"second"}]"#.as_slice(),
    ] {
        let error = parse_unique_value(bytes).expect_err("duplicate key must fail");
        let message = error.to_string();
        assert!(message.contains("duplicate key"), "{message}");
        assert!(!message.contains("private-token"), "{message}");
        assert!(!message.contains("first"), "{message}");
        assert!(!message.contains("second"), "{message}");
    }
}

#[test]
fn trailing_json_is_rejected() {
    let error = parse_unique_value(br#"{} {}"#).expect_err("trailing JSON must fail");
    assert!(error.to_string().contains("trailing characters"), "{error}");
}

#[test]
fn typed_deserialization_rejects_duplicates_inside_mapping_fields() {
    let error = from_slice::<TypedMapping>(br#"{"values":{"metric":1,"metric":2}}"#)
        .expect_err("duplicate typed mapping key must fail");
    assert!(error.to_string().contains("duplicate key"), "{error}");

    let parsed =
        from_slice::<TypedMapping>(br#"{"values":{"metric":1}}"#).expect("unique typed mapping");
    assert_eq!(parsed.values.get("metric"), Some(&1));
}

#[test]
fn safe_error_summary_never_echoes_invalid_typed_values() {
    let error = from_slice::<TypedMapping>(br#"{"values":{"metric":"private-value"}}"#)
        .expect_err("invalid typed value must fail");
    let summary = error_summary(&error);

    assert!(summary.contains("required JSON schema"), "{summary}");
    assert!(!summary.contains("private-value"), "{summary}");
    assert!(!summary.contains("metric"), "{summary}");
}

#[test]
fn non_finite_json_numbers_are_rejected() {
    for bytes in [
        b"1e400".as_slice(),
        b"NaN".as_slice(),
        b"Infinity".as_slice(),
    ] {
        assert!(parse_unique_value(bytes).is_err());
        assert!(from_slice::<Value>(bytes).is_err());
    }
}
