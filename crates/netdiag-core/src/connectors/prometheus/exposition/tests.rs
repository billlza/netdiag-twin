use super::*;

#[test]
fn quoted_braces_quotes_and_backslashes_do_not_end_labels_early() {
    let body = r#"netdiag_latency_ms{target="east}edge",note="quote: \" brace: \} slash: \\"} 42"#;

    let values = parse_prometheus_exposition(body, &mapping()).expect("quoted label content");

    assert_eq!(values["latency_ms"], 42.0);
}

#[test]
fn malformed_mapped_label_blocks_fail_without_payload_disclosure() {
    let sensitive = "private-label-value";
    for body in [
        format!(r#"netdiag_latency_ms{{target="{sensitive}}} 42"#),
        format!(r#"netdiag_latency_ms{{target="{sensitive}" 42"#),
        format!(r#"netdiag_latency_ms{{target="{sensitive}\"}} 42"#),
    ] {
        let error = parse_prometheus_exposition(&body, &mapping())
            .expect_err("unterminated mapped label block must fail");

        assert!(error.to_string().contains("unterminated label block"));
        assert!(!error.to_string().contains(sensitive));
    }
}

#[test]
fn malformed_unmapped_labels_do_not_override_a_valid_mapped_sample() {
    let body = r#"
unrelated_metric{target="unterminated
netdiag_latency_ms{target="lab"} 42
"#;

    let values = parse_prometheus_exposition(body, &mapping()).expect("mapped sample");

    assert_eq!(values["latency_ms"], 42.0);
}

#[test]
fn invalid_or_missing_mapped_values_fail_without_payload_disclosure() {
    let sensitive = "private-sample-value";
    for body in [
        format!(r#"netdiag_latency_ms{{target="lab"}} {sensitive}"#),
        r#"netdiag_latency_ms{target="lab"}"#.to_string(),
    ] {
        let error = parse_prometheus_exposition(&body, &mapping())
            .expect_err("invalid mapped sample must fail");

        assert!(error.to_string().contains("mapped metric"));
        assert!(!error.to_string().contains(sensitive));
    }
}

#[test]
fn multiple_mapped_series_remain_ambiguous() {
    let body = r#"
netdiag_latency_ms{target="one"} 41
netdiag_latency_ms{target="two"} 42
"#;

    let error = parse_prometheus_exposition(body, &mapping())
        .expect_err("multiple mapped series must fail");

    assert!(error.to_string().contains("multiple series"));
}

fn mapping() -> BTreeMap<String, String> {
    BTreeMap::from([("latency_ms".to_string(), "netdiag_latency_ms".to_string())])
}
