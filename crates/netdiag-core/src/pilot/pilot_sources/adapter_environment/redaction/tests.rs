use super::*;

#[test]
fn every_passthrough_value_is_selected_for_exact_redaction() {
    let arguments = vec![
        "--inline=opaque-inline".to_string(),
        "--label".to_string(),
        "opaque-next".to_string(),
        "opaque-positional".to_string(),
        "--negative".to_string(),
        "-42".to_string(),
        "-popaque-attached".to_string(),
        "-Dopaque-key=opaque-value".to_string(),
    ];

    let values = passthrough_redaction_values(&arguments);

    for expected in [
        "opaque-inline",
        "opaque-next",
        "opaque-positional",
        "-42",
        "opaque-attached",
        "opaque-key=opaque-value",
    ] {
        assert!(values.iter().any(|value| value == expected), "{expected}");
    }
    assert!(!values.iter().any(|value| value == "--inline"));
    assert!(!values.iter().any(|value| value == "--label"));
}

#[test]
fn short_equals_options_and_non_flag_prefixes_are_classified_fail_closed() {
    let arguments = vec![
        "-t=opaque-inline-short".to_string(),
        "-t".to_string(),
        "opaque-separated-short".to_string(),
        "-".to_string(),
        "-42".to_string(),
        "-令牌".to_string(),
    ];

    assert_eq!(
        passthrough_redaction_values(&arguments),
        [
            "-",
            "-42",
            "-令牌",
            "opaque-inline-short",
            "opaque-separated-short",
        ]
    );
}

#[test]
fn empty_long_option_name_still_selects_its_value_for_redaction() {
    let secret = "opaque-malformed-value";
    let values = passthrough_redaction_values(&[format!("--={secret}")]);

    assert_eq!(values, [secret]);
    assert!(
        !values
            .iter()
            .any(|value| value == "--=opaque-malformed-value")
    );
}

#[test]
fn argument_helpers_accept_only_supported_ascii_option_shapes() {
    for flag in ["--trace", "-t"] {
        assert!(is_flag(flag), "{flag}");
    }
    for positional in ["", "-", "-42", "-令牌", "trace"] {
        assert!(!is_flag(positional), "{positional}");
    }

    for option_name in ["--trace", "-t"] {
        assert!(is_separated_option_name(option_name), "{option_name}");
    }
    for invalid_name in ["--", "-", "-4", "-tt", "trace"] {
        assert!(!is_separated_option_name(invalid_name), "{invalid_name}");
    }

    assert_eq!(attached_short_option_value("-topaque"), Some("opaque"));
    for argument in ["-t", "--opaque", "-4opaque", "opaque"] {
        assert_eq!(attached_short_option_value(argument), None, "{argument}");
    }
}
