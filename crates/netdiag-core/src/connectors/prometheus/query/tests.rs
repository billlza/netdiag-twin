use super::*;

#[test]
fn matrix_response_requires_explicit_matrix_result_type() {
    for result_type in [
        "vector",
        "scalar",
        "Matrix",
        "matrix ",
        "private-result-type",
    ] {
        let response = format!(
            r#"{{"status":"success","data":{{"resultType":"{result_type}","result":[]}}}}"#
        );
        let error = parse_matrix_response(response.as_bytes())
            .expect_err("non-matrix resultType must fail");

        assert_eq!(
            error.to_string(),
            "connector error: Prometheus query_range success response must use matrix resultType"
        );
    }
}

#[test]
fn matrix_response_requires_success_data() {
    for response in [
        br#"{"status":"success"}"#.as_slice(),
        br#"{"status":"success","data":null}"#.as_slice(),
    ] {
        let error = parse_matrix_response(response).expect_err("success data must be present");

        assert!(
            error
                .to_string()
                .contains("success response is missing data")
        );
    }
}

#[test]
fn matrix_response_requires_result_type_and_result_fields() {
    let sensitive = "private-matrix-value";
    let responses = [
        r#"{"status":"success","data":{"result":[]}}"#.to_string(),
        r#"{"status":"success","data":{"resultType":null,"result":[]}}"#.to_string(),
        format!(
            r#"{{"status":"success","data":{{"resultType":"matrix","private":"{sensitive}"}}}}"#
        ),
    ];

    for response in responses {
        let error = parse_matrix_response(response.as_bytes())
            .expect_err("matrix response fields must be explicit");
        let message = error.to_string();

        assert!(message.contains("does not match the expected JSON schema"));
        assert!(!message.contains(sensitive));
    }
}

#[test]
fn matrix_response_accepts_a_valid_matrix() {
    let series = parse_matrix_response(
        br#"{
            "status":"success",
            "data":{
                "resultType":"matrix",
                "result":[{"metric":{"job":"fixture"},"values":[[1.0,"42"]]}]
            }
        }"#,
    )
    .expect("valid matrix response");

    assert_eq!(series.len(), 1);
    assert_eq!(
        series[0].values,
        vec![vec![Value::from(1.0), Value::from("42")]]
    );
}

#[test]
fn malformed_response_json_and_matrix_shape_are_redacted() {
    let sensitive = "private-response-value";
    let responses = [
        format!(
            r#"{{"status":"success","data":{{"resultType":"matrix","result":"{sensitive}"}}}}"#
        ),
        format!(
            r#"{{"status":"success","data":{{"resultType":{{"value":"{sensitive}"}},"result":[]}}}}"#
        ),
        format!(
            r#"{{"status":"success","data":{{"resultType":"matrix","result":[]}},"trailing":"ok"}} {sensitive}"#
        ),
        format!(
            r#"{{"status":"success","data":{{"resultType":"matrix","resultType":"{sensitive}","result":[]}}}}"#
        ),
    ];

    for response in responses {
        let error = parse_matrix_response(response.as_bytes())
            .expect_err("malformed response must fail closed");
        let message = error.to_string();

        assert!(message.contains("Prometheus query_range response"));
        assert!(!message.contains(sensitive));
    }
}

#[test]
fn response_status_and_error_details_are_redacted() {
    let sensitive = "private-error-detail";
    let unsupported = format!(r#"{{"status":"{sensitive}"}}"#);
    let unsupported_error =
        parse_matrix_response(unsupported.as_bytes()).expect_err("unsupported status must fail");
    assert!(unsupported_error.to_string().contains("unsupported status"));
    assert!(!unsupported_error.to_string().contains(sensitive));

    let error_response =
        format!(r#"{{"status":"error","errorType":"{sensitive}","error":"{sensitive}"}}"#);
    let error = parse_matrix_response(error_response.as_bytes())
        .expect_err("error envelope must remain an error");
    assert!(
        error
            .to_string()
            .contains("Prometheus query failed: unknown")
    );
    assert!(!error.to_string().contains(sensitive));
}
