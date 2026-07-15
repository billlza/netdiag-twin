use super::MAX_HTTP_ENDPOINT_BYTES;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpEndpointError {
    Empty,
    TooLong,
    Invalid,
    UnsupportedScheme,
    MissingHost,
    UserInfo,
    Fragment,
    SensitiveQuery,
    InsecureBearerTransport,
}

impl fmt::Display for HttpEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("endpoint is empty"),
            Self::TooLong => write!(
                formatter,
                "endpoint exceeds the {MAX_HTTP_ENDPOINT_BYTES}-byte limit"
            ),
            Self::Invalid => formatter.write_str("endpoint is not a valid URL"),
            Self::UnsupportedScheme => formatter.write_str("endpoint must use http or https"),
            Self::MissingHost => formatter.write_str("endpoint must include a host"),
            Self::UserInfo => formatter.write_str(
                "endpoint URL user information is forbidden; use a dedicated authentication field",
            ),
            Self::Fragment => formatter.write_str("endpoint URL fragments are forbidden"),
            Self::SensitiveQuery => formatter.write_str(
                "endpoint query parameters must not contain credentials; use a dedicated authentication field",
            ),
            Self::InsecureBearerTransport => formatter.write_str(
                "bearer authentication requires HTTPS or HTTP with a loopback IP literal",
            ),
        }
    }
}

impl std::error::Error for HttpEndpointError {}
