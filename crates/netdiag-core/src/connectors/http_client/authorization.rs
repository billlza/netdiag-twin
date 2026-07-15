use super::super::authentication::ValidatedBearerToken;
use crate::error::{NetdiagError, Result};
use reqwest::header::HeaderValue;

pub(super) fn bearer_header(
    token: Option<&ValidatedBearerToken>,
    context: &str,
) -> Result<Option<HeaderValue>> {
    let Some(token) = token else {
        return Ok(None);
    };
    token
        .authorization_header()
        .map(Some)
        .map_err(|error| match error {
            NetdiagError::Connector(detail) => {
                NetdiagError::Connector(format!("{context} {detail}"))
            }
            unexpected => unexpected,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_header_is_sensitive_and_never_debugs_the_token() {
        let token =
            super::super::super::authentication::validate_bearer_token("private-token".to_string())
                .expect("valid token");
        let header = bearer_header(Some(&token), "HTTP source")
            .expect("authorization header")
            .expect("present authorization header");

        assert!(header.is_sensitive());
        assert_eq!(
            header.to_str().expect("ASCII header"),
            "Bearer private-token"
        );
        assert!(!format!("{header:?}").contains(token.as_str()));
    }
}
