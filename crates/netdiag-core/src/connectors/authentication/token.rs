use super::authentication_error;
use crate::error::Result;
use reqwest::header::HeaderValue;
use std::fmt;
use zeroize::Zeroizing;

pub const MAX_BEARER_TOKEN_BYTES: usize = 8 * 1024;

pub struct ValidatedBearerToken {
    value: Zeroizing<String>,
}

impl ValidatedBearerToken {
    pub fn as_str(&self) -> &str {
        &self.value
    }

    pub(crate) fn authorization_header(&self) -> Result<HeaderValue> {
        authorization_header(self.as_str())
    }
}

impl fmt::Debug for ValidatedBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedBearerToken(<redacted>)")
    }
}

pub fn validate_bearer_token(value: String) -> Result<ValidatedBearerToken> {
    let value = Zeroizing::new(value);
    if value.is_empty() {
        return Err(authentication_error("bearer token is empty"));
    }
    if value.len() > MAX_BEARER_TOKEN_BYTES {
        return Err(authentication_error(format!(
            "bearer token exceeds the {MAX_BEARER_TOKEN_BYTES}-byte limit"
        )));
    }
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(authentication_error(
            "bearer token contains ASCII whitespace",
        ));
    }
    authorization_header(&value)?;
    Ok(ValidatedBearerToken { value })
}

fn authorization_header(token: &str) -> Result<HeaderValue> {
    let encoded = Zeroizing::new(format!("Bearer {token}"));
    let mut authorization = HeaderValue::try_from(encoded.as_str())
        .map_err(|_| authentication_error("bearer token is not a valid HTTP header value"))?;
    authorization.set_sensitive(true);
    Ok(authorization)
}
