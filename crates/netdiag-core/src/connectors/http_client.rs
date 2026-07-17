use super::authentication::ValidatedBearerToken;
use super::http_endpoint::{connector_endpoint, require_bearer_transport};
use crate::error::{NetdiagError, Result};
use reqwest::Error;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::AUTHORIZATION;
use reqwest::redirect::Policy;

mod authorization;
use authorization::bearer_header;

pub(super) struct ConnectorHttpClient {
    client: Client,
    endpoint: reqwest::Url,
}

impl ConnectorHttpClient {
    pub(super) fn new(endpoint: &str, context: &str) -> Result<Self> {
        let endpoint = connector_endpoint(endpoint, context)?;
        Self::from_endpoint(endpoint)
    }

    pub(super) fn from_endpoint(endpoint: reqwest::Url) -> Result<Self> {
        let client = Client::builder()
            .redirect(Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| {
                NetdiagError::Connector("HTTP client initialization failed".to_string())
            })?;
        Ok(Self { client, endpoint })
    }

    pub(super) fn endpoint(&self) -> &reqwest::Url {
        &self.endpoint
    }

    pub(super) fn get(
        &self,
        bearer_token: Option<&ValidatedBearerToken>,
        context: &str,
    ) -> Result<RequestBuilder> {
        let authorization = bearer_header(bearer_token, context)?;
        if authorization.is_some() {
            require_bearer_transport(&self.endpoint)
                .map_err(|error| NetdiagError::Connector(format!("{context} {error}")))?;
        }
        let request = self.client.get(self.endpoint.clone());
        Ok(match authorization {
            Some(value) => request.header(AUTHORIZATION, value),
            None => request,
        })
    }
}

pub(super) fn request_error(context: &str, error: &Error) -> NetdiagError {
    let reason = if error.is_timeout() {
        "timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_redirect() {
        "redirect policy failed"
    } else if error.is_request() {
        "could not be constructed"
    } else {
        "transport failed"
    };
    NetdiagError::Connector(format!("{context} failed: {reason}"))
}

pub(super) fn require_success(response: Response, context: &str) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        Ok(response)
    } else {
        Err(NetdiagError::Connector(format!(
            "{context} returned HTTP status {}",
            status.as_u16()
        )))
    }
}
