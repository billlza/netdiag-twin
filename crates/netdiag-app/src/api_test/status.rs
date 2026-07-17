use super::{ApiTestIdentity, ApiTestJob};
use netdiag_app::data_source::SourceMode;

pub(crate) struct ApiTestStatus {
    identity: ApiTestIdentity,
    message: String,
}

impl ApiTestStatus {
    fn new(source: SourceMode, credential_revision: u64, message: String) -> Self {
        Self {
            identity: ApiTestIdentity::new(source, credential_revision),
            message,
        }
    }

    fn message_if_current(&self, source: &SourceMode, credential_revision: u64) -> Option<&str> {
        self.identity
            .matches(source, credential_revision)
            .then_some(self.message.as_str())
    }
}

fn bind_status(
    source: Option<SourceMode>,
    credential_revision: u64,
    message: String,
) -> Option<ApiTestStatus> {
    source.map(|source| ApiTestStatus::new(source, credential_revision, message))
}

fn advance_credential_revision(
    revision: &mut u64,
    active_job: &mut Option<ApiTestJob>,
    status: &mut Option<ApiTestStatus>,
) {
    *status = None;
    match revision.checked_add(1) {
        Some(next) => *revision = next,
        None => {
            *active_job = None;
            *revision = 0;
        }
    }
}

impl super::super::NetDiagApp {
    pub(crate) fn advance_api_test_credential_revision(&mut self) {
        advance_credential_revision(
            &mut self.api_test_credential_revision,
            &mut self.api_test_job,
            &mut self.api_test_status,
        );
    }

    pub(crate) fn replace_api_test_status(&mut self, message: String) {
        let source = self.connector_source_mode().ok();
        self.api_test_status = bind_status(source, self.api_test_credential_revision, message);
    }

    pub(crate) fn current_api_test_status(&self) -> Option<&str> {
        let source = self.connector_source_mode().ok()?;
        self.api_test_status
            .as_ref()?
            .message_if_current(&source, self.api_test_credential_revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netdiag_app::settings::ApiConfig;
    use std::time::Duration;

    fn source(endpoint: &str) -> SourceMode {
        SourceMode::Api(
            ApiConfig::new(endpoint.to_string(), Duration::from_secs(5)),
            None,
        )
    }

    #[test]
    fn completed_status_is_visible_only_for_the_exact_identity() {
        let tested = source("https://one.example.test/traces");
        let status = ApiTestStatus::new(tested.clone(), 7, "Connection OK".to_string());

        assert_eq!(status.message_if_current(&tested, 7), Some("Connection OK"));
        assert_eq!(
            status.message_if_current(&source("https://two.example.test/traces"), 7),
            None
        );
        assert_eq!(status.message_if_current(&tested, 8), None);
    }

    #[test]
    fn credential_revision_change_clears_status_and_handles_overflow() {
        let mut revision = u64::MAX;
        let mut job = None;
        let mut status = Some(ApiTestStatus::new(
            source("https://one.example.test"),
            0,
            "old".into(),
        ));

        advance_credential_revision(&mut revision, &mut job, &mut status);

        assert_eq!(revision, 0);
        assert!(job.is_none());
        assert!(status.is_none());
    }

    #[test]
    fn invalid_current_source_drops_api_status_without_a_fallback_message() {
        assert!(bind_status(None, 7, "stale".into()).is_none());
    }
}
