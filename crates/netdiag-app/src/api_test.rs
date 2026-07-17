mod status;

use netdiag_app::data_source::SourceMode;
use netdiag_app::secrets::SecretStore;
pub(super) use status::ApiTestStatus;
use std::sync::{Arc, mpsc};
use std::thread;

struct ApiTestIdentity {
    source: SourceMode,
    credential_revision: u64,
}

impl ApiTestIdentity {
    fn new(source: SourceMode, credential_revision: u64) -> Self {
        Self {
            source,
            credential_revision,
        }
    }

    fn matches(&self, source: &SourceMode, credential_revision: u64) -> bool {
        self.source == *source && self.credential_revision == credential_revision
    }
}

pub(super) struct ApiTestJob {
    identity: ApiTestIdentity,
    receiver: mpsc::Receiver<anyhow::Result<ApiTestOutcome>>,
}

#[derive(Debug)]
pub(super) struct ApiTestOutcome {
    pub(super) rows: usize,
    pub(super) sample: String,
}

pub(super) enum ApiTestPoll {
    Pending,
    Complete(anyhow::Result<ApiTestOutcome>),
}

impl ApiTestJob {
    pub(super) fn start(
        source: SourceMode,
        credential_revision: u64,
        secrets: Arc<dyn SecretStore>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let worker_source = source.clone();
        thread::spawn(move || {
            let result = worker_source
                .load(secrets.as_ref())
                .map(|snapshot| ApiTestOutcome {
                    rows: snapshot.ingest.records.len(),
                    sample: snapshot.descriptor.name,
                });
            let _ = sender.send(result);
        });
        Self {
            identity: ApiTestIdentity::new(source, credential_revision),
            receiver,
        }
    }

    pub(super) fn poll(&self) -> ApiTestPoll {
        match self.receiver.try_recv() {
            Ok(result) => ApiTestPoll::Complete(result),
            Err(mpsc::TryRecvError::Empty) => ApiTestPoll::Pending,
            Err(mpsc::TryRecvError::Disconnected) => ApiTestPoll::Complete(Err(anyhow::anyhow!(
                "API test worker stopped before returning a result"
            ))),
        }
    }

    pub(super) fn matches_current(&self, source: &SourceMode, credential_revision: u64) -> bool {
        self.identity.matches(source, credential_revision)
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
    fn connection_test_identity_binds_configuration_and_credential_revision() {
        let tested = source("https://one.example.test/traces");
        let (sender, receiver) = mpsc::channel();
        drop(sender);
        let job = ApiTestJob {
            identity: ApiTestIdentity::new(tested.clone(), 7),
            receiver,
        };

        assert!(job.matches_current(&tested, 7));
        assert!(!job.matches_current(&source("https://two.example.test/traces"), 7));
        assert!(!job.matches_current(&tested, 8));
    }
}
