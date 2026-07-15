use super::CaptureControl;
use crate::error::{NetdiagError, Result};
use crate::resource_limits::MAX_COLLECTION_TIMEOUT_SECS;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub(super) struct CaptureDeadline {
    started: Instant,
    deadline: Instant,
    timeout: Duration,
    context: &'static str,
}

impl CaptureDeadline {
    pub(super) fn new(timeout: Duration, context: &'static str) -> Result<Self> {
        let maximum_timeout = Duration::from_secs(MAX_COLLECTION_TIMEOUT_SECS);
        if timeout < Duration::from_millis(1) || timeout > maximum_timeout {
            return Err(NetdiagError::Connector(format!(
                "{context} timeout must be within 1ms..={}ms",
                maximum_timeout.as_millis()
            )));
        }
        let started = Instant::now();
        let deadline = started.checked_add(timeout).ok_or_else(|| {
            NetdiagError::Connector(format!("{context} deadline cannot be represented"))
        })?;
        Ok(Self {
            started,
            deadline,
            timeout,
            context,
        })
    }

    pub(super) fn started(self) -> Instant {
        self.started
    }

    pub(super) fn timeout(self) -> Duration {
        self.timeout
    }

    pub(super) fn is_expired(self) -> bool {
        Instant::now() >= self.deadline
    }

    pub(super) fn ensure_remaining(self, control: &CaptureControl) -> Result<()> {
        if control.is_cancelled() {
            return Err(NetdiagError::CaptureCancelled {
                context: self.context,
            });
        }
        if self.is_expired() {
            return Err(NetdiagError::Connector(format!(
                "{} exceeded its deadline",
                self.context
            )));
        }
        Ok(())
    }
}
