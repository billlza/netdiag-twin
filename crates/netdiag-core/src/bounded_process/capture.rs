use crate::error::{NetdiagError, Result};
use rustix::fd::AsFd;
use std::io::Read;
use std::process::{ChildStderr, ChildStdout, ExitStatus, Output};
use std::time::{Duration, Instant};

mod polling;
use polling::set_nonblocking;
mod stream;

#[derive(Debug, Clone, Copy)]
pub(super) struct OutputLimit {
    pub(super) stream_name: &'static str,
    pub(super) limit: usize,
}

pub(super) enum DrainOutcome {
    Complete,
    DeadlineExceeded,
    OutputLimit(OutputLimit),
    ReadFailure(NetdiagError),
}

struct CapturedStream<R> {
    stream_name: &'static str,
    limit: usize,
    reader: Option<R>,
    bytes: Vec<u8>,
}

pub(super) struct CapturePair<O, E> {
    stdout: CapturedStream<O>,
    stderr: CapturedStream<E>,
}

pub(super) type ProcessCapture = CapturePair<ChildStdout, ChildStderr>;

impl<O, E> CapturePair<O, E>
where
    O: AsFd + Read,
    E: AsFd + Read,
{
    pub(super) fn new(
        stdout: O,
        stderr: E,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> Result<Self> {
        set_nonblocking(&stdout, "stdout")?;
        set_nonblocking(&stderr, "stderr")?;
        Ok(Self {
            stdout: CapturedStream::new("stdout", stdout, stdout_limit),
            stderr: CapturedStream::new("stderr", stderr, stderr_limit),
        })
    }

    pub(super) fn poll_once(&mut self, timeout: Duration) -> Result<Option<OutputLimit>> {
        let (stdout_events, stderr_events) = self.poll_events(timeout)?;
        let stdout_limit = self.stdout.drain_ready(stdout_events)?;
        let stderr_limit = self.stderr.drain_ready(stderr_events)?;
        Ok(stdout_limit.or(stderr_limit))
    }

    pub(super) fn drain_until(&mut self, deadline: Instant) -> DrainOutcome {
        loop {
            if self.is_complete() {
                return DrainOutcome::Complete;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.poll_once(remaining) {
                Ok(Some(limit)) => return DrainOutcome::OutputLimit(limit),
                Ok(None) if self.is_complete() => return DrainOutcome::Complete,
                Ok(None) if Instant::now() >= deadline => {
                    self.close();
                    return DrainOutcome::DeadlineExceeded;
                }
                Ok(None) => {}
                Err(error) => return DrainOutcome::ReadFailure(error),
            }
        }
    }

    pub(super) fn into_output(self, status: ExitStatus) -> Output {
        Output {
            status,
            stdout: self.stdout.bytes,
            stderr: self.stderr.bytes,
        }
    }

    pub(super) fn stderr(&self) -> &[u8] {
        &self.stderr.bytes
    }

    fn is_complete(&self) -> bool {
        self.stdout.reader.is_none() && self.stderr.reader.is_none()
    }

    fn close(&mut self) {
        self.stdout.reader.take();
        self.stderr.reader.take();
    }
}

#[cfg(test)]
mod tests;
