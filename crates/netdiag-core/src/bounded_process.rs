//! Fail-closed boundary for short-lived, non-interactive subprocesses.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

#[cfg(unix)]
mod capture;
#[cfg(unix)]
mod termination;
#[cfg(unix)]
mod unix;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ProcessLimits {
    pub(crate) timeout: Duration,
    pub(crate) stdout_bytes: usize,
    pub(crate) stderr_bytes: usize,
}

#[derive(Debug)]
pub(crate) enum ProcessFailureReason {
    Spawn(std::io::Error),
    Timeout,
    Cancelled,
    Wait(std::io::Error),
    OutputLimit {
        stream_name: &'static str,
        limit: usize,
    },
    Output(String),
}

#[derive(Debug)]
pub(crate) struct ProcessFailure {
    pub(crate) timeout: Duration,
    pub(crate) reason: ProcessFailureReason,
    pub(crate) stderr: Vec<u8>,
    pub(crate) cleanup_details: Vec<String>,
}

pub(crate) struct BoundedCommand {
    executable: PathBuf,
    command: Command,
}

impl BoundedCommand {
    pub(crate) fn new(executable: &Path) -> Self {
        let mut command = Command::new(executable);
        command.env_clear();
        Self {
            executable: executable.to_path_buf(),
            command,
        }
    }

    pub(crate) fn arg(&mut self, argument: impl AsRef<OsStr>) -> &mut Self {
        self.command.arg(argument);
        self
    }

    pub(crate) fn args<I, S>(&mut self, arguments: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.command.args(arguments);
        self
    }

    pub(crate) fn current_dir(&mut self, directory: &Path) -> &mut Self {
        self.command.current_dir(directory);
        self
    }

    pub(crate) fn envs<I, K, V>(&mut self, variables: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.command.envs(variables);
        self
    }

    pub(crate) fn run(
        self,
        limits: ProcessLimits,
        cancelled: &dyn Fn() -> bool,
    ) -> std::result::Result<Output, ProcessFailure> {
        unix::run(self, limits, cancelled)
    }
}

#[cfg(test)]
mod tests;
