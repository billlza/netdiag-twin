use super::CapturePair;
use crate::error::{NetdiagError, Result};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fd::AsFd;
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use std::io::Read;
use std::thread;
use std::time::Duration;

impl<O, E> CapturePair<O, E>
where
    O: AsFd + Read,
    E: AsFd + Read,
{
    pub(super) fn poll_events(&self, timeout: Duration) -> Result<(PollFlags, PollFlags)> {
        match (self.stdout.reader.as_ref(), self.stderr.reader.as_ref()) {
            (Some(stdout), Some(stderr)) => {
                let mut descriptors = [
                    PollFd::new(stdout, PollFlags::IN),
                    PollFd::new(stderr, PollFlags::IN),
                ];
                poll_with_timeout(&mut descriptors, timeout)?;
                Ok((descriptors[0].revents(), descriptors[1].revents()))
            }
            (Some(stdout), None) => {
                let mut descriptors = [PollFd::new(stdout, PollFlags::IN)];
                poll_with_timeout(&mut descriptors, timeout)?;
                Ok((descriptors[0].revents(), PollFlags::empty()))
            }
            (None, Some(stderr)) => {
                let mut descriptors = [PollFd::new(stderr, PollFlags::IN)];
                poll_with_timeout(&mut descriptors, timeout)?;
                Ok((PollFlags::empty(), descriptors[0].revents()))
            }
            (None, None) => {
                if !timeout.is_zero() {
                    thread::sleep(timeout);
                }
                Ok((PollFlags::empty(), PollFlags::empty()))
            }
        }
    }
}

pub(super) fn set_nonblocking(reader: &impl AsFd, stream_name: &'static str) -> Result<()> {
    let flags = inspected_flags(fcntl_getfl(reader), stream_name)?;
    applied_flags(fcntl_setfl(reader, flags | OFlags::NONBLOCK), stream_name)
}

pub(super) fn inspected_flags(
    result: rustix::io::Result<OFlags>,
    stream_name: &'static str,
) -> Result<OFlags> {
    result.map_err(|error| {
        NetdiagError::Connector(format!(
            "failed to inspect process {stream_name} pipe flags: {error}"
        ))
    })
}

pub(super) fn applied_flags(
    result: rustix::io::Result<()>,
    stream_name: &'static str,
) -> Result<()> {
    result.map_err(|error| {
        NetdiagError::Connector(format!(
            "failed to make process {stream_name} pipe nonblocking: {error}"
        ))
    })
}

pub(super) fn poll_with_timeout(descriptors: &mut [PollFd<'_>], timeout: Duration) -> Result<()> {
    let timeout = Timespec::try_from(timeout).map_err(|error| {
        NetdiagError::Connector(format!(
            "process output poll timeout could not be represented: {error}"
        ))
    })?;
    checked_poll(poll(descriptors, Some(&timeout)))
}

pub(super) fn checked_poll(result: rustix::io::Result<usize>) -> Result<()> {
    result
        .map(|_| ())
        .map_err(|error| NetdiagError::Connector(format!("process output poll failed: {error}")))
}
