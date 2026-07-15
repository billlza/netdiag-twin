use super::{CapturedStream, OutputLimit};
use crate::error::{NetdiagError, Result};
use rustix::event::PollFlags;
use std::io::{self, Read};

const READ_BUDGET_BYTES: usize = 64 * 1024;

impl<R> CapturedStream<R>
where
    R: Read,
{
    pub(super) fn new(stream_name: &'static str, reader: R, limit: usize) -> Self {
        Self {
            stream_name,
            limit,
            reader: Some(reader),
            bytes: Vec::with_capacity(limit.min(64 * 1024)),
        }
    }

    pub(super) fn drain_ready(&mut self, events: PollFlags) -> Result<Option<OutputLimit>> {
        if self.reader.is_none() || events.is_empty() {
            return Ok(None);
        }
        if events.contains(PollFlags::NVAL) {
            self.reader.take();
            return Err(self.read_error("poll reported an invalid file descriptor"));
        }
        if !events.intersects(PollFlags::IN | PollFlags::HUP | PollFlags::ERR) {
            return Ok(None);
        }

        let mut consumed = 0_usize;
        let mut chunk = [0_u8; 16 * 1024];
        while consumed < READ_BUDGET_BYTES {
            let result = self
                .reader
                .as_mut()
                .expect("active capture stream must retain its reader")
                .read(&mut chunk);
            match result {
                Ok(0) => {
                    self.reader.take();
                    return Ok(None);
                }
                Ok(count) => {
                    consumed += count;
                    let retained = self.limit.saturating_sub(self.bytes.len()).min(count);
                    self.bytes.extend_from_slice(&chunk[..retained]);
                    if retained < count {
                        self.reader.take();
                        return Ok(Some(OutputLimit {
                            stream_name: self.stream_name,
                            limit: self.limit,
                        }));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if events.intersects(PollFlags::HUP | PollFlags::ERR) {
                        self.reader.take();
                    }
                    return if events.contains(PollFlags::ERR) {
                        Err(self.read_error("poll reported an output error without data"))
                    } else {
                        Ok(None)
                    };
                }
                Err(error) => {
                    self.reader.take();
                    return Err(self.read_error(&format!("failed while reading output: {error}")));
                }
            }
        }
        Ok(None)
    }

    fn read_error(&self, cause: &str) -> NetdiagError {
        NetdiagError::Connector(format!("process {} reader {cause}", self.stream_name))
    }
}
