use crate::settings::AppSettings;
use anyhow::{Context, Result, bail};
use std::io::{self, Write};

pub(super) fn validate_serialized_size(settings: &AppSettings, max_bytes: usize) -> Result<()> {
    let mut counter = BoundedSizeCounter::new(max_bytes);
    match serde_json::to_writer_pretty(&mut counter, settings) {
        Ok(()) => Ok(()),
        Err(_) if counter.exceeded => {
            bail!("serialized settings exceed the {max_bytes}-byte settings file limit")
        }
        Err(error) => Err(error).context("settings cannot be serialized as JSON"),
    }
}

struct BoundedSizeCounter {
    exceeded: bool,
    max_bytes: usize,
    written: usize,
}

impl BoundedSizeCounter {
    fn new(max_bytes: usize) -> Self {
        Self {
            exceeded: false,
            max_bytes,
            written: 0,
        }
    }
}

impl Write for BoundedSizeCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(written) = self.written.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(limit_error(self.max_bytes));
        };
        if written > self.max_bytes {
            self.exceeded = true;
            return Err(limit_error(self.max_bytes));
        }
        self.written = written;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn limit_error(max_bytes: usize) -> io::Error {
    io::Error::new(
        io::ErrorKind::FileTooLarge,
        format!("serialized settings exceed {max_bytes} bytes"),
    )
}
