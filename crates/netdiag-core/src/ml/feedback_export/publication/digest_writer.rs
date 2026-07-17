use crate::error::{IoContext, Result};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

pub(super) struct DigestWriter<W> {
    inner: W,
    digest: Sha256,
}

impl<W: Write> DigestWriter<W> {
    pub(super) fn new(inner: W) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
        }
    }

    pub(super) fn finish(mut self, path: &Path) -> Result<String> {
        self.inner.flush().with_path(path)?;
        Ok(format!("{:x}", self.digest.finalize()))
    }
}

impl<W: Write> Write for DigestWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.digest.update(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
