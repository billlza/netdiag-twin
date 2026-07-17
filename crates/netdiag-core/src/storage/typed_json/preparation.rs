use crate::error::{NetdiagError, Result};
use serde::Serialize;
use std::io::Write;

pub(crate) struct PreparedJson(Vec<u8>);

impl PreparedJson {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) fn prepare_json_bounded<T: Serialize + ?Sized>(
    value: &T,
    max_bytes: u64,
    kind: &str,
) -> Result<PreparedJson> {
    let mut output = BoundedBuffer {
        bytes: Vec::new(),
        max_bytes,
        kind,
    };
    serde_json::to_writer_pretty(&mut output, value).map_err(|source| {
        NetdiagError::InvalidTrace(format!("cannot serialize {kind}: {source}"))
    })?;
    Ok(PreparedJson(output.bytes))
}

struct BoundedBuffer<'a> {
    bytes: Vec<u8>,
    max_bytes: u64,
    kind: &'a str,
}

impl Write for BoundedBuffer<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let projected = (self.bytes.len() as u64)
            .checked_add(buffer.len() as u64)
            .ok_or_else(|| std::io::Error::other("serialized JSON size overflow"))?;
        if projected > self.max_bytes {
            return Err(std::io::Error::other(format!(
                "serialized {} exceeds the {}-byte limit",
                self.kind, self.max_bytes
            )));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
