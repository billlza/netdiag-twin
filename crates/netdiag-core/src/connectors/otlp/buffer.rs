use super::OtlpMetricFrame;
use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use std::mem::size_of;
use tonic::Status;

pub(super) const MAX_BUFFERED_FRAMES: usize = 256;
pub(super) const MAX_BUFFERED_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub(super) struct OtlpFrameBuffer {
    frames: VecDeque<OtlpMetricFrame>,
    retained_bytes: usize,
}

impl Default for OtlpFrameBuffer {
    fn default() -> Self {
        let frames = VecDeque::with_capacity(MAX_BUFFERED_FRAMES);
        let retained_bytes = size_of::<Self>() + frames.capacity() * size_of::<OtlpMetricFrame>();
        Self {
            frames,
            retained_bytes,
        }
    }
}

impl OtlpFrameBuffer {
    pub(super) fn push(&mut self, frame: OtlpMetricFrame) -> Result<(), Status> {
        if self.frames.len() >= MAX_BUFFERED_FRAMES {
            return Err(Status::resource_exhausted(
                "OTLP receiver frame capacity is exhausted",
            ));
        }
        let frame_bytes = frame.payload_bytes().ok_or_else(|| {
            Status::resource_exhausted("OTLP receiver frame size accounting overflowed")
        })?;
        let projected = self
            .retained_bytes
            .checked_add(frame_bytes)
            .ok_or_else(|| {
                Status::resource_exhausted("OTLP receiver byte accounting overflowed")
            })?;
        if projected > MAX_BUFFERED_BYTES {
            return Err(Status::resource_exhausted(
                "OTLP receiver retained-byte capacity is exhausted",
            ));
        }
        self.frames.push_back(frame);
        self.retained_bytes = projected;
        Ok(())
    }

    pub(super) fn iter_since(
        &self,
        cutoff: DateTime<Utc>,
    ) -> impl Iterator<Item = &OtlpMetricFrame> {
        self.frames
            .iter()
            .filter(move |frame| frame.received_at >= cutoff)
    }

    pub(super) fn len(&self) -> usize {
        self.frames.len()
    }

    pub(super) fn last_received_at(&self) -> Option<DateTime<Utc>> {
        self.frames.back().map(|frame| frame.received_at)
    }

    #[cfg(test)]
    pub(super) fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn retained_byte_budget_is_fail_closed_without_partial_enqueue() {
        let mut buffer = OtlpFrameBuffer::default();
        let large_frame = || OtlpMetricFrame {
            received_at: Utc::now(),
            timestamp_ms: 1,
            input_bytes: 1,
            values: vec![1.0; 256].into_boxed_slice(),
        };

        let error = loop {
            if let Err(error) = buffer.push(large_frame()) {
                break error;
            }
        };
        let retained_frames = buffer.len();
        let retained_bytes = buffer.retained_bytes();
        let repeat_error = buffer
            .push(large_frame())
            .expect_err("exhausted byte budget must remain closed");

        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        assert!(error.message().contains("retained-byte"));
        assert_eq!(repeat_error.code(), tonic::Code::ResourceExhausted);
        assert!(retained_frames < MAX_BUFFERED_FRAMES);
        assert!(retained_bytes <= MAX_BUFFERED_BYTES);
        assert_eq!(buffer.len(), retained_frames);
        assert_eq!(buffer.retained_bytes(), retained_bytes);
    }
}
