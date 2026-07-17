use crate::error::{NetdiagError, Result};

const GLOBAL_HEADER_BYTES: usize = 24;
const PACKET_HEADER_BYTES: usize = 16;

#[derive(Debug, Clone, Copy)]
enum ByteOrder {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy)]
enum TimestampResolution {
    Microseconds,
    Nanoseconds,
}

#[derive(Debug)]
pub(super) struct PcapFilePacket<'a> {
    pub(super) seconds: i64,
    pub(super) microseconds: i64,
    pub(super) original_length: u32,
    pub(super) data: &'a [u8],
}

#[derive(Debug)]
pub(super) struct PcapFileReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
    byte_order: ByteOrder,
    timestamp_resolution: TimestampResolution,
    snapshot_length: u32,
}

impl<'a> PcapFileReader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < GLOBAL_HEADER_BYTES {
            return Err(file_error("global header is truncated"));
        }
        let (byte_order, timestamp_resolution) = parse_magic(&bytes[..4])?;
        let version_major = read_u16(&bytes[4..6], byte_order);
        let version_minor = read_u16(&bytes[6..8], byte_order);
        if (version_major, version_minor) != (2, 4) {
            return Err(file_error("version must be 2.4"));
        }
        let snapshot_length = read_u32(&bytes[16..20], byte_order);
        if snapshot_length == 0 {
            return Err(file_error("snapshot length is zero"));
        }
        validate_link_type(read_u32(&bytes[20..24], byte_order))?;
        Ok(Self {
            bytes,
            cursor: GLOBAL_HEADER_BYTES,
            byte_order,
            timestamp_resolution,
            snapshot_length,
        })
    }

    pub(super) fn next_packet(&mut self) -> Result<Option<PcapFilePacket<'a>>> {
        if self.cursor == self.bytes.len() {
            return Ok(None);
        }
        let header_end = self
            .cursor
            .checked_add(PACKET_HEADER_BYTES)
            .ok_or_else(|| file_error("packet header offset overflowed"))?;
        let header = self
            .bytes
            .get(self.cursor..header_end)
            .ok_or_else(|| file_error("packet header is truncated"))?;
        let seconds = i64::from(read_u32(&header[0..4], self.byte_order));
        let fraction = read_u32(&header[4..8], self.byte_order);
        let captured_length = read_u32(&header[8..12], self.byte_order);
        let original_length = read_u32(&header[12..16], self.byte_order);
        if captured_length > self.snapshot_length || captured_length > original_length {
            return Err(file_error("packet length metadata is inconsistent"));
        }
        let captured_length = usize::try_from(captured_length)
            .map_err(|_| file_error("captured packet length is not representable"))?;
        let packet_end = header_end
            .checked_add(captured_length)
            .ok_or_else(|| file_error("packet body offset overflowed"))?;
        let data = self
            .bytes
            .get(header_end..packet_end)
            .ok_or_else(|| file_error("packet body is truncated"))?;
        let microseconds = timestamp_microseconds(fraction, self.timestamp_resolution)?;
        self.cursor = packet_end;
        Ok(Some(PcapFilePacket {
            seconds,
            microseconds,
            original_length,
            data,
        }))
    }
}

fn parse_magic(bytes: &[u8]) -> Result<(ByteOrder, TimestampResolution)> {
    match bytes {
        [0xd4, 0xc3, 0xb2, 0xa1] => Ok((ByteOrder::Little, TimestampResolution::Microseconds)),
        [0xa1, 0xb2, 0xc3, 0xd4] => Ok((ByteOrder::Big, TimestampResolution::Microseconds)),
        [0x4d, 0x3c, 0xb2, 0xa1] => Ok((ByteOrder::Little, TimestampResolution::Nanoseconds)),
        [0xa1, 0xb2, 0x3c, 0x4d] => Ok((ByteOrder::Big, TimestampResolution::Nanoseconds)),
        [0x0a, 0x0d, 0x0d, 0x0a] => Err(file_error(
            "pcapng is unsupported; convert the capture to classic pcap",
        )),
        _ => Err(file_error("magic value is unsupported")),
    }
}

fn validate_link_type(link_type: u32) -> Result<()> {
    if matches!(link_type, 1 | 101 | 228 | 229) {
        Ok(())
    } else {
        Err(file_error(
            "link type is unsupported; Ethernet or raw IPv4/IPv6 is required",
        ))
    }
}

fn timestamp_microseconds(value: u32, resolution: TimestampResolution) -> Result<i64> {
    match resolution {
        TimestampResolution::Microseconds if value < 1_000_000 => Ok(i64::from(value)),
        TimestampResolution::Nanoseconds if value < 1_000_000_000 => Ok(i64::from(value / 1_000)),
        TimestampResolution::Microseconds => Err(file_error("microsecond timestamp is invalid")),
        TimestampResolution::Nanoseconds => Err(file_error("nanosecond timestamp is invalid")),
    }
}

fn read_u16(bytes: &[u8], order: ByteOrder) -> u16 {
    let bytes = [bytes[0], bytes[1]];
    match order {
        ByteOrder::Little => u16::from_le_bytes(bytes),
        ByteOrder::Big => u16::from_be_bytes(bytes),
    }
}

fn read_u32(bytes: &[u8], order: ByteOrder) -> u32 {
    let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match order {
        ByteOrder::Little => u32::from_le_bytes(bytes),
        ByteOrder::Big => u32::from_be_bytes(bytes),
    }
}

fn file_error(reason: &str) -> NetdiagError {
    NetdiagError::Connector(format!("failed while reading pcap file: {reason}"))
}

#[cfg(test)]
mod tests;
