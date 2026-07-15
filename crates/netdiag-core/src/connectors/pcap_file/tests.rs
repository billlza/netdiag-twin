use super::*;

#[test]
fn parses_all_classic_endian_and_timestamp_variants() {
    for (order, resolution, fraction, expected_micros) in [
        (
            ByteOrder::Little,
            TimestampResolution::Microseconds,
            321_456,
            321_456,
        ),
        (
            ByteOrder::Big,
            TimestampResolution::Microseconds,
            321_456,
            321_456,
        ),
        (
            ByteOrder::Little,
            TimestampResolution::Nanoseconds,
            654_321_999,
            654_321,
        ),
        (
            ByteOrder::Big,
            TimestampResolution::Nanoseconds,
            654_321_999,
            654_321,
        ),
    ] {
        let bytes = fixture(order, resolution, fraction, 1);
        let mut reader = PcapFileReader::new(&bytes).expect("classic pcap reader");
        let packet = reader
            .next_packet()
            .expect("classic pcap packet")
            .expect("classic pcap row");
        assert_eq!(packet.seconds, 7);
        assert_eq!(packet.microseconds, expected_micros);
        assert_eq!(packet.original_length, 4);
        assert_eq!(packet.data, [1, 2, 3, 4]);
        assert!(reader.next_packet().expect("classic pcap eof").is_none());
    }
}

#[test]
fn rejects_pcapng_unsupported_link_types_and_truncated_packets() {
    let mut pcapng = vec![0x0a, 0x0d, 0x0d, 0x0a];
    pcapng.resize(GLOBAL_HEADER_BYTES, 0);
    let pcapng_error = PcapFileReader::new(&pcapng).expect_err("pcapng must be explicit");
    assert!(pcapng_error.to_string().contains("pcapng is unsupported"));

    let unsupported = fixture(ByteOrder::Little, TimestampResolution::Microseconds, 0, 147);
    let link_error = PcapFileReader::new(&unsupported).expect_err("unsupported link type");
    assert!(link_error.to_string().contains("link type is unsupported"));

    let mut truncated = fixture(ByteOrder::Little, TimestampResolution::Microseconds, 0, 1);
    truncated.pop();
    let error = PcapFileReader::new(&truncated)
        .expect("truncated reader")
        .next_packet()
        .expect_err("truncated packet must fail");
    assert!(error.to_string().contains("packet body is truncated"));
}

#[test]
fn rejects_invalid_timestamp_and_packet_length_metadata() {
    let invalid_time = fixture(
        ByteOrder::Little,
        TimestampResolution::Microseconds,
        1_000_000,
        1,
    );
    let time_error = PcapFileReader::new(&invalid_time)
        .expect("invalid-time reader")
        .next_packet()
        .expect_err("invalid microseconds");
    assert!(time_error.to_string().contains("microsecond timestamp"));

    let mut invalid_length = fixture(ByteOrder::Little, TimestampResolution::Microseconds, 0, 1);
    write_u32_at(&mut invalid_length, 36, 3, ByteOrder::Little);
    let length_error = PcapFileReader::new(&invalid_length)
        .expect("invalid-length reader")
        .next_packet()
        .expect_err("captured length above original length");
    assert!(length_error.to_string().contains("length metadata"));
}

fn fixture(
    order: ByteOrder,
    resolution: TimestampResolution,
    fraction: u32,
    link_type: u32,
) -> Vec<u8> {
    let mut bytes = match (order, resolution) {
        (ByteOrder::Little, TimestampResolution::Microseconds) => vec![0xd4, 0xc3, 0xb2, 0xa1],
        (ByteOrder::Big, TimestampResolution::Microseconds) => vec![0xa1, 0xb2, 0xc3, 0xd4],
        (ByteOrder::Little, TimestampResolution::Nanoseconds) => vec![0x4d, 0x3c, 0xb2, 0xa1],
        (ByteOrder::Big, TimestampResolution::Nanoseconds) => vec![0xa1, 0xb2, 0x3c, 0x4d],
    };
    push_u16(&mut bytes, 2, order);
    push_u16(&mut bytes, 4, order);
    push_u32(&mut bytes, 0, order);
    push_u32(&mut bytes, 0, order);
    push_u32(&mut bytes, 65_535, order);
    push_u32(&mut bytes, link_type, order);
    push_u32(&mut bytes, 7, order);
    push_u32(&mut bytes, fraction, order);
    push_u32(&mut bytes, 4, order);
    push_u32(&mut bytes, 4, order);
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    bytes
}

fn push_u16(bytes: &mut Vec<u8>, value: u16, order: ByteOrder) {
    let encoded = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    bytes.extend_from_slice(&encoded);
}

fn push_u32(bytes: &mut Vec<u8>, value: u32, order: ByteOrder) {
    let encoded = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    bytes.extend_from_slice(&encoded);
}

fn write_u32_at(bytes: &mut [u8], offset: usize, value: u32, order: ByteOrder) {
    let encoded = match order {
        ByteOrder::Little => value.to_le_bytes(),
        ByteOrder::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + 4].copy_from_slice(&encoded);
}
