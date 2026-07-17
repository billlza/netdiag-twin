use super::super::*;
use super::quality;
use crate::resource_limits::{MAX_PCAP_PACKET_LIMIT, MAX_SOURCE_INPUT_BYTES};
use std::cell::Cell;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[test]
fn native_pcap_stats_keep_observed_values_and_warn_on_missing_fields() {
    let mut stats = PacketStats {
        packet_count: 4,
        total_bytes: 4_000,
        tcp_packets: 4,
        retransmissions: 1,
        first_ts_ms: Some(1_000),
        last_ts_ms: Some(2_000),
        ..PacketStats::default()
    };
    stats
        .flows
        .insert("10.0.0.1:443 -> 10.0.0.2:51515".to_string(), 4_000);

    let loaded = packet_stats_to_result(
        stats,
        "pcap_fixture",
        &NativePcapSource::Interface("lo0".to_string()),
    )
    .expect("pcap stats");

    assert_eq!(loaded.ingest.records[0].throughput_mbps, 0.032);
    assert_eq!(loaded.ingest.records[0].retransmission_rate, 25.0);
    assert!(
        loaded
            .ingest
            .warnings
            .iter()
            .any(|warning| warning.column == "packet_loss_rate")
    );
    assert_eq!(
        loaded
            .payload
            .as_ref()
            .and_then(|value| value.get("total_bytes"))
            .and_then(Value::as_u64),
        Some(4_000)
    );
    assert_eq!(
        loaded
            .payload
            .as_ref()
            .and_then(|value| value.get("flow_count"))
            .and_then(Value::as_u64),
        Some(1)
    );
}

#[test]
fn native_pcap_stats_reject_missing_timestamps() {
    let error = packet_stats_to_result(
        PacketStats {
            packet_count: 1,
            total_bytes: 64,
            ..PacketStats::default()
        },
        "pcap_missing_timestamp",
        &NativePcapSource::Interface("fixture".to_string()),
    )
    .expect_err("packet statistics without timestamps must fail closed");

    assert!(
        error
            .to_string()
            .contains("produced packets without timestamps"),
        "unexpected error: {error}"
    );
}

#[test]
fn native_pcap_stats_reject_non_monotonic_timestamps() {
    let error = packet_stats_to_result(
        PacketStats {
            packet_count: 1,
            total_bytes: 64,
            first_ts_ms: Some(2_000),
            last_ts_ms: Some(1_000),
            ..PacketStats::default()
        },
        "pcap_non_monotonic_timestamp",
        &NativePcapSource::Interface("fixture".to_string()),
    )
    .expect_err("non-monotonic packet timestamps must fail closed");

    assert!(
        error.to_string().contains("timestamps are not monotonic"),
        "unexpected error: {error}"
    );
}

#[test]
fn native_pcap_timestamp_rejects_invalid_microseconds_and_overflow() {
    assert_eq!(packet_timestamp_ms(1, 999_999).expect("timestamp"), 1_999);

    for micros in [-1, 1_000_000] {
        let error = packet_timestamp_ms(1, micros).expect_err("invalid microseconds must fail");
        assert!(error.to_string().contains("microseconds"), "{error}");
    }

    let error = packet_timestamp_ms(i64::MAX, 0).expect_err("seconds overflow must fail");
    assert!(error.to_string().contains("millisecond range"), "{error}");
}

#[test]
fn native_pcap_file_fixture_runs_full_loader() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("tcp_retransmission.pcap");
    let tcp = ethernet_ipv4_tcp_packet(443, 51_515, 7, b"payload");
    let captured_bytes = u64::try_from(tcp.len() * 2).expect("fixture packet bytes");
    write_pcap_fixture(&path, &[tcp.clone(), tcp]).expect("pcap fixture");

    let loaded = load_native_pcap(&NativePcapConfig {
        source: NativePcapSource::File(path),
        timeout: Duration::from_secs(1),
        packet_limit: 32,
        sample: "pcap_file_fixture".to_string(),
    })
    .expect("pcap file load");

    assert_eq!(loaded.ingest.records.len(), 1);
    assert_eq!(loaded.ingest.records[0].retransmission_rate, 50.0);
    assert_eq!(
        quality(&loaded.ingest, "throughput_mbps"),
        MetricQuality::Measured
    );
    assert_eq!(
        quality(&loaded.ingest, "quic_blocked_ratio"),
        MetricQuality::Fallback
    );
    assert_eq!(loaded.provenance["kind"], "native_pcap");
    assert_eq!(loaded.resource_usage.input_bytes, captured_bytes);
    assert_eq!(loaded.resource_usage.records, 1);
}

#[test]
fn native_pcap_rejects_invalid_limits_before_source_access() {
    let missing = Path::new("definitely-missing-capture.pcap").to_path_buf();
    let zero_limit = load_native_pcap(&NativePcapConfig {
        source: NativePcapSource::File(missing.clone()),
        timeout: Duration::from_secs(1),
        packet_limit: 0,
        sample: "invalid_limit".to_string(),
    })
    .expect_err("zero packet limit must fail before source inspection");
    assert!(
        zero_limit.to_string().contains("packet limit"),
        "{zero_limit}"
    );

    let excessive_limit = load_native_pcap(&NativePcapConfig {
        source: NativePcapSource::File(missing.clone()),
        timeout: Duration::from_secs(1),
        packet_limit: MAX_PCAP_PACKET_LIMIT + 1,
        sample: "invalid_limit".to_string(),
    })
    .expect_err("excessive packet limit must fail before source inspection");
    assert!(
        excessive_limit.to_string().contains("packet limit"),
        "{excessive_limit}"
    );

    let zero_timeout = load_native_pcap(&NativePcapConfig {
        source: NativePcapSource::File(missing),
        timeout: Duration::ZERO,
        packet_limit: 1,
        sample: "invalid_timeout".to_string(),
    })
    .expect_err("zero timeout must fail before source inspection");
    assert!(
        zero_timeout.to_string().contains("timeout"),
        "{zero_timeout}"
    );
}

#[test]
fn capture_deadline_rejects_invalid_timeouts_at_construction() {
    for timeout in [Duration::ZERO, Duration::from_secs(301)] {
        let error = CaptureDeadline::new(timeout, "test capture")
            .expect_err("deadline constructor must enforce collection bounds");
        assert!(error.to_string().contains("timeout"), "{error}");
    }

    CaptureDeadline::new(Duration::from_millis(1), "test capture")
        .expect("minimum deadline must be accepted");
    CaptureDeadline::new(Duration::from_secs(300), "test capture")
        .expect("maximum deadline must be accepted");
}

#[test]
fn native_pcap_cancellation_fails_before_source_access_and_leaves_no_handle() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("cancelled.pcap");
    write_pcap_fixture(&path, &[ethernet_ipv4_udp_packet(53, 53_000, b"dns")])
        .expect("pcap fixture");
    let control = CaptureControl::default();
    control.cancel();

    let error = load_native_pcap_with_control(
        &NativePcapConfig {
            source: NativePcapSource::File(path.clone()),
            timeout: Duration::from_secs(1),
            packet_limit: 1,
            sample: "cancelled_pcap".to_string(),
        },
        &control,
    )
    .expect_err("cancelled capture must fail closed");

    assert!(matches!(
        error,
        NetdiagError::CaptureCancelled {
            context: "native pcap capture"
        }
    ));
    std::fs::remove_file(path).expect("cancelled capture must not retain a file handle");
}

#[test]
fn native_pcap_snapshot_rejects_same_length_mutation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("mutable.pcap");
    let initial = vec![1_u8; 64];
    let replacement = vec![2_u8; 64];
    std::fs::write(&path, initial).expect("initial snapshot");
    let checkpoints = Cell::new(0_usize);

    let error = crate::storage::read_stable_regular_file_bounded_with_checkpoint(
        &path,
        MAX_SOURCE_INPUT_BYTES,
        || {
            let current = checkpoints.get() + 1;
            checkpoints.set(current);
            if current == 3 {
                std::fs::write(&path, &replacement).expect("same-length mutation");
            }
            Ok(())
        },
    )
    .expect_err("mutated pcap snapshot must fail closed");

    assert!(
        error
            .to_string()
            .contains("changed while it was being read"),
        "{error}"
    );
}

#[test]
fn native_pcap_snapshot_cancellation_releases_file_handle() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("cancel-during-read.pcap");
    std::fs::write(&path, vec![0_u8; 128 * 1024]).expect("pcap snapshot");
    let control = CaptureControl::default();
    let deadline =
        CaptureDeadline::new(Duration::from_secs(1), "native pcap capture").expect("deadline");
    let checkpoints = Cell::new(0_usize);

    let error = crate::storage::read_stable_regular_file_bounded_with_checkpoint(
        &path,
        MAX_SOURCE_INPUT_BYTES,
        || {
            let current = checkpoints.get() + 1;
            checkpoints.set(current);
            if current == 2 {
                control.cancel();
            }
            deadline.ensure_remaining(&control)
        },
    )
    .expect_err("mid-snapshot cancellation must fail closed");

    assert!(matches!(
        error,
        NetdiagError::CaptureCancelled {
            context: "native pcap capture"
        }
    ));
    std::fs::remove_file(path).expect("cancelled snapshot must release its file handle");
}

#[cfg(unix)]
#[test]
fn native_pcap_file_rejects_symlink_sources() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("capture.pcap");
    write_pcap_fixture(&target, &[ethernet_ipv4_udp_packet(53, 53_000, b"dns")])
        .expect("pcap fixture");
    let linked = temp.path().join("linked.pcap");
    symlink(&target, &linked).expect("pcap symlink");

    let error = load_native_pcap(&NativePcapConfig {
        source: NativePcapSource::File(linked),
        timeout: Duration::from_secs(1),
        packet_limit: 1,
        sample: "linked_pcap".to_string(),
    })
    .expect_err("pcap symlink must fail closed");
    assert!(error.to_string().contains("symlink/reparse"), "{error}");
}

#[test]
fn native_pcap_file_deadline_never_returns_partial_success() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("deadline.pcap");
    write_pcap_fixture(&path, &[ethernet_ipv4_udp_packet(53, 53_000, b"dns")])
        .expect("pcap fixture");
    let deadline =
        CaptureDeadline::new(Duration::from_millis(1), "native pcap capture").expect("deadline");
    std::thread::sleep(Duration::from_millis(2));
    let mut stats = PacketStats::default();
    let mut budget = NetworkSourceBudget::default();
    let error = load_native_pcap_file(
        &path,
        1,
        deadline,
        &CaptureControl::default(),
        &mut stats,
        &mut budget,
    )
    .expect_err("expired deadline must fail before returning any sample");
    assert!(error.to_string().contains("deadline"), "{error}");
    assert_eq!(stats.packet_count, 0);
}

#[test]
fn native_pcap_file_rejects_input_bytes_before_processing_over_limit_packet() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("oversized-input.pcap");
    let tcp = ethernet_ipv4_tcp_packet(443, 51_515, 7, b"payload");
    let max_packet_length = u32::try_from(MAX_SOURCE_INPUT_BYTES).expect("pcap byte limit");
    let second_packet_length = u32::try_from(tcp.len()).expect("fixture packet length");
    write_pcap_fixture_with_original_lengths(
        &path,
        &[
            (tcp.clone(), max_packet_length),
            (tcp, second_packet_length),
        ],
    )
    .expect("oversized pcap fixture");

    let error = load_native_pcap(&NativePcapConfig {
        source: NativePcapSource::File(path),
        timeout: Duration::from_secs(1),
        packet_limit: 32,
        sample: "pcap_budget_fixture".to_string(),
    })
    .expect_err("pcap input above the source byte limit must fail closed");

    assert!(error.to_string().contains("native pcap file"));
    assert!(error.to_string().contains("cumulative input size"));
}

#[test]
fn native_pcap_file_propagates_truncated_packet_errors() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("truncated.pcap");
    write_pcap_fixture(&path, &[]).expect("pcap header");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("append truncated packet");
    file.write_all(&1_777_000_000_u32.to_le_bytes())
        .expect("packet seconds");
    file.write_all(&0_u32.to_le_bytes()).expect("packet micros");
    file.write_all(&64_u32.to_le_bytes())
        .expect("captured length");
    file.write_all(&64_u32.to_le_bytes())
        .expect("original length");
    file.write_all(&[0xde, 0xad, 0xbe, 0xef])
        .expect("partial packet body");
    drop(file);

    let error = load_native_pcap(&NativePcapConfig {
        source: NativePcapSource::File(path.clone()),
        timeout: Duration::from_secs(1),
        packet_limit: 32,
        sample: "pcap_truncated_fixture".to_string(),
    })
    .expect_err("truncated pcap packet must not masquerade as end-of-file");

    assert!(
        error.to_string().contains("failed while reading pcap file"),
        "unexpected error for {}: {error}",
        path.display()
    );
    std::fs::remove_file(path).expect("parse failure must not retain a file handle");
}

#[test]
fn native_pcap_observe_extracts_flow_bytes_and_retransmission_hints() {
    let mut stats = PacketStats::default();
    let tcp = ethernet_ipv4_tcp_packet(443, 51_515, 7, b"payload");

    observe_packet(1_000, tcp.len(), &tcp, &mut stats);
    observe_packet(1_050, tcp.len(), &tcp, &mut stats);

    assert_eq!(stats.packet_count, 2);
    assert_eq!(stats.tcp_packets, 2);
    assert_eq!(stats.retransmissions, 1);
    assert_eq!(stats.tls_packets, 2);
    assert_eq!(
        stats.flows.get("10.0.0.1:443 -> 10.0.0.2:51515"),
        Some(&(tcp.len() as u64 * 2))
    );
}

#[test]
fn native_pcap_observe_extracts_dns_and_quic_hints_without_policy_claims() {
    let mut stats = PacketStats::default();
    let dns = ethernet_ipv4_udp_packet(53, 53_000, b"dns");
    let quic_like = ethernet_ipv4_udp_packet(44_444, 443, b"quic");

    observe_packet(1_000, dns.len(), &dns, &mut stats);
    observe_packet(1_010, quic_like.len(), &quic_like, &mut stats);

    assert_eq!(stats.udp_packets, 2);
    assert_eq!(stats.dns_packets, 1);
    assert_eq!(stats.quic_packets, 1);
    let loaded = packet_stats_to_result(
        stats,
        "pcap_hints",
        &NativePcapSource::Interface("fixture".to_string()),
    )
    .expect("pcap result");
    assert!(
        loaded
            .ingest
            .warnings
            .iter()
            .any(|warning| warning.column == "quic_blocked_ratio")
    );
}

#[test]
fn native_pcap_malformed_short_packet_does_not_invent_transport_metrics() {
    let mut stats = PacketStats::default();
    observe_packet(1_000, 4, &[0xde, 0xad, 0xbe, 0xef], &mut stats);

    assert_eq!(stats.packet_count, 1);
    assert_eq!(stats.total_bytes, 4);
    assert_eq!(stats.tcp_packets, 0);
    assert_eq!(stats.udp_packets, 0);
    assert_eq!(stats.retransmissions, 0);
    assert!(stats.flows.is_empty());
}

fn ethernet_ipv4_tcp_packet(
    source_port: u16,
    target_port: u16,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = ethernet_ipv4_header(6, 20 + payload.len());
    packet.extend_from_slice(&source_port.to_be_bytes());
    packet.extend_from_slice(&target_port.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&0_u32.to_be_bytes());
    packet.extend_from_slice(&[0x50, 0x18]);
    packet.extend_from_slice(&16_384_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn ethernet_ipv4_udp_packet(source_port: u16, target_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = ethernet_ipv4_header(17, 8 + payload.len());
    packet.extend_from_slice(&source_port.to_be_bytes());
    packet.extend_from_slice(&target_port.to_be_bytes());
    packet.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn ethernet_ipv4_header(protocol: u8, transport_and_payload_len: usize) -> Vec<u8> {
    let total_len = 20 + transport_and_payload_len;
    let mut packet = vec![
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00, 0x45,
        0x00,
    ];
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.push(64);
    packet.push(protocol);
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&[10, 0, 0, 1]);
    packet.extend_from_slice(&[10, 0, 0, 2]);
    packet
}

fn write_pcap_fixture(path: &Path, packets: &[Vec<u8>]) -> std::io::Result<()> {
    let packets_with_lengths = packets
        .iter()
        .map(|packet| {
            u32::try_from(packet.len())
                .map(|length| (packet.as_slice(), length))
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "fixture packet length does not fit in u32",
                    )
                })
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    write_pcap_records(path, packets_with_lengths)
}

fn write_pcap_fixture_with_original_lengths(
    path: &Path,
    packets: &[(Vec<u8>, u32)],
) -> std::io::Result<()> {
    write_pcap_records(
        path,
        packets
            .iter()
            .map(|(packet, original_length)| (packet.as_slice(), *original_length)),
    )
}

fn write_pcap_records<'a>(
    path: &Path,
    packets: impl IntoIterator<Item = (&'a [u8], u32)>,
) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(&0xa1b2c3d4_u32.to_le_bytes())?;
    file.write_all(&2_u16.to_le_bytes())?;
    file.write_all(&4_u16.to_le_bytes())?;
    file.write_all(&0_i32.to_le_bytes())?;
    file.write_all(&0_u32.to_le_bytes())?;
    file.write_all(&65_535_u32.to_le_bytes())?;
    file.write_all(&1_u32.to_le_bytes())?;
    for (idx, (packet, original_length)) in packets.into_iter().enumerate() {
        file.write_all(&1_777_000_000_u32.to_le_bytes())?;
        file.write_all(&((idx as u32) * 1_000).to_le_bytes())?;
        let captured_length = u32::try_from(packet.len()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "fixture packet length does not fit in u32",
            )
        })?;
        file.write_all(&captured_length.to_le_bytes())?;
        file.write_all(&original_length.to_le_bytes())?;
        file.write_all(packet)?;
    }
    Ok(())
}
