use super::super::*;
use super::quality;

#[cfg(target_os = "macos")]
#[test]
fn netstat_collection_uses_the_absolute_macos_system_tool() {
    assert_eq!(NETSTAT_PROGRAM, "/usr/sbin/netstat");
    assert!(std::path::Path::new(NETSTAT_PROGRAM).is_absolute());
}

#[cfg(not(target_os = "macos"))]
#[test]
fn system_counter_collection_fails_explicitly_off_macos() {
    let error = read_netstat_counters(&CaptureControl::default())
        .expect_err("unsupported platforms must not search PATH for netstat");
    assert!(
        error.to_string().contains("supported only on macOS"),
        "{error}"
    );
}

#[test]
fn system_counter_intervals_fail_before_platform_access_instead_of_clamping() {
    for interval in [Duration::ZERO, Duration::from_secs(11)] {
        let error = load_system_counters(&SystemCountersConfig {
            interface: None,
            interval,
            sample: "invalid_interval".to_string(),
        })
        .expect_err("out-of-range interval must fail before platform access");
        assert!(error.to_string().contains("between 1 and 10"), "{error}");
    }
}

#[test]
fn netstat_parser_computes_interface_counter_deltas() {
    let before = parse_netstat_counters(
        "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
         en0 1500 <Link#4> aa 10 1 1000 20 2 2000 0\n",
    )
    .expect("before");
    let after = parse_netstat_counters(
        "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
         en0 1500 <Link#4> aa 15 1 1600 30 3 2600 0\n",
    )
    .expect("after");

    let delta = diff_counters(&before, &after, Some("en0")).expect("delta");

    assert_eq!(delta.bytes, 1_200);
    assert_eq!(delta.packets, 15);
    assert_eq!(delta.errors, 1);
}

#[test]
fn netstat_counter_delta_allows_quiet_interfaces() {
    let before = parse_netstat_counters(
        "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
         en0 1500 <Link#4> aa 10 1 1000 20 2 2000 0\n",
    )
    .expect("before");
    let after = parse_netstat_counters(
        "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
         en0 1500 <Link#4> aa 10 1 1000 20 2 2000 0\n",
    )
    .expect("after");

    let delta = diff_counters(&before, &after, Some("en0")).expect("quiet delta");

    assert_eq!(delta.bytes, 0);
    assert_eq!(delta.packets, 0);
    assert_eq!(delta.errors, 0);
}

#[test]
fn netstat_counter_delta_reports_unknown_interface() {
    let before = parse_netstat_counters(
        "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
         en0 1500 <Link#4> aa 10 1 1000 20 2 2000 0\n",
    )
    .expect("before");
    let after = parse_netstat_counters(
        "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
         en0 1500 <Link#4> aa 15 1 1600 30 3 2600 0\n",
    )
    .expect("after");

    let err = diff_counters(&before, &after, Some("utun404")).expect_err("unknown interface");

    assert!(
        err.to_string()
            .contains("not found in initial sample: utun404")
    );
}

#[test]
fn netstat_counter_delta_aggregates_all_interfaces() {
    let before = parse_netstat_counters(
        "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
         en0 1500 <Link#4> aa 10 1 1000 20 2 2000 0\n\
         en1 1500 <Link#5> bb 4 0 400 6 1 600 0\n",
    )
    .expect("before");
    let after = parse_netstat_counters(
        "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
         en0 1500 <Link#4> aa 15 1 1600 30 3 2600 0\n\
         en1 1500 <Link#5> bb 8 1 900 9 1 900 0\n",
    )
    .expect("after");

    let delta = diff_counters(&before, &after, Some("all")).expect("all interfaces");

    assert_eq!(delta.bytes, 2_000);
    assert_eq!(delta.packets, 22);
    assert_eq!(delta.errors, 2);
}

#[test]
fn netstat_parser_rejects_unavailable_dash_counters() {
    let error = parse_netstat_counters(
        "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
         utun0 1380 <Link#9> aa - - - 4 - 800 0\n",
    )
    .expect_err("unavailable counter must not become zero");

    assert!(error.to_string().contains("unavailable"), "{error}");
}

#[test]
fn netstat_parser_rejects_malformed_counter_values() {
    let err = parse_netstat_counters(
        "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
         en0 1500 <Link#4> aa nope 1 1000 20 2 2000 0\n",
    )
    .expect_err("bad counter");

    assert!(err.to_string().contains("invalid netstat counter"));
}

#[test]
fn netstat_parser_rejects_counter_pair_overflow() {
    let error = parse_netstat_counters(&format!(
        "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
         en0 1500 <Link#4> aa 0 0 {} 0 0 1 0\n",
        u64::MAX
    ))
    .expect_err("inbound plus outbound overflow must fail");

    assert!(
        error.to_string().contains("bytes counter overflowed"),
        "{error}"
    );
}

#[test]
fn netstat_counter_delta_rejects_reset_and_interface_churn() {
    let initial = BTreeMap::from([(
        "en0".to_string(),
        InterfaceCounters {
            bytes: 100,
            packets: 10,
            errors: 1,
        },
    )]);
    let reset = BTreeMap::from([(
        "en0".to_string(),
        InterfaceCounters {
            bytes: 99,
            packets: 10,
            errors: 1,
        },
    )]);
    let reset_error = diff_counters(&initial, &reset, Some("en0"))
        .expect_err("counter reset must not become zero delta");
    assert!(
        reset_error.to_string().contains("bytes decreased"),
        "{reset_error}"
    );

    let appeared = BTreeMap::from([
        ("en0".to_string(), initial["en0"]),
        ("en1".to_string(), InterfaceCounters::default()),
    ]);
    let churn_error = diff_counters(&initial, &appeared, Some("all"))
        .expect_err("new interface must invalidate aggregate interval");
    assert!(
        churn_error.to_string().contains("appeared"),
        "{churn_error}"
    );
}

#[test]
fn netstat_counter_delta_rejects_aggregate_overflow() {
    let before = BTreeMap::from([
        ("en0".to_string(), InterfaceCounters::default()),
        ("en1".to_string(), InterfaceCounters::default()),
    ]);
    let after = BTreeMap::from([
        (
            "en0".to_string(),
            InterfaceCounters {
                bytes: u64::MAX,
                ..InterfaceCounters::default()
            },
        ),
        (
            "en1".to_string(),
            InterfaceCounters {
                bytes: 1,
                ..InterfaceCounters::default()
            },
        ),
    ]);

    let error =
        diff_counters(&before, &after, Some("all")).expect_err("aggregate overflow must fail");

    assert!(
        error.to_string().contains("aggregate system counter byte"),
        "{error}"
    );
}

#[test]
fn system_counter_result_rejects_packet_total_overflow() {
    let error = system_counter_delta_to_result(
        CounterDelta {
            bytes: 0,
            packets: u64::MAX,
            errors: 1,
        },
        Duration::from_secs(1),
        Utc::now(),
        &SystemCountersConfig {
            interface: Some("all".to_string()),
            interval: Duration::from_secs(1),
            sample: "overflow".to_string(),
        },
    )
    .expect_err("packet total overflow must fail");

    assert!(
        error.to_string().contains("packet and error totals"),
        "{error}"
    );
}

#[test]
fn system_counter_delta_to_result_marks_quality_without_netstat() {
    let loaded = system_counter_delta_to_result(
        CounterDelta {
            bytes: 2_000_000,
            packets: 95,
            errors: 5,
        },
        Duration::from_secs(2),
        Utc::now(),
        &SystemCountersConfig {
            interface: Some("en0".to_string()),
            interval: Duration::from_secs(2),
            sample: "counter_fixture".to_string(),
        },
    )
    .expect("counter result");

    assert_eq!(loaded.ingest.records[0].throughput_mbps, 8.0);
    assert_eq!(loaded.ingest.records[0].packet_loss_rate, 5.0);
    assert_eq!(
        quality(&loaded.ingest, "throughput_mbps"),
        MetricQuality::Measured
    );
    assert_eq!(
        quality(&loaded.ingest, "retransmission_rate"),
        MetricQuality::Fallback
    );
    assert_eq!(loaded.provenance["interface"], "en0");
}

#[test]
fn capture_control_reports_progress_and_cancels_before_work() {
    let cancel = Arc::new(AtomicBool::new(false));
    let observed = Arc::new(Mutex::new(Vec::<CaptureProgress>::new()));
    let observed_sink = Arc::clone(&observed);
    let control = CaptureControl::new(Arc::clone(&cancel)).with_progress(move |progress| {
        observed_sink.lock().expect("progress lock").push(progress);
    });

    report_counter_progress(
        &control,
        Instant::now(),
        Duration::from_secs(1),
        0,
        None,
        "sampling",
        "test progress",
    );
    control.cancel();

    assert!(control.is_cancelled());
    let progress = observed.lock().expect("progress lock");
    assert_eq!(progress.len(), 1);
    assert_eq!(progress[0].stage, "sampling");
    assert_eq!(progress[0].message, "test progress");
}
