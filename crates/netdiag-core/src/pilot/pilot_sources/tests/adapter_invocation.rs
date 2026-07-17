use super::*;

#[test]
fn adapter_invocations_use_distinct_runtime_directories_and_remove_them() {
    let temp = tempdir().expect("tempdir");
    let tracker = temp.path().join("runtime-directories.txt");
    fs::write(
        temp.path().join("adapter.py"),
        r#"import json
import sys
from pathlib import Path

runtime = Path.cwd()
tracker_arg = next(arg for arg in sys.argv if arg.startswith("--tracker="))
tracker = Path(tracker_arg.split("=", 1)[1])
with tracker.open("a", encoding="utf-8") as output:
    output.write(str(runtime) + "\n")

marker = runtime / "preflight-marker"
if "--preflight" in sys.argv:
    marker.write_text("preflight", encoding="utf-8")
    print(json.dumps({
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "source",
        "collection_mode": "sample",
        "passed": True,
        "checks": [{"name": "runtime-isolation", "status": "ok"}],
        "health": {"status": "ok"},
        "redaction": {"fields": [], "secrets": []}
    }))
    raise SystemExit(0)

if marker.exists():
    print("preflight marker leaked into collect runtime", file=sys.stderr)
    raise SystemExit(12)

print(json.dumps({
    "schema": "netdiag-adapter-payload/v1",
    "collection_mode": "sample",
    "sample": "runtime-isolation",
    "protocol": "test",
    "flow_count": 1,
    "records": [{
        "timestamp": "2026-01-01T00:00:00Z",
        "latency_ms": 1.0,
        "jitter_ms": 0.1,
        "packet_loss_rate": 0.0,
        "retransmission_rate": 0.0,
        "timeout_events": 0.0,
        "retry_events": 0.0,
        "throughput_mbps": 100.0,
        "dns_failure_events": 0.0,
        "tls_failure_events": 0.0,
        "quic_blocked_ratio": 0.0
    }],
    "experiment": {
        "scenario_id": "runtime-isolation",
        "fault_start": "2026-01-01T00:00:00Z",
        "fault_end": "2026-01-01T00:00:01Z",
        "ground_truth": "normal"
    }
}))
"#,
    )
    .expect("adapter script");

    let mut source = contract_sample_source(PilotSourceKind::AdapterSample, "adapter.py");
    source
        .adapter
        .args
        .push(format!("--tracker={}", tracker.display()));
    load_pilot_source(&source, temp.path()).expect("isolated adapter invocations");

    let runtime_directories = fs::read_to_string(&tracker)
        .expect("runtime directory tracker")
        .lines()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    assert_eq!(runtime_directories.len(), 2, "preflight and collect paths");
    assert_ne!(runtime_directories[0], runtime_directories[1]);
    for runtime_directory in runtime_directories {
        assert!(runtime_directory.is_absolute());
        assert!(
            !runtime_directory.exists(),
            "runtime directory survived process completion: {}",
            runtime_directory.display()
        );
    }
}
