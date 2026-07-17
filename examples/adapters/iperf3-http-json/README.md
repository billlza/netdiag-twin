# iperf3 HTTP/JSON Adapter

Converts `iperf3 -J` output into the canonical NetDiag adapter payload.

```bash
iperf3 -J -c 10.0.0.20 -t 10 > iperf3.json
python3 adapter.py \
  --iperf-json iperf3.json \
  --sample lab-congestion-001 \
  --scenario-id lab-congestion-001 \
  --ground-truth congestion
```

For live use, omit `--iperf-json` and pass `--server`. TCP preserves iperf's
retransmit count as `retry_events`. Because the summary does not provide a
reliable sent-segment denominator, the adapter leaves `retransmission_rate` at
the canonical zero placeholder and marks it `missing` in the top-level
`measurement_quality`; it does not mislabel a count as a rate. TCP throughput is
`measured`, while the retransmit-count mapping to `retry_events` is `estimated`.
UDP marks only jitter, loss, and throughput as `measured`; every other UDP field
is `missing`. Live collection
accepts durations from 1 to 300 seconds and
requires POSIX process-group controls. The adapter enforces a duration-derived
deadline, caps JSON stdout at 4 MiB and stderr at 256 KiB, rejects stderr on a
successful exit, and terminates the complete iperf3 process group on failure.
Offline JSON input must be a regular, non-symlink file and is capped at 4 MiB.
Both live and offline JSON reject duplicate keys, non-finite numbers, malformed
timestamps, unsupported shapes, and out-of-range measurements.
