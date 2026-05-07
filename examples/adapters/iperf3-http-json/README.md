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

For live use, omit `--iperf-json` and pass `--server`. TCP maps retransmits to
`retransmission_rate`; UDP maps iperf jitter/loss into `jitter_ms` and
`packet_loss_rate`.
