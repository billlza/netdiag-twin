# tc/netem Lab Adapter

Emits a canonical payload for a controlled `tc netem` impairment window. By
default it only reports the planned fault; pass `--apply` on a Linux lab host to
run `tc qdisc replace`.

```bash
python3 adapter.py \
  --interface eth1 \
  --latency-ms 160 \
  --jitter-ms 25 \
  --loss-pct 1.4 \
  --throughput-mbps 20 \
  --scenario-id lab-congestion-001 \
  --ground-truth congestion
```

Keep the reset command in the lab runbook, for example
`tc qdisc del dev eth1 root`.
