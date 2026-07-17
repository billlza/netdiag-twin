# tc/netem Lab Adapter

Emits a canonical read-only plan for a controlled `tc netem` impairment window.
Version 0.5.3 does not execute `tc qdisc replace`: replacing a root qdisc without
capturing its identity, verifying the applied state, and guaranteeing rollback
across timeout or process failure is not a safe active-operation contract.

```bash
python3 adapter.py \
  --collect \
  --interface eth1 \
  --latency-ms 160 \
  --jitter-ms 25 \
  --loss-pct 1.4 \
  --throughput-mbps 20 \
  --scenario-id lab-congestion-001 \
  --ground-truth congestion
```

Interface names and all numeric fault parameters are validated before a plan is
emitted. Passing `--apply` to preflight returns a structured failed check;
passing it to collection fails before any system command runs. Active mutation
can return only after a future implementation binds preflight to the exact qdisc
identity and provides verified, crash-safe rollback.

Because this adapter emits an unapplied plan, latency, jitter, loss, and
throughput are `fallback`, not measurements. It no longer derives a transport
retransmission rate or retry count from loss percentage; those and every other
unobserved field are zero placeholders marked `missing`.
