# FRR Routing-State Adapter

Converts captured FRR route churn or adjacency state JSON into canonical NetDiag telemetry. Use it for routing-loop, convergence, and asymmetric-routing lab experiments where route state is corroborating evidence rather than a seventh fault label.

```bash
python3 adapter.py --emit-sample
python3 adapter.py --input-json frr-state.json
```

Live input is intentionally fail-closed. The adapter opens a regular,
non-symlink UTF-8 file with non-following, close-on-exec, and non-blocking file
descriptor flags; reads at most 16 MiB; rejects duplicate JSON keys and
non-finite numbers; and accepts at most 100,000 non-empty routing-state objects.
Timestamp, route churn, adjacency flap, and forwarding-stall inputs used by the
conversion are required and validated instead of being replaced with zeros.
Live mode refuses to start on a platform that cannot provide all required
descriptor flags. The boundary stays in this file because Pilot executes an
isolated single-file snapshot.

FRR state is corroborating evidence, not a transport measurement. Forwarding
stall, adjacency-flap, route-churn, and synthetic throughput mappings are
`fallback`. `packet_loss_rate` and `retransmission_rate` remain zero placeholders
marked `missing`; flap counts are never emitted as a canonical rate.
