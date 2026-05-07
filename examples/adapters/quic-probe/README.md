# QUIC Probe Adapter

Uses a UDP probe as a low-dependency QUIC reachability signal. In a full lab,
replace `udp_probe` with the lab's HTTP/3 or QUIC client and keep the same JSON
shape.

```bash
python3 adapter.py \
  --host quic.internal \
  --port 443 \
  --count 10 \
  --scenario-id lab-quic-blocked-001 \
  --ground-truth udp_quic_blocked
```

Timeouts increase `quic_blocked_ratio`; successful replies contribute to
`latency_ms`.
