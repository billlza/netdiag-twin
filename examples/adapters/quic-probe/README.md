# QUIC Probe Adapter

Uses a UDP probe as a low-dependency QUIC reachability signal. In a full lab,
replace this reachability mechanism with the lab's HTTP/3 or QUIC client and
keep the same JSON shape.

```bash
python3 adapter.py \
  --host quic.internal \
  --port 443 \
  --count 10 \
  --scenario-id lab-quic-blocked-001 \
  --ground-truth udp_quic_blocked
```

Timeouts increase `quic_blocked_ratio`. Latency covers measured resolver and
socket-operation time for every attempt rather than fabricating a value when
every attempt fails.

This adapter is deliberately a UDP reachability signal; a reply is not proof of
a complete QUIC or HTTP/3 handshake. The adapter validates every argument before
emitting either sample or live JSON. `count` is limited to 1–20, each timeout to
0.05–10 seconds, the aggregate `count * timeout` budget to 60 seconds, and the
port to 1–65535. Hosts must contain 1–253 visible ASCII bytes.

Each attempt has one end-to-end deadline covering DNS resolution, UDP connect,
send, and receive. Resolution runs in an isolated worker process so a blocked
operating-system resolver can be forcibly terminated and reaped. Connected UDP
sockets accept replies only from the resolved peer.

`probe_summary.failure_counts` distinguishes `timeout`, `resolution`, and
`network` outcomes. Only timeouts contribute to `quic_blocked_ratio`; all known
failed attempts contribute to `packet_loss_rate`. Raw operating-system error
text is never emitted, and internal worker failures terminate collection.
Live `fault_start` and `fault_end` are the actual collection timestamps.

Latency, jitter, timeout counts, and resolution failures are `measured`. The
packet-loss and blocking ratios are `fallback` proxies because UDP reachability
does not prove a complete QUIC exchange. Every unobserved field is `missing`.
