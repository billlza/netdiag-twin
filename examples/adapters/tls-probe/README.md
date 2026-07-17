# TLS Probe Adapter

Measures TLS handshake failures and latency for a lab endpoint.

```bash
python3 adapter.py \
  --host api.internal \
  --port 443 \
  --count 5 \
  --scenario-id lab-tls-failure-001 \
  --ground-truth tls_failure
```

Certificate-verification and TLS-protocol failures increment
`tls_failure_events`. DNS, timeout, and generic network failures remain distinct
and do not masquerade as TLS failures. Latency covers measured resolver and
socket-operation time for every attempt rather than fabricating a value when
every attempt fails.

The adapter validates every argument before emitting either sample or live JSON.
`count` is limited to 1–20, each timeout to 0.05–10 seconds, the aggregate
`count * timeout` budget to 60 seconds, and the port to 1–65535. Hosts must
contain 1–253 visible ASCII bytes.

Each attempt has one end-to-end deadline covering DNS resolution, TCP connect,
certificate verification, and the TLS handshake. Resolution runs in an isolated
worker process so the operating system resolver can be forcibly terminated and
reaped when it exceeds that deadline. The default system trust store and
hostname verification remain enabled.

`probe_summary.failure_counts` keeps `timeout`, `resolution`, `certificate`,
`network`, and TLS `protocol` failures separate. `tls_failure_events` is the
measured sum of certificate and TLS-protocol failures only;
`dns_failure_events` independently counts resolution failures, and
`timeout_events` counts deadline failures. Raw exception text is never emitted.
Unknown worker or trust-store failures terminate collection instead of being
reported as normal telemetry.

For live output, `latency_ms` and `jitter_ms` describe measured network-operation
duration across all attempts. `fault_start` and `fault_end` are the actual
collection timestamps.

Latency, jitter, timeout counts, resolution failures, and certificate/protocol
TLS failures are `measured`. The application-failure packet-loss mapping is
`fallback`; every unobserved field is `missing`.
