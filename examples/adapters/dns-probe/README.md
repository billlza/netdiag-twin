# DNS Probe Adapter

Runs repeated resolver lookups and emits DNS failures as canonical events.

```bash
python3 adapter.py \
  --host service.internal \
  --count 10 \
  --scenario-id lab-dns-failure-001 \
  --ground-truth dns_failure
```

Use this behind an HTTP wrapper or write the JSON to a scenario `trace-file`
fixture after converting the `records` array to CSV/JSON trace input.

The adapter validates every argument before emitting either sample or live JSON.
`count` is limited to 1–20, each timeout to 0.05–10 seconds, and the aggregate
`count * timeout` budget to 60 seconds. Hosts must contain 1–253 visible ASCII
bytes. These bounds apply to sample mode as well, so an invalid sample request
fails instead of producing a misleading fixture.

Live lookups run in an isolated resolver process because a socket timeout does
not bound the operating system's `getaddrinfo` call. The parent enforces the
deadline and forcibly terminates and reaps a timed-out resolver. Known lookup
outcomes are reported in `probe_summary.failure_counts` as `timeout`,
`resolution`, or `network`; an invalid worker response or lifecycle failure
terminates collection without JSON. Error details returned by the resolver are
not copied into output or stderr.

For live output, `latency_ms` and `jitter_ms` describe measured resolver
duration across all attempts, including failed attempts. Successful resolutions
exclude worker start-up overhead; a forcibly terminated lookup reports its
observed deadline duration. `fault_start` and `fault_end` are the actual
collection timestamps rather than caller-supplied placeholders.

The top-level quality declaration marks latency, jitter, timeout counts, and DNS
failure counts `measured`. Mapping application lookup failures to canonical
packet loss is a `fallback` proxy; every unobserved field is `missing`.
