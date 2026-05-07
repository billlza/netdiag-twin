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

Failed handshakes increment `tls_failure_events`; successful handshakes
contribute to `latency_ms`.
