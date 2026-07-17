# SNMP IF-MIB Adapter

Converts interval deltas from interface counters into canonical NetDiag telemetry. Keep device polling and credential handling outside this template; pass captured JSON through `--input-json`.

```bash
python3 adapter.py --emit-sample
python3 adapter.py --input-json if-mib-deltas.json
```

Live input is intentionally fail-closed. The adapter opens a regular,
non-symlink UTF-8 file with non-following, close-on-exec, and non-blocking file
descriptor flags; reads at most 16 MiB; rejects duplicate JSON keys and
non-finite numbers; and accepts at most 100,000 non-empty interface objects.
All counters used by the conversion are required, finite, and non-negative;
`interval_seconds` must be greater than zero, and derived percentages must stay
within the inclusive `0..100` range. Live mode refuses to start on a platform
that cannot provide all required descriptor flags. The boundary stays in this
file because Pilot executes an isolated single-file snapshot.

The interval octet-rate calculation is `estimated`. Discard and error mappings
are `fallback` proxies, while RTT, jitter, timeout, DNS, TLS, and QUIC fields are
zero placeholders marked `missing`.
