# OpenConfig/gNMI Adapter

Converts normalized gNMI/OpenConfig interface telemetry into the NetDiag adapter payload. Use `--input-json` for captured notifications or `--emit-sample` for CI validation.

```bash
python3 adapter.py --emit-sample
python3 adapter.py --input-json notifications.json
```

Live input is intentionally fail-closed. The adapter opens a regular,
non-symlink UTF-8 file with non-following, close-on-exec, and non-blocking file
descriptor flags; reads at most 16 MiB; rejects duplicate JSON keys and
non-finite numbers; and accepts at most 100,000 non-empty notification objects.
Every source counter and measurement used to derive the canonical record is
required, finite, and non-negative. Loss and retransmission percentages must
remain in the inclusive `0..100` range. Live mode refuses to start on a
platform that cannot provide all required descriptor flags. The boundary stays
in this file because Pilot executes an isolated single-file snapshot.

RTT, jitter, and throughput are direct canonical measurements. Discard and
interface-error mappings are marked `fallback` because they are proxies for
packet loss, retransmission, and retries; unobserved event families are
`missing`.
