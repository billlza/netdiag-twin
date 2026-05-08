# OpenConfig/gNMI Adapter

Converts normalized gNMI/OpenConfig interface telemetry into the NetDiag adapter payload. Use `--input-json` for captured notifications or `--emit-sample` for CI validation.

```bash
python3 adapter.py --emit-sample
python3 adapter.py --input-json notifications.json
```
