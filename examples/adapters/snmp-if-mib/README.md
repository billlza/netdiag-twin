# SNMP IF-MIB Adapter

Converts interval deltas from interface counters into canonical NetDiag telemetry. Keep device polling and credential handling outside this template; pass captured JSON through `--input-json`.

```bash
python3 adapter.py --emit-sample
python3 adapter.py --input-json if-mib-deltas.json
```
