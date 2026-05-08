# FRR Routing-State Adapter

Converts captured FRR route churn or adjacency state JSON into canonical NetDiag telemetry. Use it for routing-loop, convergence, and asymmetric-routing lab experiments where route state is corroborating evidence rather than a seventh fault label.

```bash
python3 adapter.py --emit-sample
python3 adapter.py --input-json frr-state.json
```
