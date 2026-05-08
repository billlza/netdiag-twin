# OpenTelemetry Collector Config Pack

Use this pack when service reliability teams already emit OTLP metrics and want NetDiag to consume a normalized stream.

Suggested pipeline:

```yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  batch: {}
exporters:
  otlp/netdiag:
    endpoint: 127.0.0.1:4317
    tls:
      insecure: true
service:
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp/netdiag]
```

Pair with `netdiag collect --kind otlp-grpc --endpoint 127.0.0.1:4317`.
