mod registration;
mod registration_bounds;
mod split;
mod validation;

fn feature_payload(seed: f64) -> serde_json::Value {
    serde_json::json!({
        "latency_mean": seed,
        "latency_p95": seed + 10.0,
        "jitter_std": 1.0,
        "loss_rate": 0.0,
        "retrans_rate": 0.0,
        "timeout": 0.0,
        "retry": 0.0,
        "throughput": 100.0,
        "dns_events": 0.0,
        "tls_events": 0.0,
        "quic": 0.0
    })
}
