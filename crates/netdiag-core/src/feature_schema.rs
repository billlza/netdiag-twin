/// Canonical feature order shared by dataset validation and ML models.
pub const FEATURES: [&str; 11] = [
    "latency_mean",
    "latency_p95",
    "jitter_std",
    "loss_rate",
    "retrans_rate",
    "timeout",
    "retry",
    "throughput",
    "dns_events",
    "tls_events",
    "quic",
];
