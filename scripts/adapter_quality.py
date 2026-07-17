#!/usr/bin/env python3
from __future__ import annotations

from typing import Any


CANONICAL_NUMERIC_METRICS = (
    "latency_ms",
    "jitter_ms",
    "packet_loss_rate",
    "retransmission_rate",
    "timeout_events",
    "retry_events",
    "throughput_mbps",
    "dns_failure_events",
    "tls_failure_events",
    "quic_blocked_ratio",
)
MEASUREMENT_QUALITY_VALUES = frozenset(
    {"measured", "estimated", "fallback", "missing"}
)


def validate_declared_measurement_quality(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise RuntimeError("adapter payload must be a JSON object")
    quality = payload.get("measurement_quality")
    if not isinstance(quality, dict):
        raise RuntimeError("adapter payload must declare measurement_quality")

    expected = set(CANONICAL_NUMERIC_METRICS)
    declared = set(quality)
    missing = sorted(expected - declared)
    unknown = sorted(declared - expected)
    if missing:
        raise RuntimeError(
            "measurement_quality is missing canonical metrics: " + ", ".join(missing)
        )
    if unknown:
        raise RuntimeError(
            "measurement_quality contains unknown metrics: " + ", ".join(unknown)
        )

    invalid = sorted(
        metric
        for metric in CANONICAL_NUMERIC_METRICS
        if not isinstance(quality[metric], str)
        or quality[metric] not in MEASUREMENT_QUALITY_VALUES
    )
    if invalid:
        raise RuntimeError(
            "measurement_quality contains unsupported values for: "
            + ", ".join(invalid)
        )
