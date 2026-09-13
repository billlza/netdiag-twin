use netdiag_core::models::TelemetryWindow;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TrendRange {
    TenSeconds,
    #[default]
    ThirtySeconds,
    OneMinute,
    FiveMinutes,
}

impl TrendRange {
    pub const ALL: [TrendRange; 4] = [
        TrendRange::TenSeconds,
        TrendRange::ThirtySeconds,
        TrendRange::OneMinute,
        TrendRange::FiveMinutes,
    ];

    pub fn seconds(self) -> i64 {
        match self {
            TrendRange::TenSeconds => 10,
            TrendRange::ThirtySeconds => 30,
            TrendRange::OneMinute => 60,
            TrendRange::FiveMinutes => 300,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            TrendRange::TenSeconds => "10s",
            TrendRange::ThirtySeconds => "30s",
            TrendRange::OneMinute => "1m",
            TrendRange::FiveMinutes => "5m",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LatencyMetric {
    P50,
    #[default]
    P95,
    P99,
}

impl LatencyMetric {
    pub const ALL: [LatencyMetric; 3] =
        [LatencyMetric::P50, LatencyMetric::P95, LatencyMetric::P99];

    pub fn label(self) -> &'static str {
        match self {
            LatencyMetric::P50 => "P50",
            LatencyMetric::P95 => "P95",
            LatencyMetric::P99 => "P99",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TrendPoint {
    pub elapsed_s: f64,
    pub value_ms: Option<f64>,
}

/// Missing observations divide the curve instead of joining unrelated samples.
pub fn recorded_trend_segments(points: &[TrendPoint]) -> impl Iterator<Item = &[TrendPoint]> {
    points
        .split(|point| point.value_ms.is_none())
        .filter(|segment| !segment.is_empty())
}

pub fn latency_trend_points(
    windows: &[TelemetryWindow],
    range: TrendRange,
    metric: LatencyMetric,
) -> Vec<TrendPoint> {
    let Some(last) = windows.iter().map(|window| window.end_ts).max() else {
        return Vec::new();
    };
    let cutoff = last - chrono::Duration::seconds(range.seconds());
    let selected = windows
        .iter()
        .filter(|window| window.end_ts >= cutoff)
        .collect::<Vec<_>>();
    let first_ts = selected
        .first()
        .map(|window| window.start_ts)
        .unwrap_or_else(|| windows[0].start_ts);

    selected
        .into_iter()
        .map(|window| TrendPoint {
            elapsed_s: (window.start_ts - first_ts).num_milliseconds() as f64 / 1000.0,
            value_ms: match metric {
                LatencyMetric::P50 => window.latency_ms.p50,
                LatencyMetric::P95 => Some(window.latency_ms.p95),
                LatencyMetric::P99 => window.latency_ms.p99,
            },
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone, Utc};
    use netdiag_core::models::{
        DistributionStats, TelemetryWindow, ThroughputStats, WindowLatencyStats,
    };

    #[test]
    fn trend_points_filter_to_recent_range_and_metric() {
        let windows = (0..10).map(window).collect::<Vec<_>>();
        let points = latency_trend_points(&windows, TrendRange::ThirtySeconds, LatencyMetric::P99);

        assert_eq!(points.len(), 7);
        assert_eq!(points[0].elapsed_s, 0.0);
        assert_eq!(points[0].value_ms, Some(103.0));
        assert_eq!(points.last().expect("last").value_ms, Some(109.0));
    }

    #[test]
    fn trend_points_handle_empty_windows() {
        assert!(latency_trend_points(&[], TrendRange::TenSeconds, LatencyMetric::P95).is_empty());
    }

    #[test]
    fn unrecorded_percentiles_preserve_time_and_break_the_curve() {
        let mut windows = (0..5).map(window).collect::<Vec<_>>();
        windows[0].latency_ms.p50 = None;
        windows[2].latency_ms.p50 = None;
        windows[4].latency_ms.p50 = None;
        let points = latency_trend_points(&windows, TrendRange::ThirtySeconds, LatencyMetric::P50);

        assert_eq!(points.len(), 5);
        assert_eq!(points[0].value_ms, None);
        assert_eq!(points[1].elapsed_s, 5.0);
        let segments = recorded_trend_segments(&points).collect::<Vec<_>>();
        assert_eq!(segments, vec![&points[1..2], &points[3..4]]);
        assert_eq!(segments[0][0].value_ms, Some(51.0));
        assert_eq!(segments[1][0].value_ms, Some(53.0));
    }

    #[test]
    fn historical_windows_keep_p95_without_fabricating_p50_or_p99() {
        let mut windows = (0..3).map(window).collect::<Vec<_>>();
        for window in &mut windows {
            window.latency_ms.p50 = None;
            window.latency_ms.p99 = None;
        }
        for metric in [LatencyMetric::P50, LatencyMetric::P99] {
            let points = latency_trend_points(&windows, TrendRange::ThirtySeconds, metric);
            assert_eq!(points.len(), 3);
            assert!(points.iter().all(|point| point.value_ms.is_none()));
            assert!(recorded_trend_segments(&points).next().is_none());
        }
        let p95 = latency_trend_points(&windows, TrendRange::ThirtySeconds, LatencyMetric::P95);
        assert_eq!(
            recorded_trend_segments(&p95).collect::<Vec<_>>(),
            vec![&p95[..]]
        );
        assert_eq!(p95[1].value_ms, Some(91.0));
    }

    fn window(idx: i64) -> TelemetryWindow {
        let start = Utc
            .with_ymd_and_hms(2026, 4, 30, 0, 0, 0)
            .single()
            .expect("timestamp")
            + Duration::seconds(idx * 5);
        TelemetryWindow {
            start_ts: start,
            end_ts: start + Duration::seconds(5),
            count: 5,
            latency_ms: WindowLatencyStats {
                p50: Some(50.0 + idx as f64),
                mean: 70.0 + idx as f64,
                p95: 90.0 + idx as f64,
                p99: Some(100.0 + idx as f64),
                std: 1.0,
            },
            jitter_ms: DistributionStats::default(),
            packet_loss_rate: 0.0,
            retransmission_rate: 0.0,
            timeout_events: 0.0,
            retry_events: 0.0,
            throughput_mbps: ThroughputStats {
                mean: 10.0,
                p95: 10.0,
                min: Some(10.0),
            },
            dns_failure_events: 0.0,
            tls_failure_events: 0.0,
            quic_blocked_ratio: 0.0,
            raw_rows: 5,
        }
    }
}
