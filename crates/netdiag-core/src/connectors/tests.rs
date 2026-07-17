mod http_json_security;
mod http_prometheus;
mod native_pcap;
mod otlp_metrics;
mod system_counters;

fn quality(ingest: &super::IngestResult, field: &str) -> super::MetricQuality {
    ingest
        .metric_provenance
        .iter()
        .find(|item| item.field == field)
        .map(|item| item.quality)
        .expect("metric quality")
}
