use super::collect_auth::optional_bearer_token_from_lookup;
use anyhow::Context;
use clap::Args;
use netdiag_core::connectors::{
    HttpJsonConfig, NativePcapConfig, OtlpGrpcReceiverConfig, PrometheusExpositionConfig,
    PrometheusQueryRangeConfig, SystemCountersConfig, default_prometheus_mapping, load_http_json,
    load_native_pcap, load_otlp_grpc_receiver, load_prometheus_exposition,
    load_prometheus_mapping_file, load_prometheus_query_range, load_system_counters,
};
use netdiag_core::models::ConnectorHealthSnapshot;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

mod source;
use source::{native_pcap_source, system_interface};

#[derive(Debug, Args)]
pub(crate) struct CollectCommand {
    #[arg(
        long,
        value_parser = [
            "http-json",
            "prometheus-query",
            "prometheus-metrics",
            "otlp-grpc",
            "native-pcap",
            "system-counters"
        ]
    )]
    kind: String,
    #[arg(long)]
    endpoint: String,
    /// Read a bearer token from this explicitly authorized environment variable.
    #[arg(long)]
    bearer_token_env: Option<String>,
    #[arg(long, default_value_t = 8)]
    timeout_secs: u64,
    #[arg(long, default_value_t = 300)]
    lookback_secs: i64,
    #[arg(long, default_value_t = 15)]
    step_secs: u64,
    #[arg(long, default_value_t = 256)]
    packet_limit: usize,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..=10))]
    interval_secs: u64,
    #[arg(long)]
    mapping: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    diagnose: bool,
    #[arg(long, default_value = "artifacts")]
    artifacts: PathBuf,
}

pub(crate) fn run(command: CollectCommand) -> anyhow::Result<()> {
    validate_mapping_usage(&command.kind, command.mapping.as_ref())?;
    let token = optional_bearer_token_from_lookup(
        &command.kind,
        &command.endpoint,
        command.bearer_token_env.as_deref(),
        |name| std::env::var(name),
    )?;
    let loaded = match command.kind.as_str() {
        "http-json" => load_http_json(
            &HttpJsonConfig {
                endpoint: command.endpoint,
                timeout: Duration::from_secs(command.timeout_secs),
            },
            token.as_ref(),
        )?,
        "prometheus-query" => load_prometheus_query_range(
            &PrometheusQueryRangeConfig {
                base_url: command.endpoint,
                timeout: Duration::from_secs(command.timeout_secs),
                lookback_seconds: command.lookback_secs,
                step_seconds: command.step_secs,
                queries: load_mapping(command.mapping)?,
                sample: "cli_prometheus_query".to_string(),
            },
            token.as_ref(),
        )?,
        "prometheus-metrics" => load_prometheus_exposition(
            &PrometheusExpositionConfig {
                endpoint: command.endpoint,
                timeout: Duration::from_secs(command.timeout_secs),
                metrics: load_mapping(command.mapping)?,
                sample: "cli_prometheus_metrics".to_string(),
            },
            token.as_ref(),
        )?,
        "otlp-grpc" => load_otlp_grpc_receiver(&OtlpGrpcReceiverConfig {
            bind_addr: command.endpoint,
            timeout: Duration::from_secs(command.timeout_secs),
            metrics: load_mapping(command.mapping)?,
            sample: "cli_otlp_grpc".to_string(),
        })?,
        "native-pcap" => load_native_pcap(&NativePcapConfig {
            source: native_pcap_source(&command.endpoint)?,
            timeout: Duration::from_secs(command.timeout_secs),
            packet_limit: command.packet_limit,
            sample: "cli_native_pcap".to_string(),
        })?,
        "system-counters" => load_system_counters(&SystemCountersConfig {
            interface: system_interface(command.endpoint),
            interval: Duration::from_secs(command.interval_secs),
            sample: "cli_system_counters".to_string(),
        })?,
        unsupported => anyhow::bail!("unsupported connector kind: {unsupported}"),
    };
    let health = ConnectorHealthSnapshot::from_ingest(
        &command.kind,
        &command.kind,
        &loaded.sample,
        &loaded.ingest,
    );
    if command.diagnose {
        let result = netdiag_core::diagnose_ingest_with_whatif_and_connector_health(
            loaded.ingest,
            &command.artifacts,
            Some(netdiag_core::WhatIfRequest::built_in(
                "line",
                "reroute_path_b",
            )?),
            health,
        )?;
        println!("{}", serde_json::to_string_pretty(&result.report)?);
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "health": health,
                "provenance": loaded.provenance,
            }))?
        );
    }
    Ok(())
}

fn validate_mapping_usage(kind: &str, mapping: Option<&PathBuf>) -> anyhow::Result<()> {
    if mapping.is_some()
        && !matches!(
            kind,
            "prometheus-query" | "prometheus-metrics" | "otlp-grpc"
        )
    {
        anyhow::bail!("--mapping is not supported for connector kind {kind}");
    }
    Ok(())
}

pub(crate) fn load_mapping(path: Option<PathBuf>) -> anyhow::Result<BTreeMap<String, String>> {
    if let Some(path) = path {
        load_prometheus_mapping_file(&path)
            .with_context(|| format!("failed to load mapping file: {}", path.display()))
    } else {
        Ok(default_prometheus_mapping())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_is_rejected_for_connectors_that_cannot_consume_it() {
        let mapping = PathBuf::from("mapping.json");
        for kind in ["http-json", "native-pcap", "system-counters"] {
            assert!(validate_mapping_usage(kind, Some(&mapping)).is_err());
        }
        for kind in ["prometheus-query", "prometheus-metrics", "otlp-grpc"] {
            validate_mapping_usage(kind, Some(&mapping)).expect("mapping-aware connector");
        }
    }
}
