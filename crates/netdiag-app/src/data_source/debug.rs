use super::SourceMode;
use std::fmt;

impl fmt::Debug for SourceMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { .. } => formatter
                .debug_struct("Unavailable")
                .field("reason", &"<omitted>")
                .finish(),
            Self::Simulated(scenario) => {
                formatter.debug_tuple("Simulated").field(scenario).finish()
            }
            Self::File(path) => formatter.debug_tuple("File").field(path).finish(),
            Self::Api(config, scope) => formatter
                .debug_struct("Api")
                .field("config", config)
                .field("authentication", &scope.as_ref().map(|_| "bearer"))
                .finish(),
            Self::LocalProbe(settings) => {
                formatter.debug_tuple("LocalProbe").field(settings).finish()
            }
            Self::WebsiteProbe(settings) => formatter
                .debug_struct("WebsiteProbe")
                .field("target_count", &settings.targets.len())
                .field("samples_per_target", &settings.samples_per_target)
                .finish(),
            Self::PrometheusQueryRange(settings, scope) => formatter
                .debug_struct("PrometheusQueryRange")
                .field("settings", settings)
                .field("authentication", &scope.as_ref().map(|_| "bearer"))
                .finish(),
            Self::PrometheusExposition(settings, scope) => formatter
                .debug_struct("PrometheusExposition")
                .field("settings", settings)
                .field("authentication", &scope.as_ref().map(|_| "bearer"))
                .finish(),
            Self::OtlpGrpcReceiver(settings) => formatter
                .debug_struct("OtlpGrpcReceiver")
                .field("bind_addr", &settings.bind_addr)
                .field("timeout_secs", &settings.timeout_secs)
                .field("mapping_entries", &settings.mapping.len())
                .finish(),
            Self::NativePcap(settings) => formatter
                .debug_struct("NativePcap")
                .field("source", &settings.source)
                .field("packet_limit", &settings.packet_limit)
                .field("timeout_secs", &settings.timeout_secs)
                .finish(),
            Self::SystemCounters(settings) => formatter
                .debug_struct("SystemCounters")
                .field("interface", &settings.interface)
                .field("interval_secs", &settings.interval_secs)
                .finish(),
        }
    }
}
