use crate::data_source::SimScenario;
use anyhow::{Context, Result, bail};
use netdiag_core::connectors::{
    LocalProbeConfig, WebsiteProbeConfig, default_prometheus_mapping,
    validate_http_connector_bearer_endpoint, validate_prometheus_query_window,
};
use netdiag_core::models::TopologyModel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod bearer_credentials;
mod credential_cleanup;
mod debug;
mod environment;
mod otlp;
mod store;
mod validation;
pub(crate) use bearer_credentials::LEGACY_LIVE_API_SCOPE_ID;
pub use bearer_credentials::{
    BearerCredentialBinding, BearerCredentialOwner, BearerCredentialState,
};
pub use credential_cleanup::CredentialCleanupJournal;
use environment::{first_non_empty, read_api_environment};
pub use otlp::OtlpGrpcSettings;
pub use store::{SettingsLoadOutcome, SettingsLoadState, SettingsStore, SettingsVerificationError};
use validation::validate_settings;

pub const APP_SUPPORT_DIR: &str = "NetDiag Twin";
pub const SETTINGS_FILE: &str = "settings.json";
pub const NETDIAG_API_URL_ENV: &str = "NETDIAG_API_URL";
pub const NETDIAG_API_TIMEOUT_SECONDS_ENV: &str = "NETDIAG_API_TIMEOUT_SECONDS";
pub const DEFAULT_API_TIMEOUT_SECS: u64 = 8;
const MAX_SETTINGS_FILE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AppSettings {
    #[serde(default)]
    #[doc(hidden)]
    pub settings_generation: u64,
    #[serde(default)]
    pub language: LanguageSetting,
    #[serde(default)]
    pub default_source: DefaultSource,
    #[serde(default)]
    pub last_imported_trace: Option<PathBuf>,
    #[serde(default)]
    pub simulation_scenario: SimScenario,
    #[serde(default)]
    pub api: ApiSettings,
    #[serde(default)]
    pub data_connectors: DataConnectorsSettings,
    #[serde(default)]
    pub bearer_credentials: Vec<BearerCredentialBinding>,
    #[serde(default)]
    pub credential_cleanup: CredentialCleanupJournal,
    #[serde(default = "default_artifacts_root")]
    pub artifacts_root: PathBuf,
    #[serde(default)]
    pub what_if: WhatIfSettings,
    #[serde(default)]
    pub startup: StartupSettings,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            settings_generation: 0,
            language: LanguageSetting::default(),
            default_source: DefaultSource::default(),
            last_imported_trace: None,
            simulation_scenario: SimScenario::Congestion,
            api: ApiSettings::default(),
            data_connectors: DataConnectorsSettings::default(),
            bearer_credentials: Vec::new(),
            credential_cleanup: CredentialCleanupJournal::default(),
            artifacts_root: default_artifacts_root(),
            what_if: WhatIfSettings::default(),
            startup: StartupSettings::default(),
        }
    }
}

impl AppSettings {
    #[cfg(test)]
    pub fn load_from_path(path: impl Into<PathBuf>) -> Result<Self> {
        SettingsStore::new(path.into()).load()
    }

    pub fn api_config(&self) -> Result<ApiConfig> {
        self.api_config_with_env(read_api_environment()?)
    }

    pub fn api_config_with_env<I, K, V>(&self, env_vars: I) -> Result<ApiConfig>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: Into<String>,
    {
        let env_vars = env_vars
            .into_iter()
            .map(|(key, value)| (key.as_ref().to_owned(), value.into()))
            .collect::<HashMap<_, _>>();

        let endpoint = first_non_empty([
            Some(self.api.endpoint.as_str()),
            env_vars.get(NETDIAG_API_URL_ENV).map(String::as_str),
        ])
        .map(str::to_owned)
        .unwrap_or_default();
        if endpoint.is_empty() {
            bail!("configure an API endpoint in settings or {NETDIAG_API_URL_ENV}");
        }

        validate_http_connector_bearer_endpoint(&endpoint)
            .map_err(|error| anyhow::anyhow!("API endpoint {error}"))?;

        let timeout_secs = if self.api.timeout_secs > 0 {
            validate_api_timeout(self.api.timeout_secs)?
        } else if let Some(value) = env_vars.get(NETDIAG_API_TIMEOUT_SECONDS_ENV) {
            let seconds = value.trim().parse::<u64>().with_context(|| {
                format!("{NETDIAG_API_TIMEOUT_SECONDS_ENV} must be an integer between 1 and 120")
            })?;
            validate_api_timeout(seconds)?
        } else {
            DEFAULT_API_TIMEOUT_SECS
        };

        Ok(ApiConfig {
            endpoint,
            timeout: Duration::from_secs(timeout_secs),
        })
    }
}

fn validate_api_timeout(seconds: u64) -> Result<u64> {
    if (1..=120).contains(&seconds) {
        Ok(seconds)
    } else {
        bail!("API timeout must be between 1 and 120 seconds")
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LanguageSetting {
    #[default]
    Zh,
    En,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DefaultSource {
    #[default]
    Simulation,
    LastImportedFile,
    LiveApi,
}

impl DefaultSource {
    pub const ALL: [DefaultSource; 3] = [
        DefaultSource::Simulation,
        DefaultSource::LastImportedFile,
        DefaultSource::LiveApi,
    ];
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ApiSettings {
    #[serde(default)]
    pub endpoint: String,
    #[serde(default = "default_api_timeout_secs")]
    pub timeout_secs: u64,
}

impl Default for ApiSettings {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            timeout_secs: DEFAULT_API_TIMEOUT_SECS,
        }
    }
}

impl ApiSettings {
    pub fn validated_timeout_secs(&self) -> Result<u64> {
        validate_api_timeout(self.timeout_secs)
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorKind {
    LocalProbe,
    #[default]
    WebsiteProbe,
    HttpJson,
    PrometheusQueryRange,
    PrometheusExposition,
    OtlpGrpcReceiver,
    NativePcap,
    SystemCounters,
}

impl ConnectorKind {
    pub const ALL: [ConnectorKind; 8] = [
        ConnectorKind::LocalProbe,
        ConnectorKind::WebsiteProbe,
        ConnectorKind::HttpJson,
        ConnectorKind::PrometheusQueryRange,
        ConnectorKind::PrometheusExposition,
        ConnectorKind::OtlpGrpcReceiver,
        ConnectorKind::NativePcap,
        ConnectorKind::SystemCounters,
    ];

    pub fn supports_bearer_authentication(self) -> bool {
        matches!(
            self,
            Self::HttpJson | Self::PrometheusQueryRange | Self::PrometheusExposition
        )
    }

    pub fn stable_name(self) -> &'static str {
        match self {
            Self::LocalProbe => "local-probe",
            Self::WebsiteProbe => "website-probe",
            Self::HttpJson => "http-json",
            Self::PrometheusQueryRange => "prometheus-query",
            Self::PrometheusExposition => "prometheus-metrics",
            Self::OtlpGrpcReceiver => "otlp-grpc",
            Self::NativePcap => "native-pcap",
            Self::SystemCounters => "system-counters",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorAuthentication {
    #[default]
    None,
    BearerToken,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct LocalProbeSettings {
    #[serde(default = "default_probe_samples")]
    pub samples: usize,
}

impl Default for LocalProbeSettings {
    fn default() -> Self {
        Self {
            samples: default_probe_samples(),
        }
    }
}

impl LocalProbeSettings {
    pub fn validate(&self) -> Result<()> {
        LocalProbeConfig {
            samples: self.samples,
        }
        .validate()
        .map_err(anyhow::Error::from)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct WebsiteProbeSettings {
    #[serde(default = "default_website_probe_targets")]
    pub targets: Vec<String>,
    #[serde(default = "default_probe_samples")]
    pub samples_per_target: usize,
}

impl Default for WebsiteProbeSettings {
    fn default() -> Self {
        Self {
            targets: default_website_probe_targets(),
            samples_per_target: default_probe_samples(),
        }
    }
}

impl WebsiteProbeSettings {
    pub fn validate(&self) -> Result<()> {
        WebsiteProbeConfig {
            targets: self.targets.clone(),
            samples_per_target: self.samples_per_target,
        }
        .validate()
        .map_err(anyhow::Error::from)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct DataConnectorsSettings {
    #[serde(default)]
    pub default_connector: ConnectorKind,
    #[serde(default = "default_active_profile_id")]
    pub active_profile_id: String,
    #[serde(default = "default_source_profiles")]
    pub profiles: Vec<SourceProfile>,
    #[serde(default)]
    pub local_probe: LocalProbeSettings,
    #[serde(default)]
    pub website_probe: WebsiteProbeSettings,
    #[serde(default)]
    pub prometheus_query: PrometheusQuerySettings,
    #[serde(default)]
    pub prometheus_exposition: PrometheusExpositionSettings,
    #[serde(default)]
    pub otlp_grpc: OtlpGrpcSettings,
    #[serde(default)]
    pub native_pcap: NativePcapSettings,
    #[serde(default)]
    pub system_counters: SystemCountersSettings,
}

impl Default for DataConnectorsSettings {
    fn default() -> Self {
        Self {
            default_connector: ConnectorKind::WebsiteProbe,
            active_profile_id: default_active_profile_id(),
            profiles: default_source_profiles(),
            local_probe: LocalProbeSettings::default(),
            website_probe: WebsiteProbeSettings::default(),
            prometheus_query: PrometheusQuerySettings::default(),
            prometheus_exposition: PrometheusExpositionSettings::default(),
            otlp_grpc: OtlpGrpcSettings::default(),
            native_pcap: NativePcapSettings::default(),
            system_counters: SystemCountersSettings::default(),
        }
    }
}

impl DataConnectorsSettings {
    pub fn active_profile(&self) -> Option<&SourceProfile> {
        self.profiles
            .iter()
            .find(|profile| profile.id == self.active_profile_id)
    }

    pub fn active_profile_mut(&mut self) -> Option<&mut SourceProfile> {
        self.profiles
            .iter_mut()
            .find(|profile| profile.id == self.active_profile_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SourceProfile {
    pub id: String,
    pub name: String,
    pub kind: ConnectorKind,
    pub authentication: ConnectorAuthentication,
    pub local_probe: LocalProbeSettings,
    pub website_probe: WebsiteProbeSettings,
    pub http_json: ApiSettings,
    pub prometheus_query: PrometheusQuerySettings,
    pub prometheus_exposition: PrometheusExpositionSettings,
    pub otlp_grpc: OtlpGrpcSettings,
    pub native_pcap: NativePcapSettings,
    pub system_counters: SystemCountersSettings,
}

impl Default for SourceProfile {
    fn default() -> Self {
        Self {
            id: "website_probe".to_string(),
            name: "Website probe".to_string(),
            kind: ConnectorKind::WebsiteProbe,
            authentication: ConnectorAuthentication::None,
            local_probe: LocalProbeSettings::default(),
            website_probe: WebsiteProbeSettings::default(),
            http_json: ApiSettings::default(),
            prometheus_query: PrometheusQuerySettings::default(),
            prometheus_exposition: PrometheusExpositionSettings::default(),
            otlp_grpc: OtlpGrpcSettings::default(),
            native_pcap: NativePcapSettings::default(),
            system_counters: SystemCountersSettings::default(),
        }
    }
}

impl SourceProfile {
    pub fn http_endpoint(&self) -> Option<&str> {
        match self.kind {
            ConnectorKind::HttpJson => Some(&self.http_json.endpoint),
            ConnectorKind::PrometheusQueryRange => Some(&self.prometheus_query.base_url),
            ConnectorKind::PrometheusExposition => Some(&self.prometheus_exposition.endpoint),
            ConnectorKind::LocalProbe
            | ConnectorKind::WebsiteProbe
            | ConnectorKind::OtlpGrpcReceiver
            | ConnectorKind::NativePcap
            | ConnectorKind::SystemCounters => None,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct PrometheusQuerySettings {
    pub base_url: String,
    pub lookback_seconds: i64,
    pub step_seconds: u64,
    pub mapping: BTreeMapString,
}

impl Default for PrometheusQuerySettings {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:9090".to_string(),
            lookback_seconds: 300,
            step_seconds: 15,
            mapping: default_prometheus_mapping(),
        }
    }
}

impl PrometheusQuerySettings {
    pub fn validate(&self) -> Result<()> {
        if self.lookback_seconds < 10 {
            bail!("Prometheus lookback_seconds must be between 10 and 86400");
        }
        validate_prometheus_query_window(self.lookback_seconds, self.step_seconds)
            .map_err(anyhow::Error::from)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct PrometheusExpositionSettings {
    pub endpoint: String,
    pub mapping: BTreeMapString,
}

impl Default for PrometheusExpositionSettings {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:9100/metrics".to_string(),
            mapping: default_prometheus_mapping(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct NativePcapSettings {
    pub source: String,
    pub packet_limit: usize,
    pub timeout_secs: u64,
}

impl Default for NativePcapSettings {
    fn default() -> Self {
        Self {
            source: "lo0".to_string(),
            packet_limit: 256,
            timeout_secs: 8,
        }
    }
}

impl NativePcapSettings {
    pub fn validate(&self) -> Result<()> {
        validate_api_timeout(self.timeout_secs)?;
        if !(1..=netdiag_core::MAX_PCAP_PACKET_LIMIT).contains(&self.packet_limit) {
            bail!(
                "native pcap packet_limit must be between 1 and {}",
                netdiag_core::MAX_PCAP_PACKET_LIMIT
            );
        }
        if self.source.trim().is_empty() {
            bail!("native pcap source is empty");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SystemCountersSettings {
    pub interface: String,
    pub interval_secs: u64,
}

impl Default for SystemCountersSettings {
    fn default() -> Self {
        Self {
            interface: "all".to_string(),
            interval_secs: 1,
        }
    }
}

impl SystemCountersSettings {
    pub fn validate(&self) -> Result<()> {
        if (1..=10).contains(&self.interval_secs) {
            Ok(())
        } else {
            bail!("system counters interval_secs must be between 1 and 10")
        }
    }
}

pub type BTreeMapString = std::collections::BTreeMap<String, String>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WhatIfSettings {
    #[serde(default = "default_what_if_topology")]
    pub topology: String,
    #[serde(default = "default_what_if_action")]
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_topology: Option<TopologyModel>,
}

impl Default for WhatIfSettings {
    fn default() -> Self {
        Self {
            topology: default_what_if_topology(),
            action: default_what_if_action(),
            custom_topology: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct StartupSettings {
    #[serde(default)]
    pub default_tab: StartupTab,
    #[serde(default = "default_auto_run_diagnosis")]
    pub auto_run_diagnosis: bool,
}

impl Default for StartupSettings {
    fn default() -> Self {
        Self {
            default_tab: StartupTab::Overview,
            auto_run_diagnosis: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StartupTab {
    #[default]
    Overview,
    Telemetry,
    Diagnosis,
    RuleMl,
    DigitalTwin,
    WhatIf,
    Lab,
    Reports,
    Settings,
}

impl StartupTab {
    pub const ALL: [StartupTab; 9] = [
        StartupTab::Overview,
        StartupTab::Telemetry,
        StartupTab::Diagnosis,
        StartupTab::RuleMl,
        StartupTab::DigitalTwin,
        StartupTab::WhatIf,
        StartupTab::Lab,
        StartupTab::Reports,
        StartupTab::Settings,
    ];
}

#[derive(Clone, PartialEq, Eq)]
pub struct ApiConfig {
    pub endpoint: String,
    pub timeout: Duration,
}

impl ApiConfig {
    pub fn new(endpoint: String, timeout: Duration) -> Self {
        Self { endpoint, timeout }
    }

    #[cfg(test)]
    pub fn timeout_secs(&self) -> u64 {
        self.timeout.as_secs()
    }
}

#[cfg(test)]
pub fn default_settings_path() -> PathBuf {
    SettingsStore::default_path()
}

pub fn default_artifacts_root() -> PathBuf {
    if is_running_from_app_bundle() {
        return app_support_artifacts_root();
    }
    if let Ok(cwd) = env::current_dir()
        && let Some(root) = find_workspace_root(&cwd)
    {
        return root.join("artifacts");
    }
    if let Ok(exe) = env::current_exe()
        && let Some(root) = exe.parent().and_then(find_workspace_root)
    {
        return root.join("artifacts");
    }
    app_support_artifacts_root()
}

pub fn normalize_bundle_settings(settings: &mut AppSettings) -> bool {
    if !is_running_from_app_bundle()
        || !artifacts_root_points_to_workspace(&settings.artifacts_root)
    {
        return false;
    }
    settings.artifacts_root = app_support_artifacts_root();
    true
}

fn app_support_artifacts_root() -> PathBuf {
    app_support_dir().join("artifacts")
}

fn app_support_dir() -> PathBuf {
    env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .map(|home| {
            home.join("Library")
                .join("Application Support")
                .join(APP_SUPPORT_DIR)
        })
        .unwrap_or_else(|| PathBuf::from(".").join(APP_SUPPORT_DIR))
}

fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    start.ancestors().find_map(|ancestor| {
        let cargo_toml = ancestor.join("Cargo.toml");
        let crates_dir = ancestor.join("crates");
        if cargo_toml.is_file() && crates_dir.is_dir() {
            Some(ancestor.to_path_buf())
        } else {
            None
        }
    })
}

fn artifacts_root_points_to_workspace(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "artifacts")
        && path.parent().and_then(find_workspace_root).is_some()
}

fn is_running_from_app_bundle() -> bool {
    env::current_exe().ok().is_some_and(|exe| {
        exe.ancestors().any(|ancestor| {
            ancestor
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
        })
    })
}

fn default_api_timeout_secs() -> u64 {
    DEFAULT_API_TIMEOUT_SECS
}

fn default_probe_samples() -> usize {
    6
}

fn default_website_probe_targets() -> Vec<String> {
    vec![
        "https://www.cloudflare.com/".to_string(),
        "https://example.com/".to_string(),
        "1.1.1.1:443".to_string(),
    ]
}

fn default_active_profile_id() -> String {
    "website_probe".to_string()
}

fn default_source_profiles() -> Vec<SourceProfile> {
    vec![
        SourceProfile {
            id: "website_probe".to_string(),
            name: "Website probe".to_string(),
            kind: ConnectorKind::WebsiteProbe,
            ..SourceProfile::default()
        },
        SourceProfile {
            id: "local_probe".to_string(),
            name: "Local probe".to_string(),
            kind: ConnectorKind::LocalProbe,
            ..SourceProfile::default()
        },
        SourceProfile {
            id: "http_json_lab".to_string(),
            name: "HTTP/JSON lab adapter".to_string(),
            kind: ConnectorKind::HttpJson,
            ..SourceProfile::default()
        },
        SourceProfile {
            id: "prometheus_query".to_string(),
            name: "Prometheus query_range".to_string(),
            kind: ConnectorKind::PrometheusQueryRange,
            ..SourceProfile::default()
        },
        SourceProfile {
            id: "prometheus_metrics".to_string(),
            name: "Prometheus /metrics".to_string(),
            kind: ConnectorKind::PrometheusExposition,
            ..SourceProfile::default()
        },
        SourceProfile {
            id: "otlp_grpc".to_string(),
            name: "OTLP gRPC receiver".to_string(),
            kind: ConnectorKind::OtlpGrpcReceiver,
            ..SourceProfile::default()
        },
        SourceProfile {
            id: "native_pcap".to_string(),
            name: "Native pcap".to_string(),
            kind: ConnectorKind::NativePcap,
            ..SourceProfile::default()
        },
        SourceProfile {
            id: "system_counters".to_string(),
            name: "System counters".to_string(),
            kind: ConnectorKind::SystemCounters,
            ..SourceProfile::default()
        },
    ]
}

fn default_what_if_topology() -> String {
    "line".to_string()
}

fn default_what_if_action() -> String {
    "reroute_path_b".to_string()
}

fn default_auto_run_diagnosis() -> bool {
    true
}

#[cfg(test)]
mod tests;
