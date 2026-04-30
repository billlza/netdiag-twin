use crate::data_source::SimScenario;
use crate::secrets::SecretStore;
use anyhow::{Context, Result, bail};
use netdiag_core::connectors::default_prometheus_mapping;
use netdiag_core::models::TopologyModel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const APP_SUPPORT_DIR: &str = "NetDiag Twin";
pub const SETTINGS_FILE: &str = "settings.json";
pub const NETDIAG_API_URL_ENV: &str = "NETDIAG_API_URL";
pub const NETDIAG_API_TOKEN_ENV: &str = "NETDIAG_API_TOKEN";
pub const NETDIAG_API_TIMEOUT_SECONDS_ENV: &str = "NETDIAG_API_TIMEOUT_SECONDS";
pub const DEFAULT_API_TIMEOUT_SECS: u64 = 8;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AppSettings {
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
            language: LanguageSetting::default(),
            default_source: DefaultSource::default(),
            last_imported_trace: None,
            simulation_scenario: SimScenario::Congestion,
            api: ApiSettings::default(),
            data_connectors: DataConnectorsSettings::default(),
            artifacts_root: default_artifacts_root(),
            what_if: WhatIfSettings::default(),
            startup: StartupSettings::default(),
        }
    }
}

impl AppSettings {
    #[cfg(test)]
    pub fn load_from_path(path: impl Into<PathBuf>) -> Result<Self> {
        let store = SettingsStore::new(path.into());
        match store.load() {
            Ok(settings) => Ok(settings),
            Err(err) if err.to_string().contains("not valid JSON") => Ok(Self::default()),
            Err(err) => Err(err),
        }
    }

    pub fn api_config(&self, secrets: &dyn SecretStore) -> Result<ApiConfig> {
        self.api_config_with_env(secrets, env::vars())
    }

    pub fn api_config_with_env<I, K, V>(
        &self,
        secrets: &dyn SecretStore,
        env_vars: I,
    ) -> Result<ApiConfig>
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

        let bearer_token = secrets
            .get_live_api_token()?
            .and_then(non_empty_owned)
            .or_else(|| {
                env_vars
                    .get(NETDIAG_API_TOKEN_ENV)
                    .and_then(|token| non_empty(token).map(str::to_owned))
            });

        let timeout_secs = if self.api.timeout_secs > 0 {
            self.api.timeout_secs
        } else {
            env_vars
                .get(NETDIAG_API_TIMEOUT_SECONDS_ENV)
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|seconds| *seconds > 0)
                .unwrap_or(DEFAULT_API_TIMEOUT_SECS)
        };

        Ok(ApiConfig {
            endpoint,
            bearer_token,
            timeout: Duration::from_secs(timeout_secs),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
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

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorKind {
    LocalProbe,
    #[default]
    WebsiteProbe,
    HttpJson,
    PrometheusQueryRange,
    PrometheusExposition,
}

impl ConnectorKind {
    pub const ALL: [ConnectorKind; 5] = [
        ConnectorKind::LocalProbe,
        ConnectorKind::WebsiteProbe,
        ConnectorKind::HttpJson,
        ConnectorKind::PrometheusQueryRange,
        ConnectorKind::PrometheusExposition,
    ];
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
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
        }
    }
}

impl DataConnectorsSettings {
    pub fn active_profile(&self) -> Option<&SourceProfile> {
        self.profiles
            .iter()
            .find(|profile| profile.id == self.active_profile_id)
            .or_else(|| self.profiles.first())
    }

    pub fn active_profile_mut(&mut self) -> Option<&mut SourceProfile> {
        let index = self
            .profiles
            .iter()
            .position(|profile| profile.id == self.active_profile_id)
            .unwrap_or(0);
        self.profiles.get_mut(index)
    }

    pub fn ensure_profiles(&mut self) {
        if self.profiles.is_empty() {
            self.profiles = default_source_profiles();
        }
        if !self
            .profiles
            .iter()
            .any(|profile| profile.id == self.active_profile_id)
        {
            self.active_profile_id = self
                .profiles
                .first()
                .map(|profile| profile.id.clone())
                .unwrap_or_else(default_active_profile_id);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SourceProfile {
    pub id: String,
    pub name: String,
    pub kind: ConnectorKind,
    pub local_probe: LocalProbeSettings,
    pub website_probe: WebsiteProbeSettings,
    pub http_json: ApiSettings,
    pub prometheus_query: PrometheusQuerySettings,
    pub prometheus_exposition: PrometheusExpositionSettings,
}

impl Default for SourceProfile {
    fn default() -> Self {
        Self {
            id: "website_probe".to_string(),
            name: "Website probe".to_string(),
            kind: ConnectorKind::WebsiteProbe,
            local_probe: LocalProbeSettings::default(),
            website_probe: WebsiteProbeSettings::default(),
            http_json: ApiSettings::default(),
            prometheus_query: PrometheusQuerySettings::default(),
            prometheus_exposition: PrometheusExpositionSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
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

pub type BTreeMapString = std::collections::BTreeMap<String, String>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
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
#[serde(default)]
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
    Reports,
    Settings,
}

impl StartupTab {
    pub const ALL: [StartupTab; 8] = [
        StartupTab::Overview,
        StartupTab::Telemetry,
        StartupTab::Diagnosis,
        StartupTab::RuleMl,
        StartupTab::DigitalTwin,
        StartupTab::WhatIf,
        StartupTab::Reports,
        StartupTab::Settings,
    ];
}

#[derive(Clone, PartialEq, Eq)]
pub struct ApiConfig {
    pub endpoint: String,
    pub timeout: Duration,
    bearer_token: Option<String>,
}

impl ApiConfig {
    pub fn bearer_token(&self) -> Option<&str> {
        self.bearer_token.as_deref()
    }

    #[cfg(test)]
    pub fn timeout_secs(&self) -> u64 {
        self.timeout.as_secs()
    }
}

impl fmt::Debug for ApiConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiConfig")
            .field("endpoint", &self.endpoint)
            .field("timeout", &self.timeout)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct SettingsStore {
    path: PathBuf,
}

impl SettingsStore {
    pub fn default_path() -> PathBuf {
        app_support_dir().join(SETTINGS_FILE)
    }

    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load_or_default(&self) -> (AppSettings, Option<String>) {
        match self.load() {
            Ok(settings) => (settings, None),
            Err(err) => (AppSettings::default(), Some(err.to_string())),
        }
    }

    pub fn load(&self) -> Result<AppSettings> {
        match fs::read_to_string(&self.path) {
            Ok(raw) => {
                let mut settings: AppSettings = serde_json::from_str(&raw).with_context(|| {
                    format!("settings file is not valid JSON: {}", self.path.display())
                })?;
                settings.data_connectors.ensure_profiles();
                Ok(settings)
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(AppSettings::default()),
            Err(err) => Err(err)
                .with_context(|| format!("failed to read settings file: {}", self.path.display())),
        }
    }

    pub fn save(&self, settings: &AppSettings) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create settings directory: {}", parent.display())
            })?;
        }
        let raw = serde_json::to_vec_pretty(settings).context("serialize NetDiag settings")?;
        let tmp_path = temp_path_for(&self.path);
        fs::write(&tmp_path, raw).with_context(|| {
            format!("failed to write temporary settings: {}", tmp_path.display())
        })?;
        fs::rename(&tmp_path, &self.path)
            .or_else(|err| replace_settings_file(&tmp_path, &self.path, err))
            .with_context(|| format!("failed to replace settings file: {}", self.path.display()))
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

fn temp_path_for(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(SETTINGS_FILE)
        .to_owned();
    name.push_str(".tmp");
    path.with_file_name(name)
}

fn replace_settings_file(tmp_path: &Path, path: &Path, rename_err: io::Error) -> io::Result<()> {
    if rename_err.kind() != ErrorKind::AlreadyExists {
        return Err(rename_err);
    }
    fs::remove_file(path)?;
    fs::rename(tmp_path, path)
}

fn first_non_empty<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Option<&'a str> {
    values.into_iter().flatten().find_map(non_empty)
}

fn non_empty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn non_empty_owned(value: String) -> Option<String> {
    non_empty(&value).map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{MemorySecretStore, SecretStore};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn defaults_are_product_safe() {
        let settings = AppSettings::default();
        assert_eq!(settings.language, LanguageSetting::Zh);
        assert_eq!(settings.default_source, DefaultSource::Simulation);
        assert_eq!(settings.last_imported_trace, None);
        assert_eq!(settings.simulation_scenario, SimScenario::Congestion);
        assert_eq!(settings.api.endpoint, "");
        assert_eq!(settings.api.timeout_secs, DEFAULT_API_TIMEOUT_SECS);
        assert_eq!(
            settings.data_connectors.default_connector,
            ConnectorKind::WebsiteProbe
        );
        assert_eq!(settings.data_connectors.website_probe.targets.len(), 3);
        assert!(settings.artifacts_root.ends_with("artifacts"));
        assert_eq!(settings.what_if.topology, "line");
        assert_eq!(settings.what_if.action, "reroute_path_b");
        assert_eq!(settings.startup.default_tab, StartupTab::Overview);
        assert!(settings.startup.auto_run_diagnosis);
        assert!(default_settings_path().ends_with("NetDiag Twin/settings.json"));
    }

    #[test]
    fn missing_nested_fields_use_product_defaults() {
        let settings: AppSettings = serde_json::from_str(r#"{"api":{},"what_if":{},"startup":{}}"#)
            .expect("partial settings");
        assert_eq!(settings.api.timeout_secs, DEFAULT_API_TIMEOUT_SECS);
        assert_eq!(
            settings.data_connectors.default_connector,
            ConnectorKind::WebsiteProbe
        );
        assert_eq!(settings.what_if.topology, "line");
        assert_eq!(settings.what_if.action, "reroute_path_b");
        assert_eq!(settings.startup.default_tab, StartupTab::Overview);
        assert!(settings.startup.auto_run_diagnosis);
        assert!(settings.artifacts_root.ends_with("artifacts"));
    }

    #[test]
    fn save_and_load_round_trips_without_token() {
        let path = temp_settings_path();
        let store = SettingsStore::new(path.clone());
        let settings = AppSettings {
            language: LanguageSetting::En,
            default_source: DefaultSource::LiveApi,
            last_imported_trace: Some(PathBuf::from("/tmp/trace.json")),
            simulation_scenario: SimScenario::DnsFailure,
            api: ApiSettings {
                endpoint: "https://example.invalid/trace".to_string(),
                timeout_secs: 12,
            },
            data_connectors: DataConnectorsSettings {
                default_connector: ConnectorKind::HttpJson,
                ..DataConnectorsSettings::default()
            },
            artifacts_root: PathBuf::from("/tmp/netdiag-artifacts"),
            what_if: WhatIfSettings {
                topology: "mesh".to_string(),
                action: "isolate_node_c".to_string(),
                custom_topology: None,
            },
            startup: StartupSettings {
                default_tab: StartupTab::Settings,
                auto_run_diagnosis: false,
            },
        };

        store.save(&settings).expect("save settings");
        let raw = fs::read_to_string(&path).expect("settings json");
        assert!(!raw.contains("secret-token"));
        let loaded = store.load().expect("load settings");
        assert_eq!(loaded, settings);
        cleanup_temp_path(path);
    }

    #[test]
    fn corrupt_json_falls_back_to_defaults() {
        let path = temp_settings_path();
        fs::create_dir_all(path.parent().unwrap()).expect("settings dir");
        fs::write(&path, "{not json").expect("write corrupt settings");
        let store = SettingsStore::new(path.clone());

        let (settings, warning) = store.load_or_default();
        assert_eq!(settings, AppSettings::default());
        assert!(warning.expect("warning").contains("not valid JSON"));
        cleanup_temp_path(path);
    }

    #[test]
    fn app_settings_load_from_path_uses_corrupt_json_fallback() {
        let path = temp_settings_path();
        fs::create_dir_all(path.parent().unwrap()).expect("settings dir");
        fs::write(&path, "{not json").expect("write corrupt settings");

        let settings = AppSettings::load_from_path(path.clone()).expect("fallback settings");
        assert_eq!(settings, AppSettings::default());
        cleanup_temp_path(path);
    }

    #[test]
    fn api_config_uses_settings_and_secret_before_env_fallbacks() {
        let settings = AppSettings {
            api: ApiSettings {
                endpoint: "https://settings.example.test/traces".to_string(),
                timeout_secs: 14,
            },
            ..AppSettings::default()
        };
        let secrets = MemorySecretStore::with_token("stored-secret");

        let config = settings
            .api_config_with_env(
                &secrets,
                [
                    (NETDIAG_API_URL_ENV, "https://env.example.test/traces"),
                    (NETDIAG_API_TOKEN_ENV, "env-secret"),
                    (NETDIAG_API_TIMEOUT_SECONDS_ENV, "22"),
                ],
            )
            .expect("api config");

        assert_eq!(config.endpoint, "https://settings.example.test/traces");
        assert_eq!(config.bearer_token(), Some("stored-secret"));
        assert_eq!(config.timeout_secs(), 14);
        assert!(!format!("{config:?}").contains("stored-secret"));
    }

    #[test]
    fn api_config_falls_back_to_env_endpoint_token_and_timeout() {
        let settings = AppSettings {
            api: ApiSettings {
                endpoint: String::new(),
                timeout_secs: 0,
            },
            ..AppSettings::default()
        };
        let secrets = MemorySecretStore::new();

        let config = settings
            .api_config_with_env(
                &secrets,
                [
                    (NETDIAG_API_URL_ENV, " https://env.example.test/traces "),
                    (NETDIAG_API_TOKEN_ENV, " env-secret "),
                    (NETDIAG_API_TIMEOUT_SECONDS_ENV, "23"),
                ],
            )
            .expect("api config");

        assert_eq!(config.endpoint, "https://env.example.test/traces");
        assert_eq!(config.bearer_token(), Some("env-secret"));
        assert_eq!(config.timeout_secs(), 23);
    }

    #[test]
    fn api_config_requires_endpoint_after_fallbacks() {
        let settings = AppSettings::default();
        let secrets = MemorySecretStore::new();

        let err = settings
            .api_config_with_env(&secrets, std::iter::empty::<(&str, &str)>())
            .expect_err("missing endpoint");
        assert!(err.to_string().contains(NETDIAG_API_URL_ENV));
    }

    #[test]
    fn memory_secret_store_supports_api_config_without_echoing_token() {
        let settings = AppSettings {
            api: ApiSettings {
                endpoint: "https://settings.example.test/traces".to_string(),
                timeout_secs: DEFAULT_API_TIMEOUT_SECS,
            },
            ..AppSettings::default()
        };
        let secrets = MemorySecretStore::new();

        secrets
            .set_live_api_token("secret-token")
            .expect("set token");
        let config = settings
            .api_config_with_env(&secrets, std::iter::empty::<(&str, &str)>())
            .expect("api config");
        assert_eq!(config.bearer_token(), Some("secret-token"));
        assert!(!format!("{config:?}").contains("secret-token"));
    }

    fn temp_settings_path() -> PathBuf {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        env::temp_dir()
            .join(format!(
                "netdiag-settings-test-{}-{nanos}-{id}",
                std::process::id()
            ))
            .join("settings.json")
    }

    fn cleanup_temp_path(path: PathBuf) {
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }
}
