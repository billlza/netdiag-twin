use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, FontId, Layout, Margin, Mesh, Pos2, Rect, RichText,
    Sense, Stroke, UiBuilder, Vec2,
};
use egui_remixicon::icons;
use netdiag_app::data_source::{
    FlowSummary, SimScenario, SourceDescriptor, SourceMode, SourceSnapshot, native_pcap_source,
};
use netdiag_app::layout::{
    HEADER_ACTION_HEIGHT, HEADER_ACTION_WIDTH, OVERVIEW_MIN_CONTENT_HEIGHT, SUMMARY_CARD_HEIGHT,
    overview_content_height, summary_card_rects,
};
#[cfg(target_os = "macos")]
use netdiag_app::secrets::KeychainSecretStore;
#[cfg(not(target_os = "macos"))]
use netdiag_app::secrets::MemorySecretStore;
use netdiag_app::secrets::SecretStore;
use netdiag_app::settings::{
    self, AppSettings, ConnectorKind, DefaultSource, LanguageSetting, SettingsStore, StartupTab,
};
use netdiag_app::trend::{LatencyMetric, TrendRange, latency_trend_points};
use netdiag_app::updater::{UpdateCheckOutcome, sparkle_check_for_updates, sparkle_status};
use netdiag_app::view_model::{DashboardViewModel, format_bytes};
use netdiag_core::connectors::{
    CaptureControl, CaptureProgress, ConnectorLoadResult, NativePcapConfig, OtlpGrpcReceiverConfig,
    OtlpReceiverSession, SystemCountersConfig, load_native_pcap_with_control,
    load_system_counters_with_control,
};
use netdiag_core::ml::load_or_train_model;
use netdiag_core::models::{
    FaultLabel, HilReviewSummary, HilState, MetricProvenance, MetricQuality, RunManifest,
    TopologyModel,
};
use netdiag_core::storage::{compare_runs, list_run_history, review_recommendation};
use netdiag_core::twin::{action_names, topology_model, topology_names, validate_topology_model};
use netdiag_core::{PipelineResult, WhatIfRequest, diagnose_ingest_with_whatif};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::Duration;
use std::{fs, process::Command, thread};

const BLUE: Color32 = Color32::from_rgb(37, 88, 225);
const PURPLE: Color32 = Color32::from_rgb(122, 56, 230);
const GREEN: Color32 = Color32::from_rgb(28, 160, 72);
const ORANGE: Color32 = Color32::from_rgb(238, 139, 24);
const RED: Color32 = Color32::from_rgb(232, 58, 53);
const INK: Color32 = Color32::from_rgb(18, 28, 48);
const MUTED: Color32 = Color32::from_rgb(78, 88, 118);

#[cfg(target_os = "macos")]
mod native_menu;

#[cfg(target_os = "macos")]
use native_menu::{NativeMenu, NativeMenuCommand};

fn main() -> eframe::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1440.0, 900.0])
        .with_min_inner_size([1120.0, 760.0])
        .with_position([320.0, 80.0])
        .with_visible(true)
        .with_active(true)
        .with_maximized(false)
        .with_app_id("com.netdiag.twin");
    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!(
        "../assets/NetDiagTwin.iconset/icon_512x512.png"
    )) {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        centered: true,
        persist_window: false,
        ..Default::default()
    };
    eframe::run_native(
        "NetDiag Twin",
        options,
        Box::new(|cc| Ok(Box::new(NetDiagApp::new(cc)))),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Telemetry,
    Diagnosis,
    RuleMl,
    DigitalTwin,
    WhatIf,
    Reports,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    Zh,
    En,
}

impl Language {
    fn toggle(self) -> Self {
        match self {
            Language::Zh => Language::En,
            Language::En => Language::Zh,
        }
    }

    fn switch_label(self) -> &'static str {
        match self {
            Language::Zh => "EN",
            Language::En => "中文",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Text {
    Subtitle,
    ImportTrace,
    Simulate,
    LiveApi,
    NewAnalysis,
    CurrentTrace,
    Duration,
    Protocol,
    Flows,
    Packets,
    KeyMetrics,
    LatencyChart,
    DiagnosisSummary,
    RuleMlComparison,
    TopTalkers,
    SystemStatus,
    DataSource,
    LastUpdate,
    AnalysisId,
    NoMetrics,
    NoDiagnosis,
    NoComparison,
    NoFlowMetadata,
    NoSource,
    ImportTraceToBegin,
    AnalysisLoading,
    AnalysisAlreadyRunning,
    Running,
    ViewDetails,
    ViewComparison,
    Confidence,
    Agreement,
    ReviewNeeded,
    SettingsLanguage,
    Artifacts,
    CurrentRun,
    RunHistory,
    LatestComparison,
    ReviewState,
    RootCauses,
    ModelType,
    SyntheticModel,
    Recommendations,
    Evidence,
    WhatIfResult,
    MlTopPredictions,
    FeatureContribution,
    ModelStatus,
    SyntheticFallback,
    RuleBased,
    MlAssisted,
    AddApi,
    ConfigureLiveApiFirst,
    Metric,
    Baseline,
    Proposed,
    NoWhatIf,
    NoArtifacts,
    Topology,
    Action,
    Risk,
    Approval,
    HilReview,
    HilStatus,
    Accept,
    Reject,
    MarkUncertain,
    RequireRerun,
    ReviewNotes,
    ReviewedBy,
    ApiUnset,
    ApiSet,
    EngineerRole,
    Online,
    Total,
    General,
    StartupDefaultPage,
    AutoRunDiagnosis,
    DataSources,
    DefaultDataSource,
    SimulationScenario,
    LastImportedTrace,
    LiveApiConnection,
    ApiUrl,
    RequestTimeout,
    TokenStatus,
    SaveToken,
    DeleteToken,
    ConfirmDeleteToken,
    TestConnection,
    TestingConnection,
    ConnectionOk,
    KeychainError,
    DigitalTwinDefaults,
    DataArtifacts,
    ArtifactRoot,
    ChooseFolder,
    OpenFolder,
    SettingsFile,
    ClearRunHistory,
    ConfirmClearRunHistory,
    ModelCache,
    RebuildModel,
    ConfirmRebuildModel,
    DiagnosisReview,
    RulePolicy,
    MlPolicy,
    HilPolicy,
    PrivacyAbout,
    LocalProcessing,
    KeychainProtection,
    BundleId,
    Version,
    OpenReport,
    CheckForUpdates,
    UpdateStatus,
    UpdateDialogOpened,
    UpdateFeedReachable,
    OpenRunFolder,
    ArtifactFiles,
    ValidationWarnings,
    OpenFailed,
    Saved,
    NotAvailable,
    EnvFallback,
    Rows,
    DefaultSourceSimulation,
    DefaultSourceLastImport,
    DefaultSourceLiveApi,
    DataConnectors,
    ConnectorKind,
    ConnectorLocalProbe,
    ConnectorWebsiteProbe,
    ConnectorHttpJson,
    ConnectorPrometheusQuery,
    ConnectorPrometheusMetrics,
    ConnectorOtlpGrpc,
    ConnectorNativePcap,
    ConnectorSystemCounters,
    SourceProfile,
    ProfileName,
    PrometheusBaseUrl,
    PrometheusMetricsEndpoint,
    PrometheusLookback,
    PrometheusStep,
    ProbeSamples,
    ProbeTargets,
    OtlpBindAddr,
    CaptureSource,
    PacketLimit,
    CaptureTimeout,
    CaptureSession,
    StartReceiver,
    StartCapture,
    CancelCapture,
    DiagnoseLastSample,
    StopReceiver,
    DiagnoseBuffer,
    CaptureProgress,
    CaptureRunning,
    CaptureCompleted,
    CaptureCancelled,
    CaptureFailed,
    SystemInterface,
    SamplingInterval,
    HttpJsonConnectorHint,
    ConnectorHealth,
    MeasurementQuality,
    MissingMetrics,
    LastSample,
    ImportTopology,
    ExportTopology,
    CustomTopology,
    StartupOverview,
    StartupTelemetry,
    StartupDiagnosis,
    StartupRuleMl,
    StartupDigitalTwin,
    StartupWhatIf,
    StartupReports,
    StartupSettings,
}

struct NetDiagApp {
    #[cfg(target_os = "macos")]
    native_menu: Option<NativeMenu>,
    tab: Tab,
    language: Language,
    settings: AppSettings,
    settings_store: SettingsStore,
    secrets: Box<dyn SecretStore>,
    pending_startup_diagnosis: bool,
    startup_frames: u8,
    did_restore_window_size: bool,
    diagnosis_job: Option<DiagnosisJob>,
    diagnosis_restore_startup_warning: bool,
    source_mode: SourceMode,
    source_snapshot: Option<SourceSnapshot>,
    dashboard: Option<DashboardViewModel>,
    simulation_scenario: SimScenario,
    trend_range: TrendRange,
    latency_metric: LatencyMetric,
    artifacts_root: PathBuf,
    result: Option<PipelineResult>,
    topology: String,
    custom_topology: Option<TopologyModel>,
    action: String,
    token_input: String,
    probe_targets_text: String,
    hil_notes: BTreeMap<String, String>,
    settings_notice: Option<String>,
    update_notice: Option<String>,
    api_test_status: Option<String>,
    api_test_job: Option<ApiTestJob>,
    capture_session: Option<CaptureSessionState>,
    pending_delete_token: bool,
    pending_clear_runs: bool,
    pending_rebuild_model: bool,
    status: String,
    error: Option<String>,
}

type DiagnosisJob = mpsc::Receiver<anyhow::Result<(PipelineResult, SourceSnapshot)>>;
type ApiTestJob = mpsc::Receiver<anyhow::Result<ApiTestOutcome>>;
type CaptureSessionJob = mpsc::Receiver<CaptureSessionEvent>;

#[derive(Debug)]
struct ApiTestOutcome {
    rows: usize,
    sample: String,
}

#[derive(Debug)]
enum CaptureSessionEvent {
    Progress(CaptureProgress),
    Finished(Box<anyhow::Result<SourceSnapshot>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureSessionPhase {
    Running,
    Cancelling,
    Completed,
    Cancelled,
    Failed,
}

impl CaptureSessionPhase {
    fn is_active(self) -> bool {
        matches!(
            self,
            CaptureSessionPhase::Running | CaptureSessionPhase::Cancelling
        )
    }
}

struct CaptureSessionState {
    kind: ConnectorKind,
    phase: CaptureSessionPhase,
    started_at: chrono::DateTime<chrono::Utc>,
    timeout: Duration,
    progress: Option<CaptureProgress>,
    last_sample: Option<SourceSnapshot>,
    status: String,
    job: Option<CaptureSessionJob>,
    cancel: Option<Arc<AtomicBool>>,
    otlp: Option<OtlpReceiverSession>,
}

impl NetDiagApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        configure_fonts(&cc.egui_ctx);
        let settings_store = SettingsStore::new(SettingsStore::default_path());
        let (mut settings, settings_warning) = settings_store.load_or_default();
        settings.data_connectors.ensure_profiles();
        let normalize_warning = if settings::normalize_bundle_settings(&mut settings) {
            settings_store
                .save(&settings)
                .err()
                .map(|err| err.to_string())
        } else {
            None
        };
        let secrets = default_secret_store();
        let (source_mode, source_warning) = source_mode_from_settings(&settings, secrets.as_ref());
        let initial_language = Language::from(settings.language);
        #[cfg(target_os = "macos")]
        let (native_menu, menu_warning) = match NativeMenu::install(&cc.egui_ctx, initial_language)
        {
            Ok(menu) => (Some(menu), None),
            Err(err) => (None, Some(format!("native menu: {err}"))),
        };
        #[cfg(not(target_os = "macos"))]
        let menu_warning: Option<String> = None;
        let startup_warning = settings_warning
            .or(normalize_warning)
            .or(source_warning)
            .or(menu_warning);
        Self {
            #[cfg(target_os = "macos")]
            native_menu,
            tab: Tab::from(settings.startup.default_tab),
            language: initial_language,
            settings: settings.clone(),
            settings_store,
            secrets,
            pending_startup_diagnosis: settings.startup.auto_run_diagnosis,
            startup_frames: 0,
            did_restore_window_size: false,
            diagnosis_job: None,
            diagnosis_restore_startup_warning: false,
            source_mode,
            source_snapshot: None,
            dashboard: None,
            simulation_scenario: settings.simulation_scenario,
            trend_range: TrendRange::default(),
            latency_metric: LatencyMetric::default(),
            artifacts_root: settings.artifacts_root.clone(),
            result: None,
            topology: settings.what_if.topology.clone(),
            custom_topology: settings.what_if.custom_topology.clone(),
            action: settings.what_if.action.clone(),
            token_input: String::new(),
            probe_targets_text: settings
                .data_connectors
                .active_profile()
                .map(|profile| profile.website_probe.targets.join("\n"))
                .unwrap_or_else(|| settings.data_connectors.website_probe.targets.join("\n")),
            hil_notes: BTreeMap::new(),
            settings_notice: startup_warning.clone(),
            update_notice: None,
            api_test_status: None,
            api_test_job: None,
            capture_session: None,
            pending_delete_token: false,
            pending_clear_runs: false,
            pending_rebuild_model: false,
            status: "Ready".to_string(),
            error: startup_warning,
        }
    }

    fn run_diagnosis(&mut self) {
        self.start_diagnosis(false);
    }

    fn start_diagnosis(&mut self, restore_startup_warning: bool) {
        if self.diagnosis_job.is_some() {
            self.settings_notice =
                Some(tr(self.language, Text::AnalysisAlreadyRunning).to_string());
            return;
        }
        let source_mode = self.source_mode.clone();
        let artifacts_root = self.artifacts_root.clone();
        let what_if = self.current_what_if_request();
        let action = self.action.clone();
        let (sender, receiver) = mpsc::channel();
        self.status = "Running".to_string();
        self.error = None;
        self.diagnosis_restore_startup_warning = restore_startup_warning;
        self.diagnosis_job = Some(receiver);
        thread::spawn(move || {
            let result = Self::run_source(source_mode, artifacts_root, what_if, action);
            let _ = sender.send(result);
        });
    }

    fn finish_diagnosis(
        &mut self,
        result: anyhow::Result<(PipelineResult, SourceSnapshot)>,
        restore_startup_warning: bool,
    ) {
        match result {
            Ok((result, source_snapshot)) => {
                self.status = status_for_result(&result).to_string();
                self.error = None;
                self.dashboard = Some(DashboardViewModel::build(&result, &source_snapshot));
                self.source_snapshot = Some(source_snapshot);
                self.result = Some(result);
                self.hil_notes.clear();
                if restore_startup_warning && let Some(warning) = self.settings_notice.clone() {
                    self.error = Some(warning);
                }
            }
            Err(err) => {
                self.status = "Needs attention".to_string();
                self.error = Some(err.to_string());
            }
        }
    }

    fn run_source(
        source_mode: SourceMode,
        artifacts_root: PathBuf,
        what_if: Option<WhatIfRequest>,
        action: String,
    ) -> anyhow::Result<(PipelineResult, SourceSnapshot)> {
        let source_snapshot = source_mode.load()?;
        let request = what_if.or_else(|| WhatIfRequest::built_in("line", action.as_str()).ok());
        let result =
            diagnose_ingest_with_whatif(source_snapshot.ingest.clone(), &artifacts_root, request)?;
        Ok((result, source_snapshot))
    }

    fn start_diagnosis_from_snapshot(&mut self, source_snapshot: SourceSnapshot) {
        if self.diagnosis_job.is_some() {
            self.settings_notice =
                Some(tr(self.language, Text::AnalysisAlreadyRunning).to_string());
            return;
        }
        let artifacts_root = self.artifacts_root.clone();
        let what_if = self.current_what_if_request();
        let action = self.action.clone();
        let (sender, receiver) = mpsc::channel();
        self.status = "Running".to_string();
        self.error = None;
        self.diagnosis_restore_startup_warning = false;
        self.diagnosis_job = Some(receiver);
        thread::spawn(move || {
            let request = what_if.or_else(|| WhatIfRequest::built_in("line", action.as_str()).ok());
            let result = diagnose_ingest_with_whatif(
                source_snapshot.ingest.clone(),
                &artifacts_root,
                request,
            )
            .map_err(anyhow::Error::from)
            .map(|result| (result, source_snapshot));
            let _ = sender.send(result);
        });
    }

    fn current_otlp_receiver_config(&self) -> anyhow::Result<OtlpGrpcReceiverConfig> {
        let profile = self
            .settings
            .data_connectors
            .active_profile()
            .ok_or_else(|| anyhow::anyhow!("no active source profile"))?;
        if profile.kind != ConnectorKind::OtlpGrpcReceiver {
            anyhow::bail!("active source profile is not OTLP gRPC");
        }
        Ok(OtlpGrpcReceiverConfig {
            bind_addr: profile.otlp_grpc.bind_addr.clone(),
            timeout: Duration::from_secs(profile.otlp_grpc.timeout_secs.max(1)),
            metrics: profile.otlp_grpc.mapping.clone(),
            sample: "otlp_grpc_session".to_string(),
        })
    }

    fn current_native_pcap_config(&self) -> anyhow::Result<(NativePcapConfig, String)> {
        let profile = self
            .settings
            .data_connectors
            .active_profile()
            .ok_or_else(|| anyhow::anyhow!("no active source profile"))?;
        if profile.kind != ConnectorKind::NativePcap {
            anyhow::bail!("active source profile is not native pcap");
        }
        Ok((
            NativePcapConfig {
                source: native_pcap_source(&profile.native_pcap.source),
                timeout: Duration::from_secs(profile.native_pcap.timeout_secs.max(1)),
                packet_limit: profile.native_pcap.packet_limit.max(1),
                sample: "native_pcap_session".to_string(),
            },
            profile.native_pcap.source.clone(),
        ))
    }

    fn current_system_counters_config(&self) -> anyhow::Result<(SystemCountersConfig, String)> {
        let profile = self
            .settings
            .data_connectors
            .active_profile()
            .ok_or_else(|| anyhow::anyhow!("no active source profile"))?;
        if profile.kind != ConnectorKind::SystemCounters {
            anyhow::bail!("active source profile is not system counters");
        }
        let interface = profile.system_counters.interface.trim().to_string();
        Ok((
            SystemCountersConfig {
                interface: (!interface.is_empty() && interface != "all")
                    .then_some(interface.clone()),
                interval: Duration::from_secs(profile.system_counters.interval_secs.clamp(1, 10)),
                sample: "system_counters_session".to_string(),
            },
            if interface.is_empty() {
                "all interfaces".to_string()
            } else {
                interface
            },
        ))
    }

    fn start_capture_session(&mut self, kind: ConnectorKind) {
        if self
            .capture_session
            .as_ref()
            .is_some_and(|session| session.phase.is_active())
        {
            self.settings_notice = Some(tr(self.language, Text::CaptureRunning).to_string());
            return;
        }
        match kind {
            ConnectorKind::OtlpGrpcReceiver => self.start_otlp_capture_session(),
            ConnectorKind::NativePcap => self.start_native_pcap_capture_session(),
            ConnectorKind::SystemCounters => self.start_system_counters_capture_session(),
            _ => {
                self.settings_notice = Some(
                    "Capture sessions are only available for OTLP, pcap, and system counters"
                        .to_string(),
                );
            }
        }
    }

    fn start_otlp_capture_session(&mut self) {
        match self.current_otlp_receiver_config().and_then(|config| {
            let bind_addr = config.bind_addr.clone();
            OtlpReceiverSession::start(&config)
                .map(|session| (session, config.timeout, format!("Listening on {bind_addr}")))
                .map_err(anyhow::Error::from)
        }) {
            Ok((session, timeout, status)) => {
                self.capture_session = Some(CaptureSessionState {
                    kind: ConnectorKind::OtlpGrpcReceiver,
                    phase: CaptureSessionPhase::Running,
                    started_at: chrono::Utc::now(),
                    timeout,
                    progress: None,
                    last_sample: None,
                    status,
                    job: None,
                    cancel: None,
                    otlp: Some(session),
                });
            }
            Err(err) => {
                self.capture_session = Some(failed_capture_session(
                    ConnectorKind::OtlpGrpcReceiver,
                    err.to_string(),
                ));
            }
        }
    }

    fn start_native_pcap_capture_session(&mut self) {
        match self.current_native_pcap_config() {
            Ok((config, source_label)) => {
                let (sender, receiver) = mpsc::channel();
                let cancel = Arc::new(AtomicBool::new(false));
                let progress_sender = sender.clone();
                let control =
                    CaptureControl::new(Arc::clone(&cancel)).with_progress(move |progress| {
                        let _ = progress_sender.send(CaptureSessionEvent::Progress(progress));
                    });
                let timeout = config.timeout;
                thread::spawn(move || {
                    let result = load_native_pcap_with_control(&config, &control)
                        .map(|loaded| {
                            source_snapshot_from_connector_session(
                                loaded,
                                ConnectorKind::NativePcap,
                                "Captured",
                                source_label,
                            )
                        })
                        .map_err(anyhow::Error::from);
                    let _ = sender.send(CaptureSessionEvent::Finished(Box::new(result)));
                });
                self.capture_session = Some(CaptureSessionState {
                    kind: ConnectorKind::NativePcap,
                    phase: CaptureSessionPhase::Running,
                    started_at: chrono::Utc::now(),
                    timeout,
                    progress: None,
                    last_sample: None,
                    status: tr(self.language, Text::CaptureRunning).to_string(),
                    job: Some(receiver),
                    cancel: Some(cancel),
                    otlp: None,
                });
            }
            Err(err) => {
                self.capture_session = Some(failed_capture_session(
                    ConnectorKind::NativePcap,
                    err.to_string(),
                ));
            }
        }
    }

    fn start_system_counters_capture_session(&mut self) {
        match self.current_system_counters_config() {
            Ok((config, source_label)) => {
                let (sender, receiver) = mpsc::channel();
                let cancel = Arc::new(AtomicBool::new(false));
                let progress_sender = sender.clone();
                let control =
                    CaptureControl::new(Arc::clone(&cancel)).with_progress(move |progress| {
                        let _ = progress_sender.send(CaptureSessionEvent::Progress(progress));
                    });
                let timeout = config.interval;
                thread::spawn(move || {
                    let result = load_system_counters_with_control(&config, &control)
                        .map(|loaded| {
                            source_snapshot_from_connector_session(
                                loaded,
                                ConnectorKind::SystemCounters,
                                "Sampled",
                                source_label,
                            )
                        })
                        .map_err(anyhow::Error::from);
                    let _ = sender.send(CaptureSessionEvent::Finished(Box::new(result)));
                });
                self.capture_session = Some(CaptureSessionState {
                    kind: ConnectorKind::SystemCounters,
                    phase: CaptureSessionPhase::Running,
                    started_at: chrono::Utc::now(),
                    timeout,
                    progress: None,
                    last_sample: None,
                    status: tr(self.language, Text::CaptureRunning).to_string(),
                    job: Some(receiver),
                    cancel: Some(cancel),
                    otlp: None,
                });
            }
            Err(err) => {
                self.capture_session = Some(failed_capture_session(
                    ConnectorKind::SystemCounters,
                    err.to_string(),
                ));
            }
        }
    }

    fn cancel_capture_session(&mut self) {
        let Some(session) = &mut self.capture_session else {
            return;
        };
        if let Some(otlp) = session.otlp.take() {
            session.phase = CaptureSessionPhase::Cancelling;
            match otlp.stop() {
                Ok(()) => {
                    session.phase = CaptureSessionPhase::Cancelled;
                    session.status = tr(self.language, Text::CaptureCancelled).to_string();
                }
                Err(err) => {
                    session.phase = CaptureSessionPhase::Failed;
                    session.status = err.to_string();
                }
            }
        } else if let Some(cancel) = &session.cancel {
            cancel.store(true, Ordering::Relaxed);
            session.phase = CaptureSessionPhase::Cancelling;
            session.status = tr(self.language, Text::CaptureCancelled).to_string();
        }
    }

    fn diagnose_capture_last_sample(&mut self) {
        let snapshot = self
            .capture_session
            .as_ref()
            .and_then(|session| session.last_sample.clone());
        if let Some(snapshot) = snapshot {
            self.start_diagnosis_from_snapshot(snapshot);
            return;
        }
        let mut diagnose_now = None;
        let Some(session) = &mut self.capture_session else {
            return;
        };
        let Some(otlp) = &session.otlp else {
            session.status = tr(self.language, Text::NoSource).to_string();
            return;
        };
        match otlp.snapshot(session.timeout) {
            Ok(loaded) => {
                let source_snapshot = source_snapshot_from_connector_session(
                    loaded,
                    ConnectorKind::OtlpGrpcReceiver,
                    "Buffered",
                    "OTLP receiver".to_string(),
                );
                session.status = format!(
                    "{}: {} {}",
                    tr(self.language, Text::LastSample),
                    source_snapshot.ingest.records.len(),
                    tr(self.language, Text::Rows)
                );
                session.last_sample = Some(source_snapshot.clone());
                diagnose_now = Some(source_snapshot);
            }
            Err(err) => {
                session.status = err.to_string();
            }
        }
        if let Some(source_snapshot) = diagnose_now {
            self.start_diagnosis_from_snapshot(source_snapshot);
        }
    }

    fn current_what_if_request(&self) -> Option<WhatIfRequest> {
        let topology = if self.topology == "custom" {
            self.custom_topology.clone()?
        } else {
            topology_model(self.topology.as_str()).ok()?
        };
        Some(WhatIfRequest {
            topology,
            action_id: self.action.clone(),
        })
    }

    fn poll_diagnosis_job(&mut self, ctx: &egui::Context) {
        let message = match self
            .diagnosis_job
            .as_ref()
            .map(|receiver| receiver.try_recv())
        {
            Some(Ok(message)) => Some(message),
            Some(Err(mpsc::TryRecvError::Disconnected)) => Some(Err(anyhow::anyhow!(
                "diagnosis worker stopped before returning a result"
            ))),
            Some(Err(mpsc::TryRecvError::Empty)) => {
                ctx.request_repaint_after(Duration::from_millis(100));
                None
            }
            None => None,
        };

        if let Some(message) = message {
            self.diagnosis_job = None;
            let restore_startup_warning = self.diagnosis_restore_startup_warning;
            self.diagnosis_restore_startup_warning = false;
            self.finish_diagnosis(message, restore_startup_warning);
            ctx.request_repaint();
        }
    }

    fn start_api_test_connection(&mut self) {
        if self.api_test_job.is_some() {
            return;
        }
        let source_mode = match self.connector_source_mode() {
            Ok(source_mode) => source_mode,
            Err(err) => {
                self.api_test_status = Some(err.to_string());
                return;
            }
        };
        let (sender, receiver) = mpsc::channel();
        self.api_test_status = Some(tr(self.language, Text::TestingConnection).to_string());
        self.api_test_job = Some(receiver);
        thread::spawn(move || {
            let result = source_mode.load().map(|snapshot| ApiTestOutcome {
                rows: snapshot.ingest.records.len(),
                sample: snapshot.descriptor.name,
            });
            let _ = sender.send(result);
        });
    }

    fn poll_api_test_job(&mut self, ctx: &egui::Context) {
        let message = match self
            .api_test_job
            .as_ref()
            .map(|receiver| receiver.try_recv())
        {
            Some(Ok(message)) => Some(message),
            Some(Err(mpsc::TryRecvError::Disconnected)) => Some(Err(anyhow::anyhow!(
                "API test worker stopped before returning a result"
            ))),
            Some(Err(mpsc::TryRecvError::Empty)) => {
                ctx.request_repaint_after(Duration::from_millis(100));
                None
            }
            None => None,
        };

        if let Some(message) = message {
            self.api_test_job = None;
            self.api_test_status = Some(match message {
                Ok(outcome) => format!(
                    "{}: {} {} · {}",
                    tr(self.language, Text::ConnectionOk),
                    outcome.rows,
                    tr(self.language, Text::Rows),
                    outcome.sample
                ),
                Err(err) => err.to_string(),
            });
            ctx.request_repaint();
        }
    }

    fn poll_capture_session(&mut self, ctx: &egui::Context) {
        let Some(session) = &mut self.capture_session else {
            return;
        };
        if let Some(otlp) = &session.otlp
            && session.phase.is_active()
        {
            let frames = otlp.buffered_frames();
            let elapsed = (chrono::Utc::now() - session.started_at)
                .num_milliseconds()
                .max(0) as u64;
            session.progress = Some(CaptureProgress {
                stage: "listening".to_string(),
                message: "listening for OTLP metrics".to_string(),
                packets_seen: 0,
                bytes_seen: 0,
                samples_seen: frames,
                elapsed_ms: elapsed,
                timeout_ms: session.timeout.as_millis() as u64,
                packet_limit: None,
                last_sample_at: otlp.last_received_at(),
            });
            ctx.request_repaint_after(Duration::from_millis(500));
        }

        let mut finished = None;
        if let Some(receiver) = session.job.as_ref() {
            loop {
                match receiver.try_recv() {
                    Ok(CaptureSessionEvent::Progress(progress)) => {
                        session.progress = Some(progress);
                    }
                    Ok(CaptureSessionEvent::Finished(result)) => {
                        finished = Some(*result);
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        finished = Some(Err(anyhow::anyhow!(
                            "capture worker stopped before returning a result"
                        )));
                        break;
                    }
                }
            }
        }

        if let Some(result) = finished {
            session.job = None;
            session.cancel = None;
            match result {
                Ok(snapshot) => {
                    let rows = snapshot.ingest.records.len();
                    session.phase = CaptureSessionPhase::Completed;
                    session.status = format!(
                        "{}: {} {}",
                        tr(self.language, Text::CaptureCompleted),
                        rows,
                        tr(self.language, Text::Rows)
                    );
                    session.last_sample = Some(snapshot);
                }
                Err(err) if err.to_string().contains("cancelled") => {
                    session.phase = CaptureSessionPhase::Cancelled;
                    session.status = tr(self.language, Text::CaptureCancelled).to_string();
                }
                Err(err) => {
                    session.phase = CaptureSessionPhase::Failed;
                    session.status = format!("{}: {err}", tr(self.language, Text::CaptureFailed));
                }
            }
            ctx.request_repaint();
        } else if session.phase.is_active() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn maybe_start_deferred_diagnosis(&mut self, ctx: &egui::Context) {
        if !self.pending_startup_diagnosis {
            return;
        }
        self.startup_frames = self.startup_frames.saturating_add(1);
        ctx.request_repaint();
        if self.startup_frames < 2 {
            return;
        }
        self.pending_startup_diagnosis = false;
        self.start_diagnosis(self.settings_notice.is_some());
    }

    fn import_trace(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Trace", &["csv", "json"])
            .set_directory("data/samples")
            .pick_file()
        {
            self.settings.last_imported_trace = Some(path.clone());
            self.persist_settings();
            self.source_mode = SourceMode::File(path);
            self.run_diagnosis();
        }
    }

    fn run_simulation(&mut self) {
        self.simulation_scenario = self.settings.simulation_scenario;
        self.source_mode = SourceMode::Simulated(self.simulation_scenario);
        self.run_diagnosis();
    }

    fn run_live_api(&mut self) {
        match self.connector_source_mode() {
            Ok(source_mode) => {
                self.source_mode = source_mode;
                self.run_diagnosis();
            }
            Err(err) => {
                self.tab = Tab::Settings;
                self.status = "Ready".to_string();
                self.error = None;
                self.api_test_status = None;
                self.settings_notice = Some(format!(
                    "{}: {err}",
                    tr(self.language, Text::ConfigureLiveApiFirst)
                ));
            }
        }
    }

    fn connector_source_mode(&self) -> anyhow::Result<SourceMode> {
        connector_source_mode_from_profile(&self.settings, self.secrets.as_ref())
    }

    fn persist_settings(&mut self) {
        match self.settings_store.save(&self.settings) {
            Ok(()) => self.settings_notice = Some(tr(self.language, Text::Saved).to_string()),
            Err(err) => self.settings_notice = Some(err.to_string()),
        }
    }

    fn set_language(&mut self, language: Language) {
        self.language = language;
        self.settings.language = LanguageSetting::from(language);
        self.persist_settings();
    }
}

impl eframe::App for NetDiagApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        #[cfg(target_os = "macos")]
        self.poll_native_menu();
        self.poll_diagnosis_job(ui.ctx());
        self.poll_api_test_job(ui.ctx());
        self.poll_capture_session(ui.ctx());
        self.maybe_start_deferred_diagnosis(ui.ctx());
        if !self.did_restore_window_size {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::OuterPosition(Pos2::new(320.0, 80.0)));
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::InnerSize(Vec2::new(1440.0, 960.0)));
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Focus);
            self.did_restore_window_size = true;
            ui.ctx().request_repaint();
        }
        let root = ui.max_rect();
        draw_background(ui, root);

        let app_rect = root.shrink2(Vec2::new(34.0, 28.0));
        let sidebar_rect = Rect::from_min_size(app_rect.min, Vec2::new(220.0, app_rect.height()));
        let main_rect = Rect::from_min_max(
            Pos2::new(sidebar_rect.right() + 16.0, app_rect.top()),
            Pos2::new(app_rect.right(), app_rect.bottom()),
        );

        paint_glass(ui, sidebar_rect, 24, Color32::from_white_alpha(86));
        paint_glass(ui, main_rect, 24, Color32::from_white_alpha(94));

        with_rect(ui, sidebar_rect.shrink2(Vec2::new(18.0, 18.0)), |ui| {
            self.render_sidebar(ui);
        });
        with_rect(ui, main_rect.shrink2(Vec2::new(22.0, 24.0)), |ui| {
            self.render_current_tab(ui);
        });
    }
}

impl NetDiagApp {
    #[cfg(target_os = "macos")]
    fn poll_native_menu(&mut self) {
        let has_result = self.result.is_some();
        let has_live_api = self.connector_is_configured_for_menu();
        let is_running = self.diagnosis_job.is_some();
        let commands = self
            .native_menu
            .as_ref()
            .map(|menu| {
                menu.sync(
                    self.language,
                    self.tab,
                    has_result,
                    has_live_api,
                    is_running,
                );
                menu.drain_commands()
            })
            .unwrap_or_default();

        for command in commands {
            self.handle_native_menu_command(command);
        }

        if let Some(menu) = &self.native_menu {
            menu.sync(
                self.language,
                self.tab,
                self.result.is_some(),
                self.connector_is_configured_for_menu(),
                self.diagnosis_job.is_some(),
            );
        }
    }

    #[cfg(target_os = "macos")]
    fn connector_is_configured_for_menu(&self) -> bool {
        let Some(profile) = self.settings.data_connectors.active_profile() else {
            return self.settings.data_connectors.default_connector != ConnectorKind::HttpJson
                || !self.settings.api.endpoint.trim().is_empty();
        };
        match profile.kind {
            ConnectorKind::HttpJson => !profile.http_json.endpoint.trim().is_empty(),
            ConnectorKind::PrometheusQueryRange => {
                !profile.prometheus_query.base_url.trim().is_empty()
            }
            ConnectorKind::PrometheusExposition => {
                !profile.prometheus_exposition.endpoint.trim().is_empty()
            }
            ConnectorKind::OtlpGrpcReceiver => !profile.otlp_grpc.bind_addr.trim().is_empty(),
            ConnectorKind::NativePcap => !profile.native_pcap.source.trim().is_empty(),
            ConnectorKind::SystemCounters
            | ConnectorKind::LocalProbe
            | ConnectorKind::WebsiteProbe => true,
        }
    }

    #[cfg(target_os = "macos")]
    fn handle_native_menu_command(&mut self, command: NativeMenuCommand) {
        match command {
            NativeMenuCommand::NewAnalysis => self.run_diagnosis(),
            NativeMenuCommand::ImportTrace => self.import_trace(),
            NativeMenuCommand::RunSimulation => self.run_simulation(),
            NativeMenuCommand::LiveApi => self.run_live_api(),
            NativeMenuCommand::CheckForUpdates => self.check_for_updates(),
            NativeMenuCommand::OpenReport => self.open_current_report(),
            NativeMenuCommand::OpenRunFolder => self.open_current_run_folder(),
            NativeMenuCommand::Settings => self.tab = Tab::Settings,
            NativeMenuCommand::Help => self.open_help_document(),
            NativeMenuCommand::SwitchTab(tab) => self.tab = tab,
        }
    }

    fn render_current_tab(&mut self, ui: &mut egui::Ui) {
        match self.tab {
            Tab::Overview => self.render_overview(ui),
            _ => self.render_detail_shell(ui),
        }
    }

    fn render_sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("NetDiag Twin").size(18.0).strong().color(INK));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                version_pill(ui);
            });
        });
        ui.add_space(32.0);
        for (tab, icon) in [
            (Tab::Overview, icons::DASHBOARD_LINE),
            (Tab::Telemetry, icons::PULSE_LINE),
            (Tab::Diagnosis, icons::RADAR_LINE),
            (Tab::RuleMl, icons::SCALES_3_LINE),
            (Tab::DigitalTwin, icons::NODE_TREE),
            (Tab::WhatIf, icons::ROUTE_LINE),
            (Tab::Reports, icons::FILE_TEXT_LINE),
            (Tab::Settings, icons::SETTINGS_3_LINE),
        ] {
            nav_item(
                ui,
                &mut self.tab,
                tab,
                icon,
                title_for_tab(tab, self.language),
            );
            ui.add_space(10.0);
        }
        ui.add_space(ui.available_height().max(0.0) - 72.0);
        user_chip(ui, self.language);
    }

    fn render_overview(&mut self, ui: &mut egui::Ui) {
        let bounds = ui.max_rect();
        if bounds.height() < OVERVIEW_MIN_CONTENT_HEIGHT {
            egui::ScrollArea::vertical()
                .id_salt("overview_scroll")
                .auto_shrink([false, false])
                .show_viewport(ui, |ui, _| {
                    ui.set_min_size(Vec2::new(
                        bounds.width(),
                        overview_content_height(bounds.height()),
                    ));
                    let content = Rect::from_min_size(
                        bounds.min,
                        Vec2::new(bounds.width(), overview_content_height(bounds.height())),
                    );
                    self.render_overview_layout(ui, content);
                });
            return;
        }
        self.render_overview_layout(ui, bounds);
    }

    fn render_overview_layout(&mut self, ui: &mut egui::Ui, bounds: Rect) {
        let header_h = 92.0;
        let summary_h = SUMMARY_CARD_HEIGHT;
        let status_h = 58.0;
        let gap = 16.0;

        let header = Rect::from_min_size(bounds.min, Vec2::new(bounds.width(), header_h));
        with_rect(ui, header, |ui| self.render_header(ui));

        let summary = Rect::from_min_size(
            Pos2::new(bounds.left(), header.bottom()),
            Vec2::new(bounds.width(), summary_h),
        );
        with_rect(ui, summary, |ui| self.render_summary_cards(ui));

        let body_top = summary.bottom() + gap;
        let bottom_bar = Rect::from_min_size(
            Pos2::new(bounds.left() + 2.0, bounds.bottom() - status_h),
            Vec2::new(bounds.width() - 4.0, status_h),
        );
        let body_available = (bottom_bar.top() - body_top - gap).max(0.0);
        let min_middle_h = if body_available >= 520.0 {
            260.0
        } else {
            220.0
        };
        let min_bottom_h = if body_available >= 520.0 {
            250.0
        } else {
            160.0
        };
        let mut bottom_cards_h = (body_available * 0.47).clamp(min_bottom_h, 300.0);
        bottom_cards_h = bottom_cards_h.min((body_available - min_middle_h - gap).max(0.0));
        if bottom_cards_h < min_bottom_h && body_available > gap {
            bottom_cards_h = ((body_available - gap) * 0.38).max(0.0);
        }
        let middle_h = (body_available - bottom_cards_h - gap).max(0.0);

        let left_w = (bounds.width() * 0.40).clamp(430.0, 560.0);
        let metrics_rect = Rect::from_min_size(
            Pos2::new(bounds.left(), body_top),
            Vec2::new(left_w, middle_h),
        );
        let chart_rect = Rect::from_min_max(
            Pos2::new(metrics_rect.right() + gap, body_top),
            Pos2::new(bounds.right(), body_top + middle_h),
        );

        with_rect(ui, metrics_rect, |ui| self.render_key_metrics(ui));
        with_rect(ui, chart_rect, |ui| self.render_latency_panel(ui));

        let cards_top = metrics_rect.bottom() + gap;
        let card_w = (bounds.width() - gap * 2.0) / 3.0;
        let diagnosis_rect = Rect::from_min_size(
            Pos2::new(bounds.left(), cards_top),
            Vec2::new(card_w, bottom_cards_h),
        );
        let compare_rect = Rect::from_min_size(
            Pos2::new(diagnosis_rect.right() + gap, cards_top),
            Vec2::new(card_w, bottom_cards_h),
        );
        let talkers_rect = Rect::from_min_size(
            Pos2::new(compare_rect.right() + gap, cards_top),
            Vec2::new(card_w, bottom_cards_h),
        );

        with_rect(ui, diagnosis_rect, |ui| self.render_diagnosis_card(ui));
        with_rect(ui, compare_rect, |ui| self.render_rule_ml_card(ui));
        with_rect(ui, talkers_rect, |ui| self.render_top_talkers(ui));
        with_rect(ui, bottom_bar, |ui| self.render_status_bar(ui));
    }

    fn render_detail_shell(&mut self, ui: &mut egui::Ui) {
        let bounds = ui.max_rect();
        let header_h = 92.0;
        let status_h = 58.0;
        let gap = 16.0;
        let header = Rect::from_min_size(bounds.min, Vec2::new(bounds.width(), header_h));
        let status = Rect::from_min_size(
            Pos2::new(bounds.left() + 2.0, bounds.bottom() - status_h),
            Vec2::new(bounds.width() - 4.0, status_h),
        );
        let content = Rect::from_min_max(
            Pos2::new(bounds.left(), header.bottom() + gap),
            Pos2::new(bounds.right(), status.top() - gap),
        );

        with_rect(ui, header, |ui| self.render_header(ui));
        with_rect(ui, content, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.set_width(content.width());
                    match self.tab {
                        Tab::Telemetry => self.render_telemetry_page(ui),
                        Tab::Diagnosis => self.render_diagnosis_page(ui),
                        Tab::RuleMl => self.render_rule_ml_page(ui),
                        Tab::DigitalTwin => self.render_digital_twin_page(ui),
                        Tab::WhatIf => self.render_whatif_page(ui),
                        Tab::Reports => self.render_reports_page(ui),
                        Tab::Settings => self.render_settings_page(ui),
                        Tab::Overview => {}
                    }
                });
        });
        with_rect(ui, status, |ui| self.render_status_bar(ui));
    }

    fn render_telemetry_page(&self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            section_title(ui, tr(self.language, Text::KeyMetrics));
            ui.add_space(10.0);
            self.render_key_metrics(ui);
        });
        ui.add_space(16.0);
        glass_frame(ui, |ui| {
            section_title(ui, title_for_tab(Tab::Telemetry, self.language));
            ui.add_space(10.0);
            let Some(result) = &self.result else {
                ui.label(tr(self.language, Text::NoMetrics));
                return;
            };
            egui::Grid::new("telemetry_windows")
                .num_columns(7)
                .striped(true)
                .spacing(Vec2::new(20.0, 8.0))
                .show(ui, |ui| {
                    for title in telemetry_headers(self.language) {
                        ui.label(RichText::new(title).size(12.0).strong().color(MUTED));
                    }
                    ui.end_row();
                    for window in result.telemetry.windows.iter().take(18) {
                        ui.label(window.start_ts.format("%H:%M:%S").to_string());
                        ui.label(window.raw_rows.to_string());
                        ui.label(format!("{:.1}", window.latency_ms.mean));
                        ui.label(format!("{:.1}", window.latency_ms.p95));
                        ui.label(format!("{:.1}", window.jitter_ms.std));
                        ui.label(format!("{:.2}", window.packet_loss_rate));
                        ui.label(format!("{:.1}", window.throughput_mbps.mean));
                        ui.end_row();
                    }
                });
        });
    }

    fn render_diagnosis_page(&mut self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            section_title(ui, tr(self.language, Text::DiagnosisSummary));
            ui.add_space(10.0);
            let Some(result) = &self.result else {
                ui.label(tr(self.language, Text::NoDiagnosis));
                return;
            };
            for event in &result.diagnosis_events {
                ui.horizontal(|ui| {
                    alert_badge(ui, event.evidence.symptom);
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(fault_label_display(
                                event.evidence.symptom,
                                self.language,
                            ))
                            .size(18.0)
                            .strong()
                            .color(
                                if event.evidence.symptom == FaultLabel::Normal {
                                    GREEN
                                } else {
                                    RED
                                },
                            ),
                        );
                        ui.label(RichText::new(&event.evidence.why).size(13.0).color(INK));
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        confidence_chip(
                            ui,
                            event.evidence.confidence,
                            event.evidence.symptom != FaultLabel::Normal,
                        );
                    });
                });
                ui.add_space(8.0);
                ui.label(
                    RichText::new(tr(self.language, Text::Evidence))
                        .size(12.0)
                        .color(MUTED),
                );
                for metric in &event.evidence.supporting_metrics {
                    bullet(
                        ui,
                        &format!("{}: {:.2} {}", metric.name, metric.value, metric.unit),
                        PURPLE,
                    );
                }
                ui.separator();
            }
        });
    }

    fn render_rule_ml_page(&self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            section_title(ui, tr(self.language, Text::RuleMlComparison));
            ui.add_space(10.0);
            let Some(result) = &self.result else {
                ui.label(tr(self.language, Text::NoComparison));
                return;
            };
            ui.columns(2, |columns| {
                comparison_box(
                    &mut columns[0],
                    tr(self.language, Text::RuleBased),
                    &fault_label_from_str(
                        result
                            .comparison
                            .rule_labels
                            .first()
                            .map(String::as_str)
                            .unwrap_or("normal"),
                        self.language,
                    ),
                    rule_confidence(result),
                    BLUE,
                    tr(self.language, Text::Confidence),
                );
                comparison_box(
                    &mut columns[1],
                    tr(self.language, Text::MlAssisted),
                    &fault_label_from_str(result.comparison.ml_top.as_str(), self.language),
                    result.comparison.ml_top_prob,
                    PURPLE,
                    tr(self.language, Text::Confidence),
                );
            });
            ui.add_space(12.0);
            ui.label(
                RichText::new(comparison_agreement_text(
                    result.comparison.agreement,
                    self.language,
                ))
                .size(13.0)
                .color(INK),
            );
            ui.add_space(16.0);
            section_title(ui, tr(self.language, Text::MlTopPredictions));
            if let Some(manifest) = &result.ml_result.model_manifest {
                let status = if manifest.synthetic_fallback {
                    tr(self.language, Text::SyntheticFallback).to_string()
                } else {
                    manifest.training_source.clone()
                };
                bullet(
                    ui,
                    &format!("{}: {}", tr(self.language, Text::ModelStatus), status),
                    ORANGE,
                );
            }
            for prediction in &result.ml_result.top_predictions {
                bullet(
                    ui,
                    &format!(
                        "{}  {:.2}",
                        fault_label_display(prediction.label, self.language),
                        prediction.prob
                    ),
                    BLUE,
                );
            }
            ui.add_space(12.0);
            section_title(ui, tr(self.language, Text::FeatureContribution));
            for feature in result.ml_result.top_features.iter().take(8) {
                bullet(
                    ui,
                    &format!("{}  {:.3}", feature.name, feature.importance),
                    PURPLE,
                );
            }
        });
    }

    fn render_digital_twin_page(&self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            section_title(ui, title_for_tab(Tab::DigitalTwin, self.language));
            ui.add_space(10.0);
            let (topology, action, topology_model_ref) = self
                .result
                .as_ref()
                .and_then(|result| result.what_if.as_ref())
                .map(|what_if| {
                    (
                        what_if.topology.as_str(),
                        what_if.action_id.as_str(),
                        what_if.topology_snapshot.as_ref(),
                    )
                })
                .unwrap_or((self.topology.as_str(), self.action.as_str(), None));
            let fallback_model;
            let topology_model_ref = if let Some(model) = topology_model_ref {
                Some(model)
            } else if let Some(request) = self.current_what_if_request() {
                fallback_model = request.topology;
                Some(&fallback_model)
            } else {
                None
            };
            ui.label(
                RichText::new(format!(
                    "{}: {}  ·  {}: {}",
                    tr(self.language, Text::Topology),
                    topology,
                    tr(self.language, Text::Action),
                    action
                ))
                .size(14.0)
                .color(INK),
            );
            ui.add_space(16.0);
            draw_topology(
                ui,
                ui.available_width(),
                220.0,
                topology,
                action,
                self.language,
                topology_model_ref,
            );
        });
    }

    fn render_whatif_page(&self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            section_title(ui, tr(self.language, Text::WhatIfResult));
            ui.add_space(10.0);
            let Some(result) = &self.result else {
                ui.label(tr(self.language, Text::NoMetrics));
                return;
            };
            let Some(what_if) = &result.what_if else {
                ui.label(tr(self.language, Text::NoWhatIf));
                return;
            };
            ui.label(RichText::new(&what_if.action_notes).size(14.0).color(INK));
            ui.add_space(12.0);
            egui::Grid::new("whatif_grid")
                .num_columns(3)
                .spacing(Vec2::new(24.0, 8.0))
                .show(ui, |ui| {
                    ui.label(RichText::new(tr(self.language, Text::Metric)).strong());
                    ui.label(RichText::new(tr(self.language, Text::Baseline)).strong());
                    ui.label(RichText::new(tr(self.language, Text::Proposed)).strong());
                    ui.end_row();
                    for metric in ["latency_ms", "loss_rate", "throughput_mbps", "qoe_risk"] {
                        ui.label(metric);
                        ui.label(json_value_text(what_if.baseline.get(metric)));
                        ui.label(json_value_text(what_if.proposed.get(metric)));
                        ui.end_row();
                    }
                });
        });
    }

    fn render_reports_page(&mut self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            section_title(ui, tr(self.language, Text::Artifacts));
            ui.add_space(10.0);
            if let Some(result) = &self.result {
                section_title(ui, tr(self.language, Text::CurrentRun));
                ui.add_space(6.0);
                let run_dir = result.run_dir.clone();
                let recommendations = result.recommendations.clone();
                let warnings = result.ingest.warnings.clone();
                ui.label(
                    RichText::new(run_dir.display().to_string())
                        .size(13.0)
                        .color(INK),
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if soft_button(ui, tr(self.language, Text::OpenReport)).clicked() {
                        self.open_current_report();
                    }
                    if soft_button(ui, tr(self.language, Text::OpenRunFolder)).clicked() {
                        self.open_current_run_folder();
                    }
                });

                ui.add_space(14.0);
                section_title(ui, tr(self.language, Text::ArtifactFiles));
                match manifest_artifacts(&run_dir) {
                    Ok(entries) if entries.is_empty() => {
                        ui.label(tr(self.language, Text::NoArtifacts));
                    }
                    Ok(entries) => {
                        for (key, path) in entries {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(key).size(12.0).strong().color(INK));
                                ui.label(
                                    RichText::new(path.display().to_string())
                                        .size(12.0)
                                        .color(MUTED),
                                );
                            });
                        }
                    }
                    Err(err) => {
                        ui.label(
                            RichText::new(format!(
                                "{}: {err}",
                                tr(self.language, Text::OpenFailed)
                            ))
                            .size(12.0)
                            .color(RED),
                        );
                    }
                }

                if !warnings.is_empty() {
                    ui.add_space(14.0);
                    section_title(ui, tr(self.language, Text::ValidationWarnings));
                    for warning in warnings.iter().take(6) {
                        ui.label(
                            RichText::new(format!(
                                "{}: {} -> {}",
                                warning.column, warning.reason, warning.fallback
                            ))
                            .size(12.0)
                            .color(ORANGE),
                        );
                    }
                }

                ui.add_space(16.0);
                section_title(ui, tr(self.language, Text::Recommendations));
                ui.label(
                    RichText::new(tr(self.language, Text::HilReview))
                        .size(12.0)
                        .color(MUTED),
                );
                ui.add_space(6.0);
                for rec in &recommendations {
                    let mut review_action = None;
                    ui.group(|ui| {
                        ui.label(
                            RichText::new(&rec.recommended_action)
                                .size(14.0)
                                .strong()
                                .color(INK),
                        );
                        ui.label(RichText::new(&rec.expected_effect).size(13.0).color(MUTED));
                        ui.label(format!(
                            "{}={}  {}={:.2}  {}={}",
                            tr(self.language, Text::Risk),
                            rec.risk_level,
                            tr(self.language, Text::Confidence),
                            rec.confidence,
                            tr(self.language, Text::Approval),
                            approval_display(rec.recommendation_need_approval, self.language)
                        ));
                        ui.label(
                            RichText::new(format!(
                                "{}={}  ID={}",
                                tr(self.language, Text::HilStatus),
                                hil_state_display(rec.hil_state, self.language),
                                rec.recommendation_id
                            ))
                            .size(12.0)
                            .color(hil_state_color(rec.hil_state)),
                        );
                        if let Some(review) = &rec.review {
                            ui.label(
                                RichText::new(format!(
                                    "{}={}  {}",
                                    tr(self.language, Text::ReviewedBy),
                                    review.reviewer,
                                    review.reviewed_at.format("%H:%M:%S")
                                ))
                                .size(12.0)
                                .color(MUTED),
                            );
                            if !review.notes.is_empty() {
                                ui.label(RichText::new(&review.notes).size(12.0).color(MUTED));
                            }
                        }
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(tr(self.language, Text::ReviewNotes))
                                    .size(12.0)
                                    .color(MUTED),
                            );
                            let notes = self
                                .hil_notes
                                .entry(rec.recommendation_id.clone())
                                .or_insert_with(|| {
                                    rec.review
                                        .as_ref()
                                        .map(|review| review.notes.clone())
                                        .unwrap_or_default()
                                });
                            ui.add(egui::TextEdit::singleline(notes).desired_width(320.0));
                        });
                        ui.horizontal(|ui| {
                            if soft_button(ui, tr(self.language, Text::Accept)).clicked() {
                                review_action = Some(HilState::Accepted);
                            }
                            if soft_button(ui, tr(self.language, Text::Reject)).clicked() {
                                review_action = Some(HilState::Rejected);
                            }
                            if soft_button(ui, tr(self.language, Text::MarkUncertain)).clicked() {
                                review_action = Some(HilState::Uncertain);
                            }
                            if soft_button(ui, tr(self.language, Text::RequireRerun)).clicked() {
                                review_action = Some(HilState::RequiresRerun);
                            }
                        });
                    });
                    if let Some(state) = review_action {
                        self.apply_hil_review(&rec.recommendation_id, state);
                    }
                    ui.add_space(8.0);
                }
            } else {
                ui.label(tr(self.language, Text::NoArtifacts));
            }

            ui.add_space(18.0);
            self.render_run_history(ui);
        });
    }

    fn render_run_history(&mut self, ui: &mut egui::Ui) {
        section_title(ui, tr(self.language, Text::RunHistory));
        ui.add_space(8.0);
        let history = match list_run_history(&self.artifacts_root, 10) {
            Ok(history) => history,
            Err(err) => {
                ui.label(
                    RichText::new(format!("{}: {err}", tr(self.language, Text::OpenFailed)))
                        .size(12.0)
                        .color(RED),
                );
                return;
            }
        };
        if history.is_empty() {
            ui.label(tr(self.language, Text::NoArtifacts));
            return;
        }
        if history.len() >= 2
            && let Ok(comparison) =
                compare_runs(&self.artifacts_root, &history[1].run_id, &history[0].run_id)
        {
            ui.group(|ui| {
                ui.label(
                    RichText::new(tr(self.language, Text::LatestComparison))
                        .size(13.0)
                        .strong()
                        .color(INK),
                );
                ui.label(
                    RichText::new(format!(
                        "{} -> {}",
                        short_run_id(&comparison.left.run_id),
                        short_run_id(&comparison.right.run_id)
                    ))
                    .size(12.0)
                    .color(MUTED),
                );
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format_delta("P95", comparison.latency_p95_delta_pct, "%"))
                            .size(12.0)
                            .color(INK),
                    );
                    ui.label(
                        RichText::new(format_delta("loss", comparison.loss_delta_pct, "%"))
                            .size(12.0)
                            .color(INK),
                    );
                    ui.label(
                        RichText::new(format_delta(
                            "throughput",
                            comparison.throughput_delta_pct,
                            "%",
                        ))
                        .size(12.0)
                        .color(INK),
                    );
                    ui.label(
                        RichText::new(format!("ML changed={}", comparison.ml_label_changed))
                            .size(12.0)
                            .color(if comparison.ml_label_changed {
                                ORANGE
                            } else {
                                GREEN
                            }),
                    );
                    if !comparison.new_root_causes.is_empty() {
                        ui.label(
                            RichText::new(format!(
                                "{}: {}",
                                tr(self.language, Text::RootCauses),
                                comparison.new_root_causes.join(", ")
                            ))
                            .size(12.0)
                            .color(ORANGE),
                        );
                    }
                });
            });
            ui.add_space(8.0);
        }
        for entry in history {
            ui.group(|ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!("{}  {}", short_run_id(&entry.run_id), entry.sample))
                            .size(13.0)
                            .strong()
                            .color(INK),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{}: {}",
                            tr(self.language, Text::ReviewState),
                            entry.status
                        ))
                        .size(12.0)
                        .color(MUTED),
                    );
                    ui.label(
                        RichText::new(entry.created_at.format("%Y-%m-%d %H:%M:%S").to_string())
                            .size(12.0)
                            .color(MUTED),
                    );
                });
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "{}: {}",
                            tr(self.language, Text::RootCauses),
                            if entry.root_causes.is_empty() {
                                "normal".to_string()
                            } else {
                                entry.root_causes.join(", ")
                            }
                        ))
                        .size(12.0)
                        .color(INK),
                    );
                    if let Some(label) = &entry.ml_top_label {
                        ui.label(
                            RichText::new(format!(
                                "ML: {} ({:.2})",
                                label,
                                entry.ml_top_probability.unwrap_or_default()
                            ))
                            .size(12.0)
                            .color(MUTED),
                        );
                    }
                    if let Some(kind) = &entry.model_kind {
                        ui.label(
                            RichText::new(format!(
                                "{}: {}{}",
                                tr(self.language, Text::ModelType),
                                kind,
                                if entry.synthetic_model {
                                    format!(" / {}", tr(self.language, Text::SyntheticModel))
                                } else {
                                    String::new()
                                }
                            ))
                            .size(12.0)
                            .color(MUTED),
                        );
                    }
                });
                let counts = metric_quality_counts_from_provenance(&entry.measurement_quality);
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "{}: measured={} estimated={} fallback={} missing={}",
                            tr(self.language, Text::MeasurementQuality),
                            counts.measured,
                            counts.estimated,
                            counts.fallback,
                            counts.missing
                        ))
                        .size(12.0)
                        .color(if counts.fallback + counts.missing == 0 {
                            GREEN
                        } else {
                            ORANGE
                        }),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{}: {}",
                            tr(self.language, Text::ArtifactFiles),
                            entry.artifact_count
                        ))
                        .size(12.0)
                        .color(MUTED),
                    );
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let run_dir = PathBuf::from(&entry.run_dir);
                    if soft_button(ui, tr(self.language, Text::OpenReport)).clicked()
                        && let Err(err) = open_path(&run_dir.join("report.json"))
                    {
                        self.settings_notice =
                            Some(format!("{}: {err}", tr(self.language, Text::OpenFailed)));
                    }
                    if soft_button(ui, tr(self.language, Text::OpenRunFolder)).clicked()
                        && let Err(err) = open_path(&run_dir)
                    {
                        self.settings_notice =
                            Some(format!("{}: {err}", tr(self.language, Text::OpenFailed)));
                    }
                });
            });
            ui.add_space(8.0);
        }
    }

    fn render_settings_page(&mut self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            section_title(ui, title_for_tab(Tab::Settings, self.language));
            ui.add_space(10.0);
            if let Some(notice) = &self.settings_notice {
                ui.label(RichText::new(notice).size(12.0).color(MUTED));
            }
            if let Some(status) = &self.api_test_status {
                ui.label(RichText::new(status).size(12.0).color(MUTED));
            }
            ui.add_space(12.0);

            self.render_general_settings(ui);
            settings_separator(ui);
            self.render_data_source_settings(ui);
            settings_separator(ui);
            self.render_data_connector_settings(ui);
            settings_separator(ui);
            self.render_live_api_settings(ui);
            settings_separator(ui);
            self.render_digital_twin_settings(ui);
            settings_separator(ui);
            self.render_artifact_settings(ui);
            settings_separator(ui);
            self.render_diagnosis_review_settings(ui);
            settings_separator(ui);
            self.render_privacy_about_settings(ui);
        });
    }

    fn render_general_settings(&mut self, ui: &mut egui::Ui) {
        section_title(ui, tr(self.language, Text::General));
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            setting_caption(ui, tr(self.language, Text::SettingsLanguage));
            if soft_button(ui, self.language.switch_label()).clicked() {
                self.set_language(self.language.toggle());
            }
        });
        ui.horizontal(|ui| {
            setting_caption(ui, tr(self.language, Text::StartupDefaultPage));
            let mut changed = false;
            egui::ComboBox::from_id_salt("startup_default_page")
                .selected_text(startup_tab_label(
                    self.settings.startup.default_tab,
                    self.language,
                ))
                .show_ui(ui, |ui| {
                    for tab in StartupTab::ALL {
                        changed |= ui
                            .selectable_value(
                                &mut self.settings.startup.default_tab,
                                tab,
                                startup_tab_label(tab, self.language),
                            )
                            .changed();
                    }
                });
            if changed {
                self.persist_settings();
            }
        });
        let changed = ui
            .checkbox(
                &mut self.settings.startup.auto_run_diagnosis,
                tr(self.language, Text::AutoRunDiagnosis),
            )
            .changed();
        if changed {
            self.persist_settings();
        }
    }

    fn render_data_source_settings(&mut self, ui: &mut egui::Ui) {
        section_title(ui, tr(self.language, Text::DataSources));
        ui.add_space(8.0);
        let mut source_changed = false;
        ui.horizontal(|ui| {
            setting_caption(ui, tr(self.language, Text::DefaultDataSource));
            egui::ComboBox::from_id_salt("default_data_source")
                .selected_text(default_source_label(
                    self.settings.default_source,
                    self.language,
                ))
                .show_ui(ui, |ui| {
                    for source in DefaultSource::ALL {
                        source_changed |= ui
                            .selectable_value(
                                &mut self.settings.default_source,
                                source,
                                default_source_label(source, self.language),
                            )
                            .changed();
                    }
                });
        });

        let mut scenario_changed = false;
        ui.horizontal(|ui| {
            setting_caption(ui, tr(self.language, Text::SimulationScenario));
            egui::ComboBox::from_id_salt("simulation_scenario")
                .selected_text(sim_scenario_label(
                    self.settings.simulation_scenario,
                    self.language,
                ))
                .show_ui(ui, |ui| {
                    for scenario in SimScenario::ALL {
                        scenario_changed |= ui
                            .selectable_value(
                                &mut self.settings.simulation_scenario,
                                scenario,
                                sim_scenario_label(scenario, self.language),
                            )
                            .changed();
                    }
                });
        });
        ui.label(
            RichText::new(format!(
                "{}: {}",
                tr(self.language, Text::LastImportedTrace),
                self.settings
                    .last_imported_trace
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| tr(self.language, Text::NotAvailable).to_string())
            ))
            .size(12.0)
            .color(MUTED),
        );
        if source_changed || scenario_changed {
            self.simulation_scenario = self.settings.simulation_scenario;
            self.persist_settings();
            let (source_mode, warning) =
                source_mode_from_settings(&self.settings, self.secrets.as_ref());
            self.source_mode = source_mode;
            if warning.is_some() {
                self.settings_notice = warning;
            }
            self.run_diagnosis();
        }
    }

    fn render_live_api_settings(&mut self, ui: &mut egui::Ui) {
        section_title(ui, tr(self.language, Text::LiveApiConnection));
        ui.add_space(8.0);
        let mut changed = false;
        ui.horizontal(|ui| {
            setting_caption(ui, tr(self.language, Text::ApiUrl));
            changed |= ui
                .add(
                    egui::TextEdit::singleline(&mut self.settings.api.endpoint)
                        .desired_width(360.0),
                )
                .changed();
        });
        ui.horizontal(|ui| {
            setting_caption(ui, tr(self.language, Text::RequestTimeout));
            changed |= ui
                .add(
                    egui::DragValue::new(&mut self.settings.api.timeout_secs)
                        .range(1..=120)
                        .suffix(" s"),
                )
                .changed();
        });
        if changed {
            self.persist_settings();
        }

        let env_token = std::env::var(settings::NETDIAG_API_TOKEN_ENV)
            .ok()
            .is_some_and(|token| !token.trim().is_empty());
        let (token_status, token_color) = match self.secrets.has_live_api_token() {
            Ok(keychain_token) => (
                format!(
                    "{}: {}{}",
                    tr(self.language, Text::TokenStatus),
                    if keychain_token {
                        tr(self.language, Text::ApiSet)
                    } else {
                        tr(self.language, Text::ApiUnset)
                    },
                    if env_token {
                        tr(self.language, Text::EnvFallback)
                    } else {
                        ""
                    }
                ),
                MUTED,
            ),
            Err(err) => (
                format!("{}: {err}", tr(self.language, Text::KeychainError)),
                RED,
            ),
        };
        ui.label(RichText::new(token_status).size(12.0).color(token_color));
        ui.horizontal(|ui| {
            setting_caption(ui, tr(self.language, Text::KeychainProtection));
            ui.add(
                egui::TextEdit::singleline(&mut self.token_input)
                    .password(true)
                    .desired_width(220.0),
            );
            if soft_button(ui, tr(self.language, Text::SaveToken)).clicked() {
                match self.secrets.set_live_api_token(self.token_input.trim()) {
                    Ok(()) => {
                        self.token_input.clear();
                        self.pending_delete_token = false;
                        self.settings_notice = Some(tr(self.language, Text::Saved).to_string());
                    }
                    Err(err) => self.settings_notice = Some(err.to_string()),
                }
            }
            let delete_label = if self.pending_delete_token {
                tr(self.language, Text::ConfirmDeleteToken)
            } else {
                tr(self.language, Text::DeleteToken)
            };
            if soft_button(ui, delete_label).clicked() {
                if self.pending_delete_token {
                    match self.secrets.delete_live_api_token() {
                        Ok(()) => {
                            self.pending_delete_token = false;
                            self.settings_notice = Some(tr(self.language, Text::Saved).to_string());
                        }
                        Err(err) => self.settings_notice = Some(err.to_string()),
                    }
                } else {
                    self.pending_delete_token = true;
                }
            }
            let testing = self.api_test_job.is_some();
            let test_label = if testing {
                tr(self.language, Text::TestingConnection)
            } else {
                tr(self.language, Text::TestConnection)
            };
            let test_button = egui::Button::new(RichText::new(test_label).size(13.0).color(INK))
                .fill(Color32::from_white_alpha(130))
                .stroke(Stroke::new(1.0, Color32::from_white_alpha(140)))
                .corner_radius(8);
            if ui.add_enabled(!testing, test_button).clicked() {
                self.start_api_test_connection();
            }
        });
    }

    fn render_data_connector_settings(&mut self, ui: &mut egui::Ui) {
        section_title(ui, tr(self.language, Text::DataConnectors));
        ui.add_space(8.0);
        let mut changed = false;
        self.settings.data_connectors.ensure_profiles();
        ui.horizontal(|ui| {
            setting_caption(ui, tr(self.language, Text::SourceProfile));
            let selected_name = self
                .settings
                .data_connectors
                .active_profile()
                .map(|profile| profile.name.clone())
                .unwrap_or_else(|| tr(self.language, Text::NotAvailable).to_string());
            egui::ComboBox::from_id_salt("source_profile")
                .selected_text(selected_name)
                .show_ui(ui, |ui| {
                    for profile in &self.settings.data_connectors.profiles {
                        changed |= ui
                            .selectable_value(
                                &mut self.settings.data_connectors.active_profile_id,
                                profile.id.clone(),
                                &profile.name,
                            )
                            .changed();
                    }
                });
        });
        let active_profile_id = self.settings.data_connectors.active_profile_id.clone();
        let Some(profile_index) = self
            .settings
            .data_connectors
            .profiles
            .iter()
            .position(|profile| profile.id == active_profile_id)
        else {
            return;
        };
        let active_kind = {
            let profile = &mut self.settings.data_connectors.profiles[profile_index];
            ui.horizontal(|ui| {
                setting_caption(ui, tr(self.language, Text::ProfileName));
                changed |= ui
                    .add(egui::TextEdit::singleline(&mut profile.name).desired_width(260.0))
                    .changed();
            });
            ui.horizontal(|ui| {
                setting_caption(ui, tr(self.language, Text::ConnectorKind));
                egui::ComboBox::from_id_salt("profile_connector_kind")
                    .selected_text(connector_kind_label(profile.kind, self.language))
                    .show_ui(ui, |ui| {
                        for connector in ConnectorKind::ALL {
                            changed |= ui
                                .selectable_value(
                                    &mut profile.kind,
                                    connector,
                                    connector_kind_label(connector, self.language),
                                )
                                .changed();
                        }
                    });
            });
            match profile.kind {
                ConnectorKind::LocalProbe => {
                    ui.horizontal(|ui| {
                        setting_caption(ui, tr(self.language, Text::ProbeSamples));
                        changed |= ui
                            .add(
                                egui::DragValue::new(&mut profile.local_probe.samples)
                                    .range(1..=20),
                            )
                            .changed();
                    });
                }
                ConnectorKind::WebsiteProbe => {
                    ui.horizontal(|ui| {
                        setting_caption(ui, tr(self.language, Text::ProbeSamples));
                        changed |= ui
                            .add(
                                egui::DragValue::new(&mut profile.website_probe.samples_per_target)
                                    .range(1..=12),
                            )
                            .changed();
                    });
                    ui.horizontal(|ui| {
                        setting_caption(ui, tr(self.language, Text::ProbeTargets));
                        if self.probe_targets_text.is_empty() {
                            self.probe_targets_text = profile.website_probe.targets.join("\n");
                        }
                        let response = ui.add(
                            egui::TextEdit::multiline(&mut self.probe_targets_text)
                                .desired_rows(3)
                                .desired_width(420.0),
                        );
                        if response.changed() {
                            let targets = self
                                .probe_targets_text
                                .lines()
                                .map(str::trim)
                                .filter(|line| !line.is_empty())
                                .map(str::to_owned)
                                .collect::<Vec<_>>();
                            if !targets.is_empty() {
                                profile.website_probe.targets = targets;
                                changed = true;
                            }
                        }
                    });
                }
                ConnectorKind::HttpJson => {
                    ui.label(
                        RichText::new(tr(self.language, Text::HttpJsonConnectorHint))
                            .size(12.0)
                            .color(MUTED),
                    );
                    ui.horizontal(|ui| {
                        setting_caption(ui, tr(self.language, Text::ApiUrl));
                        changed |= ui
                            .add(
                                egui::TextEdit::singleline(&mut profile.http_json.endpoint)
                                    .desired_width(420.0),
                            )
                            .changed();
                    });
                    ui.horizontal(|ui| {
                        setting_caption(ui, tr(self.language, Text::RequestTimeout));
                        changed |= ui
                            .add(
                                egui::DragValue::new(&mut profile.http_json.timeout_secs)
                                    .range(1..=120),
                            )
                            .changed();
                    });
                }
                ConnectorKind::PrometheusQueryRange => {
                    ui.horizontal(|ui| {
                        setting_caption(ui, tr(self.language, Text::PrometheusBaseUrl));
                        changed |= ui
                            .add(
                                egui::TextEdit::singleline(&mut profile.prometheus_query.base_url)
                                    .desired_width(420.0),
                            )
                            .changed();
                    });
                    ui.horizontal(|ui| {
                        setting_caption(ui, tr(self.language, Text::PrometheusLookback));
                        changed |= ui
                            .add(
                                egui::DragValue::new(
                                    &mut profile.prometheus_query.lookback_seconds,
                                )
                                .range(10..=86_400),
                            )
                            .changed();
                        setting_caption(ui, tr(self.language, Text::PrometheusStep));
                        changed |= ui
                            .add(
                                egui::DragValue::new(&mut profile.prometheus_query.step_seconds)
                                    .range(1..=3_600),
                            )
                            .changed();
                    });
                }
                ConnectorKind::PrometheusExposition => {
                    ui.horizontal(|ui| {
                        setting_caption(ui, tr(self.language, Text::PrometheusMetricsEndpoint));
                        changed |= ui
                            .add(
                                egui::TextEdit::singleline(
                                    &mut profile.prometheus_exposition.endpoint,
                                )
                                .desired_width(420.0),
                            )
                            .changed();
                    });
                }
                ConnectorKind::OtlpGrpcReceiver => {
                    ui.horizontal(|ui| {
                        setting_caption(ui, tr(self.language, Text::OtlpBindAddr));
                        changed |= ui
                            .add(
                                egui::TextEdit::singleline(&mut profile.otlp_grpc.bind_addr)
                                    .desired_width(260.0),
                            )
                            .changed();
                    });
                    ui.horizontal(|ui| {
                        setting_caption(ui, tr(self.language, Text::RequestTimeout));
                        changed |= ui
                            .add(
                                egui::DragValue::new(&mut profile.otlp_grpc.timeout_secs)
                                    .range(1..=120),
                            )
                            .changed();
                    });
                }
                ConnectorKind::NativePcap => {
                    ui.horizontal(|ui| {
                        setting_caption(ui, tr(self.language, Text::CaptureSource));
                        changed |= ui
                            .add(
                                egui::TextEdit::singleline(&mut profile.native_pcap.source)
                                    .desired_width(260.0),
                            )
                            .changed();
                    });
                    ui.horizontal(|ui| {
                        setting_caption(ui, tr(self.language, Text::PacketLimit));
                        changed |= ui
                            .add(
                                egui::DragValue::new(&mut profile.native_pcap.packet_limit)
                                    .range(1..=10_000),
                            )
                            .changed();
                        setting_caption(ui, tr(self.language, Text::CaptureTimeout));
                        changed |= ui
                            .add(
                                egui::DragValue::new(&mut profile.native_pcap.timeout_secs)
                                    .range(1..=120),
                            )
                            .changed();
                    });
                }
                ConnectorKind::SystemCounters => {
                    ui.horizontal(|ui| {
                        setting_caption(ui, tr(self.language, Text::SystemInterface));
                        changed |= ui
                            .add(
                                egui::TextEdit::singleline(&mut profile.system_counters.interface)
                                    .desired_width(220.0),
                            )
                            .changed();
                        setting_caption(ui, tr(self.language, Text::SamplingInterval));
                        changed |= ui
                            .add(
                                egui::DragValue::new(&mut profile.system_counters.interval_secs)
                                    .range(1..=10),
                            )
                            .changed();
                    });
                }
            }
            profile.kind
        };
        let testing = self.api_test_job.is_some();
        let test_label = if testing {
            tr(self.language, Text::TestingConnection)
        } else {
            tr(self.language, Text::TestConnection)
        };
        let test_button = egui::Button::new(RichText::new(test_label).size(13.0).color(INK))
            .fill(Color32::from_white_alpha(130))
            .stroke(Stroke::new(1.0, Color32::from_white_alpha(140)))
            .corner_radius(8);
        if ui.add_enabled(!testing, test_button).clicked() {
            self.start_api_test_connection();
        }
        if matches!(
            active_kind,
            ConnectorKind::OtlpGrpcReceiver
                | ConnectorKind::NativePcap
                | ConnectorKind::SystemCounters
        ) {
            ui.add_space(8.0);
            self.render_capture_session_controls(ui, active_kind);
        }
        ui.add_space(10.0);
        self.render_connector_health_panel(ui);
        if changed {
            self.settings.data_connectors.default_connector = active_kind;
            self.persist_settings();
            let (source_mode, warning) =
                source_mode_from_settings(&self.settings, self.secrets.as_ref());
            self.source_mode = source_mode;
            if warning.is_some() {
                self.settings_notice = warning;
            }
        }
    }

    fn render_capture_session_controls(&mut self, ui: &mut egui::Ui, active_kind: ConnectorKind) {
        section_title(ui, tr(self.language, Text::CaptureSession));
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            let running = self
                .capture_session
                .as_ref()
                .is_some_and(|session| session.phase.is_active());
            let session_matches = self
                .capture_session
                .as_ref()
                .is_some_and(|session| session.kind == active_kind);
            let has_last_sample = self.capture_session.as_ref().is_some_and(|session| {
                session.kind == active_kind && session.last_sample.is_some()
            });
            let start_label = if active_kind == ConnectorKind::OtlpGrpcReceiver {
                tr(self.language, Text::StartReceiver)
            } else {
                tr(self.language, Text::StartCapture)
            };
            let start = egui::Button::new(RichText::new(start_label).size(13.0).color(INK))
                .fill(Color32::from_white_alpha(130))
                .stroke(Stroke::new(1.0, Color32::from_white_alpha(140)))
                .corner_radius(8);
            if ui.add_enabled(!running, start).clicked() {
                self.start_capture_session(active_kind);
            }
            let diagnose = egui::Button::new(
                RichText::new(
                    if active_kind == ConnectorKind::OtlpGrpcReceiver && running {
                        tr(self.language, Text::DiagnoseBuffer)
                    } else {
                        tr(self.language, Text::DiagnoseLastSample)
                    },
                )
                .size(13.0)
                .color(INK),
            )
            .fill(Color32::from_white_alpha(130))
            .stroke(Stroke::new(1.0, Color32::from_white_alpha(140)))
            .corner_radius(8);
            if ui
                .add_enabled(
                    session_matches
                        && self.diagnosis_job.is_none()
                        && (has_last_sample
                            || (active_kind == ConnectorKind::OtlpGrpcReceiver && running)),
                    diagnose,
                )
                .clicked()
            {
                self.diagnose_capture_last_sample();
            }
            let stop = egui::Button::new(
                RichText::new(if active_kind == ConnectorKind::OtlpGrpcReceiver {
                    tr(self.language, Text::StopReceiver)
                } else {
                    tr(self.language, Text::CancelCapture)
                })
                .size(13.0)
                .color(INK),
            )
            .fill(Color32::from_white_alpha(130))
            .stroke(Stroke::new(1.0, Color32::from_white_alpha(140)))
            .corner_radius(8);
            if ui.add_enabled(session_matches && running, stop).clicked() {
                self.cancel_capture_session();
            }
        });
        if let Some(session) = &self.capture_session {
            if session.kind == active_kind {
                ui.label(RichText::new(&session.status).size(12.0).color(MUTED));
                if let Some(progress) = &session.progress {
                    ui.label(
                        RichText::new(format!(
                            "{}: {}",
                            tr(self.language, Text::CaptureProgress),
                            format_capture_progress(progress)
                        ))
                        .size(12.0)
                        .color(MUTED),
                    );
                }
                if let Some(sample) = &session.last_sample {
                    ui.label(
                        RichText::new(format!(
                            "{}: {} {} · {}",
                            tr(self.language, Text::LastSample),
                            sample.ingest.records.len(),
                            tr(self.language, Text::Rows),
                            sample.descriptor.captured_label
                        ))
                        .size(12.0)
                        .color(MUTED),
                    );
                }
            } else if session.phase.is_active() {
                ui.label(
                    RichText::new(format!(
                        "{}: {}",
                        tr(self.language, Text::CaptureRunning),
                        connector_kind_label(session.kind, self.language)
                    ))
                    .size(12.0)
                    .color(MUTED),
                );
            }
        }
    }

    fn render_connector_health_panel(&self, ui: &mut egui::Ui) {
        section_title(ui, tr(self.language, Text::ConnectorHealth));
        ui.add_space(6.0);
        let Some(snapshot) = &self.source_snapshot else {
            ui.label(
                RichText::new(tr(self.language, Text::NoSource))
                    .size(12.0)
                    .color(MUTED),
            );
            return;
        };
        let counts = metric_quality_counts(snapshot);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!(
                    "{}: {}",
                    tr(self.language, Text::Rows),
                    snapshot.ingest.schema.rows
                ))
                .size(12.0)
                .color(MUTED),
            );
            ui.label(
                RichText::new(format!(
                    "{}: {}",
                    tr(self.language, Text::ValidationWarnings),
                    snapshot.ingest.warnings.len()
                ))
                .size(12.0)
                .color(if snapshot.ingest.warnings.is_empty() {
                    GREEN
                } else {
                    ORANGE
                }),
            );
            ui.label(
                RichText::new(format!(
                    "{}: {}",
                    tr(self.language, Text::LastSample),
                    snapshot.ingest.schema.end_time.format("%H:%M:%S")
                ))
                .size(12.0)
                .color(MUTED),
            );
        });
        ui.label(
            RichText::new(format!(
                "{}: measured={} estimated={} fallback={} missing={}",
                tr(self.language, Text::MeasurementQuality),
                counts.measured,
                counts.estimated,
                counts.fallback,
                counts.missing
            ))
            .size(12.0)
            .color(if counts.fallback + counts.missing == 0 {
                GREEN
            } else {
                ORANGE
            }),
        );
        let missing = snapshot
            .ingest
            .metric_provenance
            .iter()
            .filter(|item| {
                matches!(
                    item.quality,
                    MetricQuality::Fallback | MetricQuality::Missing
                )
            })
            .map(|item| item.field.as_str())
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            ui.label(
                RichText::new(format!(
                    "{}: {}",
                    tr(self.language, Text::MissingMetrics),
                    missing.join(", ")
                ))
                .size(12.0)
                .color(MUTED),
            );
        }
    }

    fn render_digital_twin_settings(&mut self, ui: &mut egui::Ui) {
        section_title(ui, tr(self.language, Text::DigitalTwinDefaults));
        ui.add_space(8.0);
        let mut changed = false;
        ui.horizontal(|ui| {
            setting_caption(ui, tr(self.language, Text::Topology));
            egui::ComboBox::from_id_salt("whatif_topology")
                .selected_text(topology_display(self.settings.what_if.topology.as_str()))
                .show_ui(ui, |ui| {
                    for topology in topology_names() {
                        changed |= ui
                            .selectable_value(
                                &mut self.settings.what_if.topology,
                                topology.to_string(),
                                topology_display(topology),
                            )
                            .changed();
                    }
                    if self.settings.what_if.custom_topology.is_some() {
                        changed |= ui
                            .selectable_value(
                                &mut self.settings.what_if.topology,
                                "custom".to_string(),
                                tr(self.language, Text::CustomTopology),
                            )
                            .changed();
                    }
                });
        });
        ui.horizontal(|ui| {
            setting_caption(ui, tr(self.language, Text::Action));
            egui::ComboBox::from_id_salt("whatif_action")
                .selected_text(action_display(self.settings.what_if.action.as_str()))
                .show_ui(ui, |ui| {
                    for action in action_names() {
                        changed |= ui
                            .selectable_value(
                                &mut self.settings.what_if.action,
                                action.to_string(),
                                action_display(action),
                            )
                            .changed();
                    }
                });
        });
        ui.horizontal(|ui| {
            if soft_button(ui, tr(self.language, Text::ImportTopology)).clicked() {
                self.import_topology();
            }
            if soft_button(ui, tr(self.language, Text::ExportTopology)).clicked() {
                self.export_topology();
            }
        });
        if let Some(topology) = &self.settings.what_if.custom_topology {
            ui.label(
                RichText::new(format!(
                    "{}: {} · {} nodes · {} links",
                    tr(self.language, Text::CustomTopology),
                    topology.name,
                    topology.nodes.len(),
                    topology.links.len()
                ))
                .size(12.0)
                .color(MUTED),
            );
        }
        if changed {
            self.topology.clone_from(&self.settings.what_if.topology);
            self.custom_topology = self.settings.what_if.custom_topology.clone();
            self.action.clone_from(&self.settings.what_if.action);
            self.persist_settings();
            self.run_diagnosis();
        }
    }

    fn render_artifact_settings(&mut self, ui: &mut egui::Ui) {
        section_title(ui, tr(self.language, Text::DataArtifacts));
        ui.add_space(8.0);
        ui.label(
            RichText::new(format!(
                "{}: {}",
                tr(self.language, Text::ArtifactRoot),
                self.settings.artifacts_root.display()
            ))
            .size(12.0)
            .color(MUTED),
        );
        ui.horizontal(|ui| {
            if soft_button(ui, tr(self.language, Text::ChooseFolder)).clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .set_directory(&self.settings.artifacts_root)
                    .pick_folder()
            {
                self.settings.artifacts_root = path.clone();
                self.artifacts_root = path;
                self.persist_settings();
                self.run_diagnosis();
            }
            if soft_button(ui, tr(self.language, Text::OpenFolder)).clicked() {
                let path = self.settings.artifacts_root.clone();
                self.open_path_with_notice(&path);
            }
            let clear_label = if self.pending_clear_runs {
                tr(self.language, Text::ConfirmClearRunHistory)
            } else {
                tr(self.language, Text::ClearRunHistory)
            };
            if soft_button(ui, clear_label).clicked() {
                if self.pending_clear_runs {
                    self.clear_run_history();
                } else {
                    self.pending_clear_runs = true;
                }
            }
        });
        ui.label(
            RichText::new(format!(
                "{}: {}",
                tr(self.language, Text::ModelCache),
                model_cache_status(&self.settings.artifacts_root, self.language)
            ))
            .size(12.0)
            .color(MUTED),
        );
        let rebuild_label = if self.pending_rebuild_model {
            tr(self.language, Text::ConfirmRebuildModel)
        } else {
            tr(self.language, Text::RebuildModel)
        };
        if soft_button(ui, rebuild_label).clicked() {
            if self.pending_rebuild_model {
                self.rebuild_model_cache();
            } else {
                self.pending_rebuild_model = true;
            }
        }
    }

    fn render_diagnosis_review_settings(&self, ui: &mut egui::Ui) {
        section_title(ui, tr(self.language, Text::DiagnosisReview));
        ui.add_space(8.0);
        bullet(ui, tr(self.language, Text::RulePolicy), BLUE);
        bullet(ui, tr(self.language, Text::MlPolicy), PURPLE);
        bullet(ui, tr(self.language, Text::HilPolicy), GREEN);
    }

    fn render_privacy_about_settings(&mut self, ui: &mut egui::Ui) {
        section_title(ui, tr(self.language, Text::PrivacyAbout));
        ui.add_space(8.0);
        bullet(ui, tr(self.language, Text::LocalProcessing), GREEN);
        bullet(ui, tr(self.language, Text::KeychainProtection), BLUE);
        ui.label(
            RichText::new(format!(
                "{}: {}",
                tr(self.language, Text::SettingsFile),
                self.settings_store.path().display()
            ))
            .size(12.0)
            .color(MUTED),
        );
        ui.label(
            RichText::new(format!(
                "{}: com.netdiag.twin  ·  {}: {}",
                tr(self.language, Text::BundleId),
                tr(self.language, Text::Version),
                env!("CARGO_PKG_VERSION")
            ))
            .size(12.0)
            .color(MUTED),
        );
        if self.result.is_some() && soft_button(ui, tr(self.language, Text::OpenReport)).clicked() {
            self.open_current_report();
        }
        if soft_button(ui, tr(self.language, Text::CheckForUpdates)).clicked() {
            self.check_for_updates();
        }
        ui.label(
            RichText::new(format!(
                "{}: {}",
                tr(self.language, Text::UpdateStatus),
                sparkle_status()
            ))
            .size(12.0)
            .color(MUTED),
        );
    }

    fn check_for_updates(&mut self) {
        match sparkle_check_for_updates() {
            Ok(UpdateCheckOutcome::NativeDialogOpened) => {
                let message = tr(self.language, Text::UpdateDialogOpened).to_string();
                self.update_notice = Some(message.clone());
                self.settings_notice = Some(message);
                self.error = None;
            }
            Ok(UpdateCheckOutcome::FeedReachable { feed_url }) => {
                let message = format!(
                    "{}: {feed_url}",
                    tr(self.language, Text::UpdateFeedReachable)
                );
                self.update_notice = Some(message.clone());
                self.settings_notice = Some(message);
                self.error = None;
            }
            Err(err) => {
                self.update_notice = Some(err.clone());
                self.settings_notice = Some(err);
            }
        }
    }

    fn open_path_with_notice(&mut self, path: &Path) {
        if let Err(err) = open_path(path) {
            self.settings_notice = Some(format!("{}: {err}", tr(self.language, Text::OpenFailed)));
        }
    }

    fn open_current_report(&mut self) {
        let Some(path) = self
            .result
            .as_ref()
            .map(|result| result.run_dir.join("report.json"))
        else {
            self.settings_notice = Some(tr(self.language, Text::NotAvailable).to_string());
            return;
        };
        self.open_path_with_notice(&path);
    }

    fn open_current_run_folder(&mut self) {
        let Some(path) = self.result.as_ref().map(|result| result.run_dir.clone()) else {
            self.settings_notice = Some(tr(self.language, Text::NotAvailable).to_string());
            return;
        };
        self.open_path_with_notice(&path);
    }

    fn import_topology(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Topology JSON", &["json"])
            .pick_file()
        else {
            return;
        };
        match fs::read_to_string(&path)
            .map_err(anyhow::Error::from)
            .and_then(|raw| {
                serde_json::from_str::<TopologyModel>(&raw).map_err(anyhow::Error::from)
            })
            .and_then(|model| {
                validate_topology_model(&model).map_err(anyhow::Error::from)?;
                Ok(model)
            }) {
            Ok(model) => {
                self.settings.what_if.topology = "custom".to_string();
                self.settings.what_if.custom_topology = Some(model.clone());
                self.topology = "custom".to_string();
                self.custom_topology = Some(model);
                self.persist_settings();
                self.run_diagnosis();
            }
            Err(err) => {
                self.settings_notice =
                    Some(format!("{}: {err}", tr(self.language, Text::OpenFailed)));
            }
        }
    }

    fn export_topology(&mut self) {
        let topology = if self.topology == "custom" {
            self.custom_topology.clone()
        } else {
            topology_model(self.topology.as_str()).ok()
        };
        let Some(topology) = topology else {
            self.settings_notice = Some(tr(self.language, Text::NotAvailable).to_string());
            return;
        };
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("{}_topology.json", topology.key))
            .save_file()
        else {
            return;
        };
        match serde_json::to_vec_pretty(&topology)
            .map_err(anyhow::Error::from)
            .and_then(|raw| fs::write(&path, raw).map_err(anyhow::Error::from))
        {
            Ok(()) => self.settings_notice = Some(tr(self.language, Text::Saved).to_string()),
            Err(err) => {
                self.settings_notice =
                    Some(format!("{}: {err}", tr(self.language, Text::OpenFailed)));
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn open_help_document(&mut self) {
        let help_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../README.md");
        if help_path.exists() {
            self.open_path_with_notice(&help_path);
        } else {
            self.tab = Tab::Settings;
            self.settings_notice = Some(tr(self.language, Text::NotAvailable).to_string());
        }
    }

    fn apply_hil_review(&mut self, recommendation_id: &str, state: HilState) {
        let Some(result) = &self.result else {
            return;
        };
        let run_id = result.run_id.clone();
        let artifact_root =
            artifact_root_for_result(result).unwrap_or_else(|| self.artifacts_root.clone());
        let notes = self
            .hil_notes
            .get(recommendation_id)
            .cloned()
            .unwrap_or_default();
        match review_recommendation(
            artifact_root,
            &run_id,
            recommendation_id,
            state,
            &notes,
            tr(self.language, Text::EngineerRole),
            None,
        ) {
            Ok(outcome) => {
                if let Some(result) = &mut self.result {
                    result.recommendations = outcome.recommendations.clone();
                    result.report.recommendations = outcome.recommendations;
                    result.report.hil_summary =
                        HilReviewSummary::from_recommendations(&result.report.recommendations);
                    self.status = status_for_result(result).to_string();
                }
                self.settings_notice = Some(format!(
                    "{}: {}",
                    tr(self.language, Text::Saved),
                    hil_state_display(outcome.review.state, self.language)
                ));
            }
            Err(err) => {
                self.settings_notice = Some(err.to_string());
            }
        }
    }

    fn clear_run_history(&mut self) {
        let runs_dir = self.settings.artifacts_root.join("runs");
        let index_path = self.settings.artifacts_root.join("run_index.json");
        let result = (|| -> std::io::Result<()> {
            if runs_dir.exists() {
                fs::remove_dir_all(&runs_dir)?;
            }
            if index_path.exists() {
                fs::remove_file(&index_path)?;
            }
            Ok(())
        })();
        self.pending_clear_runs = false;
        self.settings_notice = Some(match result {
            Ok(()) => tr(self.language, Text::Saved).to_string(),
            Err(err) => err.to_string(),
        });
    }

    fn rebuild_model_cache(&mut self) {
        let model_dir = self.settings.artifacts_root.join("model");
        let model_file = model_dir.join("rust_logistic_model.json");
        if model_file.exists()
            && let Err(err) = fs::remove_file(&model_file)
        {
            self.settings_notice = Some(err.to_string());
            self.pending_rebuild_model = false;
            return;
        }
        match load_or_train_model(&model_dir) {
            Ok(_) => {
                self.settings_notice = Some(tr(self.language, Text::Saved).to_string());
                self.pending_rebuild_model = false;
                self.run_diagnosis();
            }
            Err(err) => {
                self.settings_notice = Some(err.to_string());
                self.pending_rebuild_model = false;
            }
        }
    }

    fn render_header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(title_for_tab(self.tab, self.language))
                        .size(28.0)
                        .strong()
                        .color(INK),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new(tr(self.language, Text::Subtitle))
                        .size(14.0)
                        .color(MUTED),
                );
                if let Some(error) = &self.error {
                    ui.add_space(4.0);
                    ui.label(RichText::new(error).size(12.0).color(RED));
                }
                if let Some(notice) = &self.update_notice {
                    ui.add_space(4.0);
                    ui.label(RichText::new(notice).size(12.0).color(BLUE));
                }
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let is_running = self.diagnosis_job.is_some();
                let new_label = if is_running {
                    tr(self.language, Text::Running)
                } else {
                    tr(self.language, Text::NewAnalysis)
                };
                if action_button(ui, new_label, true, !is_running).clicked() {
                    self.run_diagnosis();
                }
                ui.add_space(10.0);
                if action_button(ui, self.live_api_action_label(), false, !is_running).clicked() {
                    self.run_live_api();
                }
                ui.add_space(10.0);
                self.simulation_menu_button(ui, !is_running);
                ui.add_space(10.0);
                if action_button(ui, tr(self.language, Text::ImportTrace), false, !is_running)
                    .clicked()
                {
                    self.import_trace();
                }
                ui.add_space(10.0);
                if action_button(ui, self.language.switch_label(), false, true).clicked() {
                    self.set_language(self.language.toggle());
                }
            });
        });
    }

    fn simulation_menu_button(&mut self, ui: &mut egui::Ui, enabled: bool) {
        let button = egui::Button::new(
            RichText::new(tr(self.language, Text::Simulate))
                .size(15.0)
                .strong(),
        )
        .fill(Color32::from_white_alpha(if enabled { 150 } else { 80 }))
        .stroke(Stroke::new(1.0, Color32::from_white_alpha(150)))
        .corner_radius(12)
        .min_size(Vec2::new(HEADER_ACTION_WIDTH, HEADER_ACTION_HEIGHT));
        ui.add_enabled_ui(enabled, |ui| {
            #[allow(deprecated)]
            egui::menu::menu_custom_button(ui, button, |ui| {
                for scenario in SimScenario::ALL {
                    if ui
                        .selectable_label(
                            self.settings.simulation_scenario == scenario,
                            sim_scenario_label(scenario, self.language),
                        )
                        .clicked()
                    {
                        self.settings.simulation_scenario = scenario;
                        self.simulation_scenario = scenario;
                        self.settings.default_source = DefaultSource::Simulation;
                        self.persist_settings();
                        self.run_simulation();
                        ui.close();
                    }
                }
            });
        });
    }

    fn live_api_action_label(&self) -> &'static str {
        if self.settings.data_connectors.default_connector == ConnectorKind::HttpJson
            && self.settings.api.endpoint.trim().is_empty()
        {
            tr(self.language, Text::AddApi)
        } else {
            tr(self.language, Text::LiveApi)
        }
    }

    fn render_summary_cards(&self, ui: &mut egui::Ui) {
        let Some(result) = &self.result else {
            ui.label(tr(self.language, Text::ImportTraceToBegin));
            return;
        };
        let Some(dashboard) = &self.dashboard else {
            ui.label(tr(self.language, Text::AnalysisLoading));
            return;
        };
        let summary = &result.telemetry.overall;
        let items = [
            (
                tr(self.language, Text::CurrentTrace),
                dashboard.current_trace.clone(),
                captured_label_display(&dashboard.captured_label, self.language),
                icons::FILE_TEXT_LINE,
            ),
            (
                tr(self.language, Text::Duration),
                format!("{:.1} s", summary.duration_s),
                String::new(),
                icons::TIME_LINE,
            ),
            (
                tr(self.language, Text::Protocol),
                dashboard.protocol.clone(),
                String::new(),
                icons::GLOBAL_LINE,
            ),
            (
                tr(self.language, Text::Flows),
                dashboard.flow_count.clone(),
                String::new(),
                icons::FLOW_CHART,
            ),
            (
                tr(self.language, Text::Packets),
                format_number(summary.samples as u64),
                String::new(),
                icons::BAR_CHART_LINE,
            ),
        ];
        for (rect, (label, value, caption, icon)) in summary_card_rects(ui.max_rect())
            .into_iter()
            .zip(items.iter())
        {
            with_rect(ui, rect, |ui| {
                summary_card(ui, icon, label, value, caption, rect.size());
            });
        }
    }

    fn render_key_metrics(&self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            section_title(ui, tr(self.language, Text::KeyMetrics));
            ui.add_space(12.0);
            let Some(result) = &self.result else {
                ui.label(tr(self.language, Text::NoMetrics));
                return;
            };
            let overall = &result.telemetry.overall;
            let latency_p50 = result
                .telemetry
                .windows
                .iter()
                .map(|window| window.latency_ms.p50)
                .collect::<Vec<_>>();
            let latency_p95 = result
                .telemetry
                .windows
                .iter()
                .map(|window| window.latency_ms.p95)
                .collect::<Vec<_>>();
            let jitter = result
                .telemetry
                .windows
                .iter()
                .map(|window| window.jitter_ms.std)
                .collect::<Vec<_>>();
            let loss = result
                .telemetry
                .windows
                .iter()
                .map(|window| window.packet_loss_rate)
                .collect::<Vec<_>>();
            let retrans = result
                .telemetry
                .windows
                .iter()
                .map(|window| window.retransmission_rate)
                .collect::<Vec<_>>();
            let throughput = result
                .telemetry
                .windows
                .iter()
                .map(|window| window.throughput_mbps.mean)
                .collect::<Vec<_>>();
            let tile_w = ((ui.available_width() - 20.0) / 3.0).clamp(124.0, 156.0);
            egui::Grid::new("metric_grid")
                .num_columns(3)
                .spacing(Vec2::new(10.0, 12.0))
                .show(ui, |ui| {
                    metric_tile(
                        ui,
                        metric_label("latency_p50", self.language),
                        format!("{:.1} ms", overall.latency.p50),
                        BLUE,
                        &latency_p50,
                        tile_w,
                    );
                    metric_tile(
                        ui,
                        metric_label("latency_p95", self.language),
                        format!("{:.1} ms", overall.latency.p95),
                        PURPLE,
                        &latency_p95,
                        tile_w,
                    );
                    metric_tile(
                        ui,
                        metric_label("jitter", self.language),
                        format!("{:.1} ms", overall.jitter_ms.mean),
                        ORANGE,
                        &jitter,
                        tile_w,
                    );
                    ui.end_row();
                    metric_tile(
                        ui,
                        metric_label("packet_loss", self.language),
                        format!("{:.2} %", overall.packet_loss_rate),
                        RED,
                        &loss,
                        tile_w,
                    );
                    metric_tile(
                        ui,
                        metric_label("retransmission", self.language),
                        format!("{:.2} %", overall.retransmission_rate),
                        ORANGE,
                        &retrans,
                        tile_w,
                    );
                    metric_tile(
                        ui,
                        metric_label("throughput", self.language),
                        format!("{:.2} Mbps", overall.throughput_mbps.mean),
                        GREEN,
                        &throughput,
                        tile_w,
                    );
                });
        });
    }

    fn render_latency_panel(&mut self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            ui.horizontal(|ui| {
                let title = format!(
                    "{} {}",
                    self.latency_metric.label(),
                    tr(self.language, Text::LatencyChart)
                );
                section_title(ui, &title);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    for range in TrendRange::ALL.into_iter().rev() {
                        if segmented_pill(ui, range.label(), self.trend_range == range).clicked() {
                            self.trend_range = range;
                        }
                    }
                });
            });
            ui.horizontal(|ui| {
                for metric in LatencyMetric::ALL {
                    if segmented_pill(ui, metric.label(), self.latency_metric == metric).clicked() {
                        self.latency_metric = metric;
                    }
                    ui.add_space(4.0);
                }
            });
            let points = self
                .result
                .as_ref()
                .map(|result| {
                    latency_trend_points(
                        &result.telemetry.windows,
                        self.trend_range,
                        self.latency_metric,
                    )
                })
                .unwrap_or_default();
            ui.add_space(8.0);
            let chart_height = (ui.available_height() - 8.0).clamp(156.0, 320.0);
            draw_large_chart(ui, &points, self.trend_range, chart_height);
        });
    }

    fn render_diagnosis_card(&mut self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            section_title(ui, tr(self.language, Text::DiagnosisSummary));
            ui.add_space(12.0);
            let Some(result) = &self.result else {
                ui.label(tr(self.language, Text::NoDiagnosis));
                return;
            };
            let compact = ui.available_height() < 260.0;
            let event = result.diagnosis_events.first();
            let label = event
                .map(|event| event.evidence.symptom)
                .unwrap_or(FaultLabel::Normal);
            let confidence = event.map(|event| event.evidence.confidence).unwrap_or(0.0);
            let headline = fault_label_display(label, self.language);
            ui.horizontal(|ui| {
                alert_badge(ui, label);
                ui.label(RichText::new(headline).size(17.0).strong().color(
                    if label == FaultLabel::Normal {
                        GREEN
                    } else {
                        RED
                    },
                ));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    confidence_chip(ui, confidence, label != FaultLabel::Normal);
                    ui.label(
                        RichText::new(tr(self.language, Text::Confidence))
                            .size(11.0)
                            .color(MUTED),
                    );
                });
            });
            ui.add_space(if compact { 8.0 } else { 12.0 });
            if let Some(event) = event {
                ui.label(
                    RichText::new(&event.evidence.why)
                        .size(if compact { 12.0 } else { 13.0 })
                        .color(INK),
                );
                ui.add_space(if compact { 8.0 } else { 14.0 });
                ui.label(
                    RichText::new(tr(self.language, Text::Evidence))
                        .size(11.0)
                        .color(MUTED),
                );
                let evidence_limit = if compact { 3 } else { 4 };
                for metric in event
                    .evidence
                    .supporting_metrics
                    .iter()
                    .take(evidence_limit)
                {
                    bullet(ui, metric.name.as_str(), PURPLE);
                }
            }
            ui.with_layout(Layout::bottom_up(Align::RIGHT), |ui| {
                if soft_button(ui, tr(self.language, Text::ViewDetails)).clicked() {
                    self.tab = Tab::Diagnosis;
                }
            });
        });
    }

    fn render_rule_ml_card(&mut self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            section_title(ui, tr(self.language, Text::RuleMlComparison));
            ui.add_space(12.0);
            let Some(result) = &self.result else {
                ui.label(tr(self.language, Text::NoComparison));
                return;
            };
            ui.columns(2, |columns| {
                comparison_box(
                    &mut columns[0],
                    tr(self.language, Text::RuleBased),
                    &fault_label_from_str(
                        result
                            .comparison
                            .rule_labels
                            .first()
                            .map(String::as_str)
                            .unwrap_or("normal"),
                        self.language,
                    ),
                    rule_confidence(result),
                    BLUE,
                    tr(self.language, Text::Confidence),
                );
                comparison_box(
                    &mut columns[1],
                    tr(self.language, Text::MlAssisted),
                    &fault_label_from_str(result.comparison.ml_top.as_str(), self.language),
                    result.comparison.ml_top_prob,
                    PURPLE,
                    tr(self.language, Text::Confidence),
                );
            });
            ui.add_space(14.0);
            let fill = if result.comparison.agreement {
                Color32::from_rgb(215, 244, 218)
            } else {
                Color32::from_rgb(255, 235, 219)
            };
            egui::Frame::new()
                .fill(fill)
                .corner_radius(12)
                .stroke(Stroke::new(1.0, Color32::from_white_alpha(140)))
                .inner_margin(Margin::symmetric(14, 10))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(if result.comparison.agreement {
                                    tr(self.language, Text::Agreement)
                                } else {
                                    tr(self.language, Text::ReviewNeeded)
                                })
                                .strong()
                                .color(
                                    if result.comparison.agreement {
                                        Color32::from_rgb(28, 120, 46)
                                    } else {
                                        ORANGE
                                    },
                                ),
                            );
                            ui.label(
                                RichText::new(comparison_agreement_text(
                                    result.comparison.agreement,
                                    self.language,
                                ))
                                .size(12.0)
                                .color(INK),
                            );
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            status_circle(ui, result.comparison.agreement);
                        });
                    });
                });
            ui.with_layout(Layout::bottom_up(Align::RIGHT), |ui| {
                if soft_button(ui, tr(self.language, Text::ViewComparison)).clicked() {
                    self.tab = Tab::RuleMl;
                }
            });
        });
    }

    fn render_top_talkers(&self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            section_title(ui, tr(self.language, Text::TopTalkers));
            ui.add_space(14.0);
            let Some(dashboard) = &self.dashboard else {
                ui.label(
                    RichText::new(tr(self.language, Text::NoFlowMetadata))
                        .size(13.0)
                        .color(MUTED),
                );
                return;
            };

            let content_size = Vec2::new(ui.available_width(), ui.available_height().max(0.0));
            let (content_rect, _) = ui.allocate_exact_size(content_size, Sense::hover());
            if content_rect.width() < 120.0 || content_rect.height() < 64.0 {
                return;
            }

            let talkers = dashboard.top_talkers.iter().take(4).collect::<Vec<_>>();
            if talkers.is_empty() {
                with_rect(ui, content_rect, |ui| {
                    ui.label(
                        RichText::new(tr(self.language, Text::NoFlowMetadata))
                            .size(13.0)
                            .color(MUTED),
                    );
                });
                return;
            }

            let compact = content_rect.width() < 340.0 || content_rect.height() < 150.0;
            let row_count = talkers.len();
            let row_gap = if compact { 4.0 } else { 6.0 };
            let desired_row_h = if compact { 30.0 } else { 34.0 };
            let min_row_h = if compact { 24.0 } else { 28.0 };
            let row_gaps_h = row_gap * row_count.saturating_sub(1) as f32;
            let row_h = ((content_rect.height() - row_gaps_h) / row_count as f32)
                .clamp(min_row_h, desired_row_h);
            let legend_h = row_h * row_count as f32 + row_gaps_h;
            let column_gap = if compact { 12.0 } else { 18.0 };
            let min_legend_w = if compact { 150.0 } else { 180.0 };
            let max_donut = if compact { 112.0 } else { 140.0 };
            let donut_w_budget = (content_rect.width() - column_gap - min_legend_w)
                .max(78.0)
                .min(max_donut);
            let donut_size = content_rect
                .height()
                .min(donut_w_budget)
                .clamp(78.0, max_donut);
            let group_h = donut_size.max(legend_h).min(content_rect.height());
            let group_top = content_rect.top() + (content_rect.height() - group_h).max(0.0) * 0.5;
            let donut_top = group_top + (group_h - donut_size).max(0.0) * 0.5;
            let donut_rect = Rect::from_min_size(
                Pos2::new(content_rect.left() + 4.0, donut_top),
                Vec2::splat(donut_size),
            );
            let legend_top = group_top + (group_h - legend_h).max(0.0) * 0.5;
            let legend_rect = Rect::from_min_max(
                Pos2::new(donut_rect.right() + column_gap, legend_top),
                Pos2::new(content_rect.right(), content_rect.bottom()),
            );

            draw_donut(ui, donut_rect, dashboard, self.language);
            with_rect(ui, legend_rect, |ui| {
                for (idx, talker) in talkers.iter().enumerate() {
                    if idx > 0 {
                        ui.add_space(row_gap);
                    }
                    let label = talker_label_display(&talker.label, self.language);
                    legend_row(ui, talker_color(idx), &label, &talker.detail, row_h);
                }
            });
        });
    }

    fn render_status_bar(&self, ui: &mut egui::Ui) {
        let rect = ui.max_rect();
        paint_glass(ui, rect, 18, Color32::from_white_alpha(82));
        let Some(result) = &self.result else {
            return;
        };
        let fallback_source = self
            .dashboard
            .as_ref()
            .map(|dashboard| dashboard.data_source.as_str())
            .unwrap_or_else(|| tr(self.language, Text::NoSource));
        let data_source = data_source_display(
            self.source_snapshot.as_ref(),
            fallback_source,
            self.language,
        );
        let painter = ui.painter();
        let y = rect.center().y;
        let left = rect.left() + 24.0;
        let right = rect.right() - 46.0;
        let cell_w = ((right - left) / 4.0).max(130.0);
        let status_rect = Rect::from_min_size(
            Pos2::new(left + 18.0, rect.top()),
            Vec2::new(cell_w - 18.0, rect.height()),
        );
        let source_rect = Rect::from_min_size(
            Pos2::new(left + cell_w, rect.top()),
            Vec2::new(cell_w, rect.height()),
        );
        let update_rect = Rect::from_min_size(
            Pos2::new(left + cell_w * 2.0, rect.top()),
            Vec2::new(cell_w, rect.height()),
        );
        let id_rect = Rect::from_min_size(
            Pos2::new(left + cell_w * 3.0, rect.top()),
            Vec2::new((right - (left + cell_w * 3.0)).max(120.0), rect.height()),
        );
        painter.circle_filled(Pos2::new(left, y), 5.0, status_color(&self.status));
        status_cell(
            painter,
            status_rect,
            tr(self.language, Text::SystemStatus),
            status_display(&self.status, self.language),
            status_color(&self.status),
        );
        status_cell(
            painter,
            source_rect,
            tr(self.language, Text::DataSource),
            &data_source,
            INK,
        );
        status_cell(
            painter,
            update_rect,
            tr(self.language, Text::LastUpdate),
            &result.report.generated_at.format("%H:%M:%S").to_string(),
            INK,
        );
        status_cell(
            painter,
            id_rect,
            tr(self.language, Text::AnalysisId),
            &short_id(&result.run_id),
            INK,
        );
        painter.text(
            Pos2::new(rect.right() - 28.0, y),
            Align2::CENTER_CENTER,
            icons::PULSE_LINE,
            icon_font(18.0),
            BLUE,
        );
    }
}

fn title_for_tab(tab: Tab, lang: Language) -> &'static str {
    match (lang, tab) {
        (Language::Zh, Tab::Overview) => "概览",
        (Language::Zh, Tab::Telemetry) => "遥测",
        (Language::Zh, Tab::Diagnosis) => "诊断",
        (Language::Zh, Tab::RuleMl) => "规则 vs ML",
        (Language::Zh, Tab::DigitalTwin) => "数字孪生",
        (Language::Zh, Tab::WhatIf) => "What-if",
        (Language::Zh, Tab::Reports) => "报告",
        (Language::Zh, Tab::Settings) => "设置",
        (Language::En, Tab::Overview) => "Overview",
        (Language::En, Tab::Telemetry) => "Telemetry",
        (Language::En, Tab::Diagnosis) => "Diagnosis",
        (Language::En, Tab::RuleMl) => "Rule vs ML",
        (Language::En, Tab::DigitalTwin) => "Digital Twin",
        (Language::En, Tab::WhatIf) => "What-if",
        (Language::En, Tab::Reports) => "Reports",
        (Language::En, Tab::Settings) => "Settings",
    }
}

impl From<LanguageSetting> for Language {
    fn from(value: LanguageSetting) -> Self {
        match value {
            LanguageSetting::Zh => Language::Zh,
            LanguageSetting::En => Language::En,
        }
    }
}

impl From<Language> for LanguageSetting {
    fn from(value: Language) -> Self {
        match value {
            Language::Zh => LanguageSetting::Zh,
            Language::En => LanguageSetting::En,
        }
    }
}

impl From<StartupTab> for Tab {
    fn from(value: StartupTab) -> Self {
        match value {
            StartupTab::Overview => Tab::Overview,
            StartupTab::Telemetry => Tab::Telemetry,
            StartupTab::Diagnosis => Tab::Diagnosis,
            StartupTab::RuleMl => Tab::RuleMl,
            StartupTab::DigitalTwin => Tab::DigitalTwin,
            StartupTab::WhatIf => Tab::WhatIf,
            StartupTab::Reports => Tab::Reports,
            StartupTab::Settings => Tab::Settings,
        }
    }
}

impl From<Tab> for StartupTab {
    fn from(value: Tab) -> Self {
        match value {
            Tab::Overview => StartupTab::Overview,
            Tab::Telemetry => StartupTab::Telemetry,
            Tab::Diagnosis => StartupTab::Diagnosis,
            Tab::RuleMl => StartupTab::RuleMl,
            Tab::DigitalTwin => StartupTab::DigitalTwin,
            Tab::WhatIf => StartupTab::WhatIf,
            Tab::Reports => StartupTab::Reports,
            Tab::Settings => StartupTab::Settings,
        }
    }
}

#[cfg(target_os = "macos")]
fn default_secret_store() -> Box<dyn SecretStore> {
    Box::new(KeychainSecretStore)
}

#[cfg(not(target_os = "macos"))]
fn default_secret_store() -> Box<dyn SecretStore> {
    Box::new(MemorySecretStore::default())
}

fn source_mode_from_settings(
    settings: &AppSettings,
    secrets: &dyn SecretStore,
) -> (SourceMode, Option<String>) {
    match settings.default_source {
        DefaultSource::Simulation => (SourceMode::Simulated(settings.simulation_scenario), None),
        DefaultSource::LastImportedFile => {
            if let Some(path) = &settings.last_imported_trace {
                if path.is_file() {
                    return (SourceMode::File(path.clone()), None);
                }
                return (
                    SourceMode::Simulated(settings.simulation_scenario),
                    Some(format!(
                        "Last imported trace is unavailable: {}",
                        path.display()
                    )),
                );
            }
            (
                SourceMode::Simulated(settings.simulation_scenario),
                Some("No last imported trace is saved; using simulation.".to_string()),
            )
        }
        DefaultSource::LiveApi => connector_source_mode_from_settings(settings, secrets),
    }
}

fn connector_source_mode_from_settings(
    settings: &AppSettings,
    secrets: &dyn SecretStore,
) -> (SourceMode, Option<String>) {
    match connector_source_mode_from_profile(settings, secrets) {
        Ok(source_mode) => (source_mode, None),
        Err(err) => (
            SourceMode::Simulated(settings.simulation_scenario),
            Some(format!(
                "Live collection is not ready; using simulation. {err}"
            )),
        ),
    }
}

fn connector_source_mode_from_profile(
    settings: &AppSettings,
    secrets: &dyn SecretStore,
) -> anyhow::Result<SourceMode> {
    let profile = settings.data_connectors.active_profile();
    let kind = profile
        .map(|profile| profile.kind)
        .unwrap_or(settings.data_connectors.default_connector);
    match kind {
        ConnectorKind::LocalProbe => Ok(SourceMode::LocalProbe(
            profile
                .map(|profile| profile.local_probe.clone())
                .unwrap_or_else(|| settings.data_connectors.local_probe.clone()),
        )),
        ConnectorKind::WebsiteProbe => Ok(SourceMode::WebsiteProbe(
            profile
                .map(|profile| profile.website_probe.clone())
                .unwrap_or_else(|| settings.data_connectors.website_probe.clone()),
        )),
        ConnectorKind::HttpJson => {
            let config = if let Some(profile) = profile {
                AppSettings {
                    api: profile.http_json.clone(),
                    ..settings.clone()
                }
                .api_config(secrets)?
            } else {
                settings.api_config(secrets)?
            };
            Ok(SourceMode::Api(config))
        }
        ConnectorKind::PrometheusQueryRange => Ok(SourceMode::PrometheusQueryRange(
            profile
                .map(|profile| profile.prometheus_query.clone())
                .unwrap_or_else(|| settings.data_connectors.prometheus_query.clone()),
            secrets.get_live_api_token()?,
        )),
        ConnectorKind::PrometheusExposition => Ok(SourceMode::PrometheusExposition(
            profile
                .map(|profile| profile.prometheus_exposition.clone())
                .unwrap_or_else(|| settings.data_connectors.prometheus_exposition.clone()),
            secrets.get_live_api_token()?,
        )),
        ConnectorKind::OtlpGrpcReceiver => Ok(SourceMode::OtlpGrpcReceiver(
            profile
                .map(|profile| profile.otlp_grpc.clone())
                .unwrap_or_else(|| settings.data_connectors.otlp_grpc.clone()),
        )),
        ConnectorKind::NativePcap => Ok(SourceMode::NativePcap(
            profile
                .map(|profile| profile.native_pcap.clone())
                .unwrap_or_else(|| settings.data_connectors.native_pcap.clone()),
        )),
        ConnectorKind::SystemCounters => Ok(SourceMode::SystemCounters(
            profile
                .map(|profile| profile.system_counters.clone())
                .unwrap_or_else(|| settings.data_connectors.system_counters.clone()),
        )),
    }
}

fn failed_capture_session(kind: ConnectorKind, status: String) -> CaptureSessionState {
    CaptureSessionState {
        kind,
        phase: CaptureSessionPhase::Failed,
        started_at: chrono::Utc::now(),
        timeout: Duration::from_secs(0),
        progress: None,
        last_sample: None,
        status,
        job: None,
        cancel: None,
        otlp: None,
    }
}

fn source_snapshot_from_connector_session(
    loaded: ConnectorLoadResult,
    kind: ConnectorKind,
    captured_verb: &str,
    data_source_label: String,
) -> SourceSnapshot {
    let rows = loaded.ingest.records.len();
    let payload = loaded.payload.unwrap_or(Value::Null);
    let (kind_label, protocol) = match kind {
        ConnectorKind::OtlpGrpcReceiver => ("OTLP gRPC Session", "OTLP"),
        ConnectorKind::NativePcap => ("Native pcap Session", "PCAP"),
        ConnectorKind::SystemCounters => ("System counters Session", "Interface"),
        _ => ("Capture Session", "Capture"),
    };
    let mut flow_summary = connector_payload_flow_summary(&payload, protocol, rows);
    if flow_summary.total_bytes.is_none() {
        flow_summary.total_bytes = estimate_session_bytes(&loaded.ingest.records);
    }
    SourceSnapshot {
        descriptor: SourceDescriptor {
            name: loaded.sample,
            kind: kind_label.to_string(),
            captured_label: format!("{captured_verb}  •  {}", chrono::Utc::now().format("%H:%M")),
            data_source_label,
        },
        flow_summary,
        ingest: loaded.ingest,
    }
}

fn connector_payload_flow_summary(payload: &Value, protocol: &str, rows: usize) -> FlowSummary {
    let top_talkers = payload
        .get("top_talkers")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let label = item.get("label").and_then(Value::as_str)?;
                    let bytes = item.get("bytes").and_then(Value::as_u64)?;
                    Some(netdiag_app::data_source::TopTalker {
                        label: label.to_string(),
                        bytes,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let total_bytes = payload
        .get("total_bytes")
        .or_else(|| payload.get("bytes"))
        .and_then(Value::as_u64)
        .or_else(|| {
            let sum = top_talkers.iter().map(|talker| talker.bytes).sum::<u64>();
            (sum > 0).then_some(sum)
        });
    let flows = if top_talkers.is_empty() {
        payload
            .get("flow_count")
            .and_then(Value::as_u64)
            .map(|value| value as usize)
            .or(Some(rows))
    } else {
        Some(top_talkers.len())
    };
    FlowSummary {
        protocol: Some(protocol.to_string()),
        flows,
        total_bytes,
        top_talkers,
    }
}

fn estimate_session_bytes(records: &[netdiag_core::models::TraceRecord]) -> Option<u64> {
    if records.len() < 2 {
        return None;
    }
    let mut bytes = 0.0;
    for pair in records.windows(2) {
        let seconds = (pair[1].timestamp - pair[0].timestamp)
            .num_milliseconds()
            .max(0) as f64
            / 1000.0;
        bytes += pair[0].throughput_mbps.max(0.0) * 1_000_000.0 * seconds / 8.0;
    }
    bytes.is_finite().then_some(bytes.round() as u64)
}

fn format_capture_progress(progress: &CaptureProgress) -> String {
    let mut parts = vec![
        format!("{}: {}", progress.stage, progress.message),
        format!("{}ms/{}ms", progress.elapsed_ms, progress.timeout_ms.max(1)),
    ];
    if let Some(limit) = progress.packet_limit {
        parts.push(format!(
            "packets {}/{}",
            progress.packets_seen.min(limit),
            limit
        ));
    } else if progress.samples_seen > 0 {
        parts.push(format!("samples {}", progress.samples_seen));
    }
    if progress.bytes_seen > 0 {
        parts.push(format_bytes(progress.bytes_seen));
    }
    if let Some(last_sample_at) = progress.last_sample_at {
        parts.push(format!("last {}", last_sample_at.format("%H:%M:%S")));
    }
    parts.join(" · ")
}

fn tr(lang: Language, text: Text) -> &'static str {
    match (lang, text) {
        (Language::Zh, Text::Subtitle) => "实时网络诊断与分析",
        (Language::Zh, Text::ImportTrace) => "导入 Trace",
        (Language::Zh, Text::Simulate) => "仿真",
        (Language::Zh, Text::LiveApi) => "真实 API",
        (Language::Zh, Text::NewAnalysis) => "+ 新分析",
        (Language::Zh, Text::CurrentTrace) => "当前 Trace",
        (Language::Zh, Text::Duration) => "持续时间",
        (Language::Zh, Text::Protocol) => "协议",
        (Language::Zh, Text::Flows) => "流",
        (Language::Zh, Text::Packets) => "数据包",
        (Language::Zh, Text::KeyMetrics) => "关键指标",
        (Language::Zh, Text::LatencyChart) => "延迟趋势",
        (Language::Zh, Text::DiagnosisSummary) => "诊断摘要",
        (Language::Zh, Text::RuleMlComparison) => "规则 vs ML 对比",
        (Language::Zh, Text::TopTalkers) => "主要流量",
        (Language::Zh, Text::SystemStatus) => "系统状态",
        (Language::Zh, Text::DataSource) => "数据源",
        (Language::Zh, Text::LastUpdate) => "最后更新",
        (Language::Zh, Text::AnalysisId) => "分析 ID",
        (Language::Zh, Text::NoMetrics) => "暂无指标。",
        (Language::Zh, Text::NoDiagnosis) => "暂无诊断。",
        (Language::Zh, Text::NoComparison) => "暂无对比。",
        (Language::Zh, Text::NoFlowMetadata) => "当前数据源没有逐流元数据。",
        (Language::Zh, Text::NoSource) => "暂无数据源",
        (Language::Zh, Text::ImportTraceToBegin) => "导入 Trace 后开始分析。",
        (Language::Zh, Text::AnalysisLoading) => "分析正在载入。",
        (Language::Zh, Text::AnalysisAlreadyRunning) => "分析正在运行，请等待当前任务完成",
        (Language::Zh, Text::Running) => "运行中",
        (Language::Zh, Text::ViewDetails) => "查看详情",
        (Language::Zh, Text::ViewComparison) => "查看对比",
        (Language::Zh, Text::Confidence) => "置信度",
        (Language::Zh, Text::Agreement) => "一致",
        (Language::Zh, Text::ReviewNeeded) => "需要复核",
        (Language::Zh, Text::SettingsLanguage) => "界面语言",
        (Language::Zh, Text::Artifacts) => "运行产物",
        (Language::Zh, Text::CurrentRun) => "当前运行",
        (Language::Zh, Text::RunHistory) => "运行历史",
        (Language::Zh, Text::LatestComparison) => "最新两次对比",
        (Language::Zh, Text::ReviewState) => "复核状态",
        (Language::Zh, Text::RootCauses) => "根因",
        (Language::Zh, Text::ModelType) => "模型类型",
        (Language::Zh, Text::SyntheticModel) => "合成 fallback",
        (Language::Zh, Text::Recommendations) => "推荐动作",
        (Language::Zh, Text::Evidence) => "证据",
        (Language::Zh, Text::WhatIfResult) => "What-if 结果",
        (Language::Zh, Text::MlTopPredictions) => "ML Top 预测",
        (Language::Zh, Text::FeatureContribution) => "特征贡献",
        (Language::Zh, Text::ModelStatus) => "模型状态",
        (Language::Zh, Text::SyntheticFallback) => "synthetic fallback，仅适合原型和回归验证",
        (Language::Zh, Text::RuleBased) => "规则诊断",
        (Language::Zh, Text::MlAssisted) => "ML 辅助",
        (Language::Zh, Text::AddApi) => "添加 API",
        (Language::Zh, Text::ConfigureLiveApiFirst) => {
            "请先在 Settings 填写 API URL，或设置 NETDIAG_API_URL"
        }
        (Language::Zh, Text::Metric) => "指标",
        (Language::Zh, Text::Baseline) => "基线",
        (Language::Zh, Text::Proposed) => "方案",
        (Language::Zh, Text::NoWhatIf) => "暂无 What-if 结果。",
        (Language::Zh, Text::NoArtifacts) => "暂无运行产物。",
        (Language::Zh, Text::Topology) => "拓扑",
        (Language::Zh, Text::Action) => "动作",
        (Language::Zh, Text::Risk) => "风险",
        (Language::Zh, Text::Approval) => "审批",
        (Language::Zh, Text::HilReview) => "HIL 复核",
        (Language::Zh, Text::HilStatus) => "HIL 状态",
        (Language::Zh, Text::Accept) => "通过",
        (Language::Zh, Text::Reject) => "驳回",
        (Language::Zh, Text::MarkUncertain) => "标记不确定",
        (Language::Zh, Text::RequireRerun) => "要求重跑",
        (Language::Zh, Text::ReviewNotes) => "复核备注",
        (Language::Zh, Text::ReviewedBy) => "复核人",
        (Language::Zh, Text::ApiUnset) => "未配置",
        (Language::Zh, Text::ApiSet) => "已配置",
        (Language::Zh, Text::EngineerRole) => "网络工程师",
        (Language::Zh, Text::Online) => "在线",
        (Language::Zh, Text::Total) => "总计",
        (Language::Zh, Text::General) => "通用",
        (Language::Zh, Text::StartupDefaultPage) => "启动默认页",
        (Language::Zh, Text::AutoRunDiagnosis) => "启动时自动运行诊断",
        (Language::Zh, Text::DataSources) => "数据源",
        (Language::Zh, Text::DefaultDataSource) => "默认数据源",
        (Language::Zh, Text::SimulationScenario) => "仿真场景",
        (Language::Zh, Text::LastImportedTrace) => "上次导入",
        (Language::Zh, Text::LiveApiConnection) => "真实 API 连接",
        (Language::Zh, Text::ApiUrl) => "API URL",
        (Language::Zh, Text::RequestTimeout) => "请求超时",
        (Language::Zh, Text::TokenStatus) => "Token 状态",
        (Language::Zh, Text::SaveToken) => "保存 Token",
        (Language::Zh, Text::DeleteToken) => "删除 Token",
        (Language::Zh, Text::ConfirmDeleteToken) => "确认删除",
        (Language::Zh, Text::TestConnection) => "测试连接",
        (Language::Zh, Text::TestingConnection) => "正在测试...",
        (Language::Zh, Text::ConnectionOk) => "连接成功",
        (Language::Zh, Text::KeychainError) => "Keychain 错误",
        (Language::Zh, Text::DigitalTwinDefaults) => "数字孪生默认值",
        (Language::Zh, Text::DataArtifacts) => "数据与产物",
        (Language::Zh, Text::ArtifactRoot) => "产物目录",
        (Language::Zh, Text::ChooseFolder) => "选择目录",
        (Language::Zh, Text::OpenFolder) => "打开目录",
        (Language::Zh, Text::SettingsFile) => "设置文件",
        (Language::Zh, Text::ClearRunHistory) => "清理运行历史",
        (Language::Zh, Text::ConfirmClearRunHistory) => "确认清理历史",
        (Language::Zh, Text::ModelCache) => "模型缓存",
        (Language::Zh, Text::RebuildModel) => "重建模型",
        (Language::Zh, Text::ConfirmRebuildModel) => "确认重建模型",
        (Language::Zh, Text::DiagnosisReview) => "诊断与复核",
        (Language::Zh, Text::RulePolicy) => "规则引擎：证据优先、确定性诊断",
        (Language::Zh, Text::MlPolicy) => "ML：Rust linfa logistic，提供概率和特征贡献",
        (Language::Zh, Text::HilPolicy) => "HIL：推荐动作默认需要人工复核",
        (Language::Zh, Text::PrivacyAbout) => "隐私与关于",
        (Language::Zh, Text::LocalProcessing) => "Trace、报告和模型缓存都保存在本机",
        (Language::Zh, Text::KeychainProtection) => "Token 使用 macOS Keychain 保存",
        (Language::Zh, Text::BundleId) => "Bundle ID",
        (Language::Zh, Text::Version) => "版本",
        (Language::Zh, Text::OpenReport) => "打开报告",
        (Language::Zh, Text::CheckForUpdates) => "检查更新",
        (Language::Zh, Text::UpdateStatus) => "更新状态",
        (Language::Zh, Text::UpdateDialogOpened) => "更新窗口已打开",
        (Language::Zh, Text::UpdateFeedReachable) => "更新源可访问",
        (Language::Zh, Text::OpenRunFolder) => "打开运行目录",
        (Language::Zh, Text::ArtifactFiles) => "产物文件",
        (Language::Zh, Text::ValidationWarnings) => "校验警告",
        (Language::Zh, Text::OpenFailed) => "打开失败",
        (Language::Zh, Text::Saved) => "已保存",
        (Language::Zh, Text::NotAvailable) => "不可用",
        (Language::Zh, Text::EnvFallback) => " / 环境变量",
        (Language::Zh, Text::Rows) => "行",
        (Language::Zh, Text::DefaultSourceSimulation) => "仿真",
        (Language::Zh, Text::DefaultSourceLastImport) => "上次导入文件",
        (Language::Zh, Text::DefaultSourceLiveApi) => "真实采集",
        (Language::Zh, Text::DataConnectors) => "数据连接器",
        (Language::Zh, Text::ConnectorKind) => "连接器类型",
        (Language::Zh, Text::ConnectorLocalProbe) => "本机网络探针",
        (Language::Zh, Text::ConnectorWebsiteProbe) => "网站探针",
        (Language::Zh, Text::ConnectorHttpJson) => "HTTP/JSON 实验平台",
        (Language::Zh, Text::ConnectorPrometheusQuery) => "Prometheus query_range",
        (Language::Zh, Text::ConnectorPrometheusMetrics) => "Prometheus /metrics",
        (Language::Zh, Text::ConnectorOtlpGrpc) => "OTLP gRPC 接收器",
        (Language::Zh, Text::ConnectorNativePcap) => "Rust 原生抓包",
        (Language::Zh, Text::ConnectorSystemCounters) => "系统接口计数器",
        (Language::Zh, Text::SourceProfile) => "采集 Profile",
        (Language::Zh, Text::ProfileName) => "Profile 名称",
        (Language::Zh, Text::PrometheusBaseUrl) => "Prometheus URL",
        (Language::Zh, Text::PrometheusMetricsEndpoint) => "Metrics 端点",
        (Language::Zh, Text::PrometheusLookback) => "回看秒数",
        (Language::Zh, Text::PrometheusStep) => "步长秒数",
        (Language::Zh, Text::ProbeSamples) => "探测次数",
        (Language::Zh, Text::ProbeTargets) => "探测目标",
        (Language::Zh, Text::OtlpBindAddr) => "OTLP 监听地址",
        (Language::Zh, Text::CaptureSource) => "抓包来源",
        (Language::Zh, Text::PacketLimit) => "包数上限",
        (Language::Zh, Text::CaptureTimeout) => "抓包超时",
        (Language::Zh, Text::CaptureSession) => "采集会话",
        (Language::Zh, Text::StartReceiver) => "启动接收器",
        (Language::Zh, Text::StartCapture) => "开始采集",
        (Language::Zh, Text::CancelCapture) => "取消采集",
        (Language::Zh, Text::DiagnoseLastSample) => "诊断最近采样",
        (Language::Zh, Text::StopReceiver) => "停止接收器",
        (Language::Zh, Text::DiagnoseBuffer) => "诊断缓冲区",
        (Language::Zh, Text::CaptureProgress) => "采集进度",
        (Language::Zh, Text::CaptureRunning) => "采集中",
        (Language::Zh, Text::CaptureCompleted) => "采集完成",
        (Language::Zh, Text::CaptureCancelled) => "采集已取消",
        (Language::Zh, Text::CaptureFailed) => "采集失败",
        (Language::Zh, Text::SystemInterface) => "接口",
        (Language::Zh, Text::SamplingInterval) => "采样间隔",
        (Language::Zh, Text::HttpJsonConnectorHint) => {
            "HTTP/JSON 使用下方真实 API URL 和 Keychain Token"
        }
        (Language::Zh, Text::ConnectorHealth) => "连接器健康",
        (Language::Zh, Text::MeasurementQuality) => "测量质量",
        (Language::Zh, Text::MissingMetrics) => "缺失指标",
        (Language::Zh, Text::LastSample) => "最近采样",
        (Language::Zh, Text::ImportTopology) => "导入拓扑",
        (Language::Zh, Text::ExportTopology) => "导出拓扑",
        (Language::Zh, Text::CustomTopology) => "自定义拓扑",
        (Language::Zh, Text::StartupOverview) => "概览",
        (Language::Zh, Text::StartupTelemetry) => "遥测",
        (Language::Zh, Text::StartupDiagnosis) => "诊断",
        (Language::Zh, Text::StartupRuleMl) => "规则 vs ML",
        (Language::Zh, Text::StartupDigitalTwin) => "数字孪生",
        (Language::Zh, Text::StartupWhatIf) => "What-if",
        (Language::Zh, Text::StartupReports) => "报告",
        (Language::Zh, Text::StartupSettings) => "设置",
        (Language::En, Text::Subtitle) => "Real-time network diagnosis and analysis",
        (Language::En, Text::ImportTrace) => "Import Trace",
        (Language::En, Text::Simulate) => "Simulate",
        (Language::En, Text::LiveApi) => "Live API",
        (Language::En, Text::NewAnalysis) => "+ New Analysis",
        (Language::En, Text::CurrentTrace) => "Current Trace",
        (Language::En, Text::Duration) => "Duration",
        (Language::En, Text::Protocol) => "Protocol",
        (Language::En, Text::Flows) => "Flows",
        (Language::En, Text::Packets) => "Packets",
        (Language::En, Text::KeyMetrics) => "Key Metrics",
        (Language::En, Text::LatencyChart) => "Latency Trend",
        (Language::En, Text::DiagnosisSummary) => "Diagnosis Summary",
        (Language::En, Text::RuleMlComparison) => "Rule vs ML Comparison",
        (Language::En, Text::TopTalkers) => "Top Talkers",
        (Language::En, Text::SystemStatus) => "System Status",
        (Language::En, Text::DataSource) => "Data Source",
        (Language::En, Text::LastUpdate) => "Last Update",
        (Language::En, Text::AnalysisId) => "Analysis ID",
        (Language::En, Text::NoMetrics) => "No metrics yet.",
        (Language::En, Text::NoDiagnosis) => "No diagnosis yet.",
        (Language::En, Text::NoComparison) => "No comparison yet.",
        (Language::En, Text::NoFlowMetadata) => "No per-flow metadata in this source.",
        (Language::En, Text::NoSource) => "No source",
        (Language::En, Text::ImportTraceToBegin) => "Import a trace to begin.",
        (Language::En, Text::AnalysisLoading) => "Analysis is loading.",
        (Language::En, Text::AnalysisAlreadyRunning) => {
            "Analysis is already running; wait for the current job to finish"
        }
        (Language::En, Text::Running) => "Running",
        (Language::En, Text::ViewDetails) => "View Details",
        (Language::En, Text::ViewComparison) => "View Comparison",
        (Language::En, Text::Confidence) => "Confidence",
        (Language::En, Text::Agreement) => "Agreement",
        (Language::En, Text::ReviewNeeded) => "Review Needed",
        (Language::En, Text::SettingsLanguage) => "Interface Language",
        (Language::En, Text::Artifacts) => "Run Artifacts",
        (Language::En, Text::CurrentRun) => "Current Run",
        (Language::En, Text::RunHistory) => "Run History",
        (Language::En, Text::LatestComparison) => "Latest Comparison",
        (Language::En, Text::ReviewState) => "Review State",
        (Language::En, Text::RootCauses) => "Root Causes",
        (Language::En, Text::ModelType) => "Model Type",
        (Language::En, Text::SyntheticModel) => "Synthetic fallback",
        (Language::En, Text::Recommendations) => "Recommendations",
        (Language::En, Text::Evidence) => "Evidence",
        (Language::En, Text::WhatIfResult) => "What-if Result",
        (Language::En, Text::MlTopPredictions) => "ML Top Predictions",
        (Language::En, Text::FeatureContribution) => "Feature Contribution",
        (Language::En, Text::ModelStatus) => "Model Status",
        (Language::En, Text::SyntheticFallback) => {
            "synthetic fallback; suitable for prototype and regression validation"
        }
        (Language::En, Text::RuleBased) => "Rule-based",
        (Language::En, Text::MlAssisted) => "ML-assisted",
        (Language::En, Text::AddApi) => "Add API",
        (Language::En, Text::ConfigureLiveApiFirst) => {
            "Configure an API URL in Settings or set NETDIAG_API_URL first"
        }
        (Language::En, Text::Metric) => "Metric",
        (Language::En, Text::Baseline) => "Baseline",
        (Language::En, Text::Proposed) => "Proposed",
        (Language::En, Text::NoWhatIf) => "No what-if result.",
        (Language::En, Text::NoArtifacts) => "No run artifacts yet.",
        (Language::En, Text::Topology) => "Topology",
        (Language::En, Text::Action) => "Action",
        (Language::En, Text::Risk) => "Risk",
        (Language::En, Text::Approval) => "Approval",
        (Language::En, Text::HilReview) => "HIL Review",
        (Language::En, Text::HilStatus) => "HIL Status",
        (Language::En, Text::Accept) => "Accept",
        (Language::En, Text::Reject) => "Reject",
        (Language::En, Text::MarkUncertain) => "Mark Uncertain",
        (Language::En, Text::RequireRerun) => "Require Rerun",
        (Language::En, Text::ReviewNotes) => "Review Notes",
        (Language::En, Text::ReviewedBy) => "Reviewed By",
        (Language::En, Text::ApiUnset) => "not set",
        (Language::En, Text::ApiSet) => "set",
        (Language::En, Text::EngineerRole) => "Network Engineer",
        (Language::En, Text::Online) => "Online",
        (Language::En, Text::Total) => "Total",
        (Language::En, Text::General) => "General",
        (Language::En, Text::StartupDefaultPage) => "Startup Page",
        (Language::En, Text::AutoRunDiagnosis) => "Run diagnosis on launch",
        (Language::En, Text::DataSources) => "Data Sources",
        (Language::En, Text::DefaultDataSource) => "Default Source",
        (Language::En, Text::SimulationScenario) => "Simulation Scenario",
        (Language::En, Text::LastImportedTrace) => "Last Import",
        (Language::En, Text::LiveApiConnection) => "Live API Connection",
        (Language::En, Text::ApiUrl) => "API URL",
        (Language::En, Text::RequestTimeout) => "Request Timeout",
        (Language::En, Text::TokenStatus) => "Token Status",
        (Language::En, Text::SaveToken) => "Save Token",
        (Language::En, Text::DeleteToken) => "Delete Token",
        (Language::En, Text::ConfirmDeleteToken) => "Confirm Delete",
        (Language::En, Text::TestConnection) => "Test Connection",
        (Language::En, Text::TestingConnection) => "Testing...",
        (Language::En, Text::ConnectionOk) => "Connection OK",
        (Language::En, Text::KeychainError) => "Keychain error",
        (Language::En, Text::DigitalTwinDefaults) => "Digital Twin Defaults",
        (Language::En, Text::DataArtifacts) => "Data & Artifacts",
        (Language::En, Text::ArtifactRoot) => "Artifact Root",
        (Language::En, Text::ChooseFolder) => "Choose Folder",
        (Language::En, Text::OpenFolder) => "Open Folder",
        (Language::En, Text::SettingsFile) => "Settings File",
        (Language::En, Text::ClearRunHistory) => "Clear Run History",
        (Language::En, Text::ConfirmClearRunHistory) => "Confirm Clear History",
        (Language::En, Text::ModelCache) => "Model Cache",
        (Language::En, Text::RebuildModel) => "Rebuild Model",
        (Language::En, Text::ConfirmRebuildModel) => "Confirm Rebuild Model",
        (Language::En, Text::DiagnosisReview) => "Diagnosis & Review",
        (Language::En, Text::RulePolicy) => "Rules: evidence-first deterministic diagnosis",
        (Language::En, Text::MlPolicy) => {
            "ML: Rust linfa logistic probabilities and feature contribution"
        }
        (Language::En, Text::HilPolicy) => "HIL: recommendations require human review by default",
        (Language::En, Text::PrivacyAbout) => "Privacy & About",
        (Language::En, Text::LocalProcessing) => "Traces, reports, and model cache remain local",
        (Language::En, Text::KeychainProtection) => "Token is stored in macOS Keychain",
        (Language::En, Text::BundleId) => "Bundle ID",
        (Language::En, Text::Version) => "Version",
        (Language::En, Text::OpenReport) => "Open Report",
        (Language::En, Text::CheckForUpdates) => "Check for Updates",
        (Language::En, Text::UpdateStatus) => "Update Status",
        (Language::En, Text::UpdateDialogOpened) => "Update window opened",
        (Language::En, Text::UpdateFeedReachable) => "Update feed reachable",
        (Language::En, Text::OpenRunFolder) => "Open Run Folder",
        (Language::En, Text::ArtifactFiles) => "Artifact Files",
        (Language::En, Text::ValidationWarnings) => "Validation Warnings",
        (Language::En, Text::OpenFailed) => "Open failed",
        (Language::En, Text::Saved) => "Saved",
        (Language::En, Text::NotAvailable) => "Unavailable",
        (Language::En, Text::EnvFallback) => " / env",
        (Language::En, Text::Rows) => "rows",
        (Language::En, Text::DefaultSourceSimulation) => "Simulation",
        (Language::En, Text::DefaultSourceLastImport) => "Last Imported File",
        (Language::En, Text::DefaultSourceLiveApi) => "Live Collection",
        (Language::En, Text::DataConnectors) => "Data Connectors",
        (Language::En, Text::ConnectorKind) => "Connector Type",
        (Language::En, Text::ConnectorLocalProbe) => "Local Network Probe",
        (Language::En, Text::ConnectorWebsiteProbe) => "Website Probe",
        (Language::En, Text::ConnectorHttpJson) => "HTTP/JSON Lab Adapter",
        (Language::En, Text::ConnectorPrometheusQuery) => "Prometheus query_range",
        (Language::En, Text::ConnectorPrometheusMetrics) => "Prometheus /metrics",
        (Language::En, Text::ConnectorOtlpGrpc) => "OTLP gRPC Receiver",
        (Language::En, Text::ConnectorNativePcap) => "Rust Native Capture",
        (Language::En, Text::ConnectorSystemCounters) => "System Counters",
        (Language::En, Text::SourceProfile) => "Source Profile",
        (Language::En, Text::ProfileName) => "Profile Name",
        (Language::En, Text::PrometheusBaseUrl) => "Prometheus URL",
        (Language::En, Text::PrometheusMetricsEndpoint) => "Metrics Endpoint",
        (Language::En, Text::PrometheusLookback) => "Lookback Seconds",
        (Language::En, Text::PrometheusStep) => "Step Seconds",
        (Language::En, Text::ProbeSamples) => "Probe Samples",
        (Language::En, Text::ProbeTargets) => "Probe Targets",
        (Language::En, Text::OtlpBindAddr) => "OTLP Bind Address",
        (Language::En, Text::CaptureSource) => "Capture Source",
        (Language::En, Text::PacketLimit) => "Packet Limit",
        (Language::En, Text::CaptureTimeout) => "Capture Timeout",
        (Language::En, Text::CaptureSession) => "Capture Session",
        (Language::En, Text::StartReceiver) => "Start Receiver",
        (Language::En, Text::StartCapture) => "Start Capture",
        (Language::En, Text::CancelCapture) => "Cancel Capture",
        (Language::En, Text::DiagnoseLastSample) => "Diagnose Last Sample",
        (Language::En, Text::StopReceiver) => "Stop Receiver",
        (Language::En, Text::DiagnoseBuffer) => "Diagnose Buffer",
        (Language::En, Text::CaptureProgress) => "Capture Progress",
        (Language::En, Text::CaptureRunning) => "Capturing",
        (Language::En, Text::CaptureCompleted) => "Capture Completed",
        (Language::En, Text::CaptureCancelled) => "Capture Cancelled",
        (Language::En, Text::CaptureFailed) => "Capture Failed",
        (Language::En, Text::SystemInterface) => "Interface",
        (Language::En, Text::SamplingInterval) => "Sampling Interval",
        (Language::En, Text::HttpJsonConnectorHint) => {
            "HTTP/JSON uses the Live API URL and Keychain token below"
        }
        (Language::En, Text::ConnectorHealth) => "Connector Health",
        (Language::En, Text::MeasurementQuality) => "Measurement Quality",
        (Language::En, Text::MissingMetrics) => "Missing Metrics",
        (Language::En, Text::LastSample) => "Last Sample",
        (Language::En, Text::ImportTopology) => "Import Topology",
        (Language::En, Text::ExportTopology) => "Export Topology",
        (Language::En, Text::CustomTopology) => "Custom Topology",
        (Language::En, Text::StartupOverview) => "Overview",
        (Language::En, Text::StartupTelemetry) => "Telemetry",
        (Language::En, Text::StartupDiagnosis) => "Diagnosis",
        (Language::En, Text::StartupRuleMl) => "Rule vs ML",
        (Language::En, Text::StartupDigitalTwin) => "Digital Twin",
        (Language::En, Text::StartupWhatIf) => "What-if",
        (Language::En, Text::StartupReports) => "Reports",
        (Language::En, Text::StartupSettings) => "Settings",
    }
}

fn settings_separator(ui: &mut egui::Ui) {
    ui.add_space(12.0);
    ui.separator();
    ui.add_space(12.0);
}

fn setting_caption(ui: &mut egui::Ui, text: &str) {
    ui.set_min_width(180.0);
    ui.label(RichText::new(text).size(12.0).color(MUTED));
}

fn default_source_label(source: DefaultSource, lang: Language) -> &'static str {
    match source {
        DefaultSource::Simulation => tr(lang, Text::DefaultSourceSimulation),
        DefaultSource::LastImportedFile => tr(lang, Text::DefaultSourceLastImport),
        DefaultSource::LiveApi => tr(lang, Text::DefaultSourceLiveApi),
    }
}

fn connector_kind_label(connector: ConnectorKind, lang: Language) -> &'static str {
    match connector {
        ConnectorKind::LocalProbe => tr(lang, Text::ConnectorLocalProbe),
        ConnectorKind::WebsiteProbe => tr(lang, Text::ConnectorWebsiteProbe),
        ConnectorKind::HttpJson => tr(lang, Text::ConnectorHttpJson),
        ConnectorKind::PrometheusQueryRange => tr(lang, Text::ConnectorPrometheusQuery),
        ConnectorKind::PrometheusExposition => tr(lang, Text::ConnectorPrometheusMetrics),
        ConnectorKind::OtlpGrpcReceiver => tr(lang, Text::ConnectorOtlpGrpc),
        ConnectorKind::NativePcap => tr(lang, Text::ConnectorNativePcap),
        ConnectorKind::SystemCounters => tr(lang, Text::ConnectorSystemCounters),
    }
}

fn startup_tab_label(tab: StartupTab, lang: Language) -> &'static str {
    match tab {
        StartupTab::Overview => tr(lang, Text::StartupOverview),
        StartupTab::Telemetry => tr(lang, Text::StartupTelemetry),
        StartupTab::Diagnosis => tr(lang, Text::StartupDiagnosis),
        StartupTab::RuleMl => tr(lang, Text::StartupRuleMl),
        StartupTab::DigitalTwin => tr(lang, Text::StartupDigitalTwin),
        StartupTab::WhatIf => tr(lang, Text::StartupWhatIf),
        StartupTab::Reports => tr(lang, Text::StartupReports),
        StartupTab::Settings => tr(lang, Text::StartupSettings),
    }
}

fn sim_scenario_label(scenario: SimScenario, lang: Language) -> &'static str {
    match scenario {
        SimScenario::Normal => fault_label_display(FaultLabel::Normal, lang),
        SimScenario::Congestion => fault_label_display(FaultLabel::Congestion, lang),
        SimScenario::RandomLoss => fault_label_display(FaultLabel::RandomLoss, lang),
        SimScenario::DnsFailure => fault_label_display(FaultLabel::DnsFailure, lang),
        SimScenario::TlsFailure => fault_label_display(FaultLabel::TlsFailure, lang),
        SimScenario::UdpQuicBlocked => fault_label_display(FaultLabel::UdpQuicBlocked, lang),
    }
}

fn topology_display(key: &str) -> String {
    if key == "custom" {
        return "custom topology".to_string();
    }
    key.replace('_', " ")
}

fn action_display(key: &str) -> String {
    key.replace('_', " ")
}

fn open_path(path: &Path) -> std::io::Result<()> {
    Command::new("open").arg(path).spawn().map(|_| ())
}

fn manifest_artifacts(run_dir: &Path) -> anyhow::Result<Vec<(String, PathBuf)>> {
    let file = fs::File::open(run_dir.join("manifest.json"))?;
    let manifest: RunManifest = serde_json::from_reader(file)?;
    let mut entries = manifest
        .artifact_paths
        .into_iter()
        .filter_map(|(key, value)| {
            if key == "run_id" {
                return None;
            }
            let path = PathBuf::from(value);
            let path = if path.is_absolute() {
                path
            } else {
                run_dir.join(path)
            };
            Some((key, path))
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

fn model_cache_status(root: &Path, lang: Language) -> String {
    let model = root.join("model").join("rust_logistic_model.json");
    match fs::metadata(&model) {
        Ok(metadata) => format_bytes(metadata.len()),
        Err(_) => tr(lang, Text::NotAvailable).to_string(),
    }
}

fn configure_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    if let Some(font) = load_font(UI_FONT_CANDIDATES) {
        fonts
            .font_data
            .insert("netdiag_ui".to_string(), Arc::new(font));
        insert_font_family(&mut fonts, egui::FontFamily::Proportional, 0, "netdiag_ui");
    }

    if let Some(font) = load_font(MONO_FONT_CANDIDATES) {
        fonts
            .font_data
            .insert("netdiag_mono".to_string(), Arc::new(font));
        insert_font_family(&mut fonts, egui::FontFamily::Monospace, 0, "netdiag_mono");
    }

    fonts.font_data.insert(
        "netdiag_cjk".to_string(),
        Arc::new(egui::FontData::from_static(CJK_FONT_BYTES)),
    );
    insert_font_family(&mut fonts, egui::FontFamily::Proportional, 1, "netdiag_cjk");
    insert_font_family(&mut fonts, egui::FontFamily::Monospace, 1, "netdiag_cjk");

    fonts.font_data.insert(
        "netdiag_remixicon".to_string(),
        Arc::new(egui::FontData::from_static(egui_remixicon::FONT)),
    );
    fonts
        .families
        .insert(icon_font_family(), vec!["netdiag_remixicon".to_string()]);

    ctx.set_fonts(fonts);
}

fn insert_font_family(
    fonts: &mut egui::FontDefinitions,
    family: egui::FontFamily,
    index: usize,
    font_name: &str,
) {
    let font_names = fonts.families.entry(family).or_default();
    let index = index.min(font_names.len());
    font_names.insert(index, font_name.to_string());
}

fn icon_font(size: f32) -> FontId {
    FontId::new(size, icon_font_family())
}

fn icon_font_family() -> egui::FontFamily {
    egui::FontFamily::Name("netdiag_icons".into())
}

const CJK_FONT_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/fonts/NotoSansCJKsc-Regular.otf"
));

const UI_FONT_CANDIDATES: &[(&str, u32)] = &[
    ("/System/Library/Fonts/SFNS.ttf", 0),
    ("/System/Library/Fonts/SFCompact.ttf", 0),
    ("/System/Library/Fonts/HelveticaNeue.ttc", 0),
];

const MONO_FONT_CANDIDATES: &[(&str, u32)] = &[
    ("/System/Library/Fonts/SFNSMono.ttf", 0),
    ("/System/Library/Fonts/SFNS.ttf", 0),
];

fn load_font(candidates: &[(&str, u32)]) -> Option<egui::FontData> {
    candidates.iter().find_map(|(path, index)| {
        let bytes = fs::read(path).ok()?;
        Some(egui::FontData {
            index: *index,
            ..egui::FontData::from_owned(bytes)
        })
    })
}

fn telemetry_headers(lang: Language) -> [&'static str; 7] {
    match lang {
        Language::Zh => ["窗口", "行数", "P50 ms", "P95 ms", "抖动", "丢包 %", "Mbps"],
        Language::En => [
            "Window", "Rows", "P50 ms", "P95 ms", "Jitter", "Loss %", "Mbps",
        ],
    }
}

fn metric_label(key: &str, lang: Language) -> &'static str {
    match (lang, key) {
        (Language::Zh, "latency_p50") => "延迟 (P50)",
        (Language::Zh, "latency_p95") => "延迟 (P95)",
        (Language::Zh, "jitter") => "抖动",
        (Language::Zh, "packet_loss") => "丢包率",
        (Language::Zh, "retransmission") => "重传率",
        (Language::Zh, "throughput") => "吞吐量",
        (_, "latency_p50") => "Latency (P50)",
        (_, "latency_p95") => "Latency (P95)",
        (_, "jitter") => "Jitter",
        (_, "packet_loss") => "Packet Loss",
        (_, "retransmission") => "Retransmission Rate",
        (_, "throughput") => "Throughput",
        _ => "Metric",
    }
}

fn fault_label_display(label: FaultLabel, lang: Language) -> &'static str {
    match (lang, label) {
        (Language::Zh, FaultLabel::Normal) => "路径正常",
        (Language::Zh, FaultLabel::Congestion) => "检测到拥塞",
        (Language::Zh, FaultLabel::RandomLoss) => "检测到随机丢包",
        (Language::Zh, FaultLabel::DnsFailure) => "检测到 DNS 故障",
        (Language::Zh, FaultLabel::TlsFailure) => "检测到 TLS 故障",
        (Language::Zh, FaultLabel::UdpQuicBlocked) => "检测到 QUIC 阻断",
        (Language::En, FaultLabel::Normal) => "Normal Path",
        (Language::En, FaultLabel::Congestion) => "Congestion Detected",
        (Language::En, FaultLabel::RandomLoss) => "Random Loss Detected",
        (Language::En, FaultLabel::DnsFailure) => "DNS Failure Detected",
        (Language::En, FaultLabel::TlsFailure) => "TLS Failure Detected",
        (Language::En, FaultLabel::UdpQuicBlocked) => "QUIC Blocked",
    }
}

fn fault_label_from_str(value: &str, lang: Language) -> String {
    value
        .parse::<FaultLabel>()
        .map(|label| fault_label_display(label, lang).to_string())
        .unwrap_or_else(|_| value.replace('_', " "))
}

#[derive(Default)]
struct MetricQualityCounts {
    measured: usize,
    estimated: usize,
    fallback: usize,
    missing: usize,
}

fn metric_quality_counts(snapshot: &SourceSnapshot) -> MetricQualityCounts {
    metric_quality_counts_from_provenance(&snapshot.ingest.metric_provenance)
}

fn metric_quality_counts_from_provenance(provenance: &[MetricProvenance]) -> MetricQualityCounts {
    let mut counts = MetricQualityCounts::default();
    for item in provenance {
        match item.quality {
            MetricQuality::Measured => counts.measured += 1,
            MetricQuality::Estimated => counts.estimated += 1,
            MetricQuality::Fallback => counts.fallback += 1,
            MetricQuality::Missing => counts.missing += 1,
        }
    }
    counts
}

fn short_run_id(run_id: &str) -> &str {
    run_id.get(..8).unwrap_or(run_id)
}

fn format_delta(label: &str, value: Option<f64>, unit: &str) -> String {
    value
        .map(|value| format!("{label} {value:+.1}{unit}"))
        .unwrap_or_else(|| format!("{label} n/a"))
}

fn comparison_agreement_text(agreement: bool, lang: Language) -> &'static str {
    match (lang, agreement) {
        (Language::Zh, true) => "规则和 ML 对主故障类别判断一致。",
        (Language::Zh, false) => "规则和 ML 的首选判断不一致，请复核置信度与证据。",
        (Language::En, true) => "Rule and ML agree on the leading fault class.",
        (Language::En, false) => {
            "Rule and ML disagree on the top prediction; check confidence and evidence."
        }
    }
}

fn approval_display(approval_required: bool, lang: Language) -> &'static str {
    match (lang, approval_required) {
        (Language::Zh, true) => "需要",
        (Language::Zh, false) => "不需要",
        (Language::En, true) => "required",
        (Language::En, false) => "not required",
    }
}

fn hil_state_display(state: HilState, lang: Language) -> &'static str {
    match (lang, state) {
        (Language::Zh, HilState::Unreviewed) => "待复核",
        (Language::Zh, HilState::Accepted) => "已通过",
        (Language::Zh, HilState::Rejected) => "已驳回",
        (Language::Zh, HilState::Uncertain) => "不确定",
        (Language::Zh, HilState::RequiresRerun) => "需要重跑",
        (Language::En, HilState::Unreviewed) => "Pending Review",
        (Language::En, HilState::Accepted) => "Accepted",
        (Language::En, HilState::Rejected) => "Rejected",
        (Language::En, HilState::Uncertain) => "Uncertain",
        (Language::En, HilState::RequiresRerun) => "Requires Rerun",
    }
}

fn hil_state_color(state: HilState) -> Color32 {
    match state {
        HilState::Unreviewed => ORANGE,
        HilState::Accepted => GREEN,
        HilState::Rejected | HilState::RequiresRerun => RED,
        HilState::Uncertain => PURPLE,
    }
}

fn data_source_display(
    snapshot: Option<&SourceSnapshot>,
    fallback: &str,
    lang: Language,
) -> String {
    let Some(snapshot) = snapshot else {
        return fallback.to_string();
    };
    format!(
        "{} · {}",
        source_kind_display(snapshot.descriptor.kind.as_str(), lang),
        source_label_display(snapshot.descriptor.data_source_label.as_str(), lang)
    )
}

fn source_kind_display(kind: &str, lang: Language) -> &str {
    match (lang, kind) {
        (Language::Zh, "Trace File") => "Trace 文件",
        (Language::Zh, "Simulation") => "仿真",
        (Language::Zh, "Live API") => "真实 API",
        (Language::Zh, "Local Probe") => "本机网络探针",
        (Language::Zh, "Website Probe") => "网站探针",
        _ => kind,
    }
}

fn source_label_display(label: &str, lang: Language) -> String {
    match (lang, label) {
        (Language::Zh, "Imported trace") => "导入 Trace".to_string(),
        (Language::Zh, "Live API") => "真实 API".to_string(),
        (Language::Zh, "Local host network stack") => "本机网络栈".to_string(),
        (Language::Zh, "Simulation: normal") => "仿真：正常".to_string(),
        (Language::Zh, "Simulation: congestion") => "仿真：拥塞".to_string(),
        (Language::Zh, "Simulation: random loss") => "仿真：随机丢包".to_string(),
        (Language::Zh, "Simulation: DNS failure") => "仿真：DNS 故障".to_string(),
        (Language::Zh, "Simulation: TLS failure") => "仿真：TLS 故障".to_string(),
        (Language::Zh, "Simulation: QUIC blocked") => "仿真：QUIC 阻断".to_string(),
        _ => label.to_string(),
    }
}

fn captured_label_display(label: &str, lang: Language) -> String {
    if lang == Language::En {
        return label.to_string();
    }
    label
        .replace("Captured", "采集")
        .replace("Simulated", "仿真")
        .replace("Fetched", "获取")
        .replace("Probed", "探测")
}

fn talker_label_display(label: &str, lang: Language) -> String {
    match (lang, label) {
        (Language::Zh, "Others") => "其他".to_string(),
        _ => label.to_string(),
    }
}

fn json_value_text(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::Number(number)) => number
            .as_f64()
            .map(format_compact_float)
            .unwrap_or_else(|| number.to_string()),
        Some(serde_json::Value::String(text)) => text.clone(),
        Some(serde_json::Value::Bool(value)) => value.to_string(),
        Some(serde_json::Value::Null) | None => "-".to_string(),
        Some(value) => value.to_string(),
    }
}

fn format_compact_float(value: f64) -> String {
    let formatted = if value.abs() >= 100.0 {
        format!("{value:.1}")
    } else if value.abs() >= 10.0 {
        format!("{value:.2}")
    } else {
        format!("{value:.3}")
    };
    formatted
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

fn status_for_result(result: &PipelineResult) -> &'static str {
    let hil_summary = HilReviewSummary::from_recommendations(&result.recommendations);
    if hil_summary.requires_rerun > 0 {
        return "Requires rerun";
    }
    if hil_summary.pending > 0 {
        return "Review";
    }
    let leading = result
        .diagnosis_events
        .first()
        .map(|event| event.evidence.symptom)
        .unwrap_or(FaultLabel::Normal);
    if leading == FaultLabel::Normal {
        "Healthy"
    } else {
        "Reviewed"
    }
}

fn rule_confidence(result: &PipelineResult) -> f64 {
    result
        .diagnosis_events
        .iter()
        .map(|event| event.evidence.confidence)
        .fold(0.0, f64::max)
}

fn status_display(status: &str, lang: Language) -> &'static str {
    match (lang, status) {
        (Language::Zh, "Healthy") => "健康",
        (Language::Zh, "Review") => "待复核",
        (Language::Zh, "Reviewed") => "已复核",
        (Language::Zh, "Requires rerun") => "需要重跑",
        (Language::Zh, "Ready") => "就绪",
        (Language::Zh, "Needs attention") => "需要关注",
        (_, "Healthy") => "Healthy",
        (_, "Review") => "Review",
        (_, "Reviewed") => "Reviewed",
        (_, "Requires rerun") => "Requires rerun",
        (_, "Ready") => "Ready",
        (_, "Needs attention") => "Needs attention",
        (Language::Zh, _) => "未知",
        (Language::En, _) => "Unknown",
    }
}

fn status_color(status: &str) -> Color32 {
    match status {
        "Healthy" | "Ready" | "Reviewed" => GREEN,
        "Review" => ORANGE,
        _ => RED,
    }
}

fn artifact_root_for_result(result: &PipelineResult) -> Option<PathBuf> {
    result
        .run_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
}

fn status_cell(
    painter: &egui::Painter,
    rect: Rect,
    label: &str,
    value: &str,
    value_color: Color32,
) {
    let y = rect.center().y;
    let label_w = if rect.width() >= 220.0 { 88.0 } else { 70.0 };
    let value_chars = ((rect.width() - label_w - 10.0) / 7.0).max(6.0) as usize;
    let value = truncate_middle(value, value_chars);
    painter.text(
        Pos2::new(rect.left(), y),
        Align2::LEFT_CENTER,
        label,
        FontId::proportional(12.0),
        MUTED,
    );
    painter.text(
        Pos2::new(rect.left() + label_w, y),
        Align2::LEFT_CENTER,
        value,
        FontId::proportional(12.0),
        value_color,
    );
}

fn truncate_middle(value: &str, max_chars: usize) -> String {
    let count = value.chars().count();
    if count <= max_chars {
        return value.to_string();
    }
    let keep = max_chars.saturating_sub(1) / 2;
    let start: String = value.chars().take(keep).collect();
    let end: String = value
        .chars()
        .rev()
        .take(keep)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{start}…{end}")
}

fn draw_background(ui: &mut egui::Ui, rect: Rect) {
    let mut mesh = Mesh::default();
    mesh.colored_vertex(rect.left_top(), Color32::from_rgb(230, 238, 255));
    mesh.colored_vertex(rect.right_top(), Color32::from_rgb(216, 226, 255));
    mesh.colored_vertex(rect.left_bottom(), Color32::from_rgb(112, 187, 238));
    mesh.colored_vertex(rect.right_bottom(), Color32::from_rgb(64, 134, 234));
    mesh.add_triangle(0, 1, 2);
    mesh.add_triangle(2, 1, 3);
    ui.painter().add(egui::Shape::mesh(mesh));

    let painter = ui.painter();
    let a = rect.left_top() + Vec2::new(0.0, rect.height() * 0.22);
    let b = rect.center() + Vec2::new(rect.width() * 0.18, -rect.height() * 0.02);
    let c = rect.right_bottom() + Vec2::new(-rect.width() * 0.06, -rect.height() * 0.30);
    painter.line_segment([a, b], Stroke::new(42.0, Color32::from_white_alpha(22)));
    painter.line_segment(
        [b, c],
        Stroke::new(54.0, Color32::from_rgba_unmultiplied(76, 132, 226, 46)),
    );
    painter.line_segment(
        [
            rect.left_bottom() + Vec2::new(-rect.width() * 0.06, -rect.height() * 0.05),
            rect.center() + Vec2::new(-rect.width() * 0.18, rect.height() * 0.14),
        ],
        Stroke::new(34.0, Color32::from_rgba_unmultiplied(246, 207, 187, 42)),
    );
}

fn with_rect(ui: &mut egui::Ui, rect: Rect, add_contents: impl FnOnce(&mut egui::Ui)) {
    ui.scope_builder(
        UiBuilder::new()
            .max_rect(rect)
            .layout(Layout::top_down(Align::Min)),
        |ui| {
            ui.set_clip_rect(rect);
            add_contents(ui);
        },
    );
}

fn paint_glass(ui: &mut egui::Ui, rect: Rect, radius: u8, fill: Color32) {
    ui.painter()
        .rect_filled(rect, CornerRadius::same(radius), fill);
    ui.painter().rect_stroke(
        rect,
        CornerRadius::same(radius),
        Stroke::new(1.0, Color32::from_white_alpha(150)),
        egui::StrokeKind::Inside,
    );
}

fn glass_frame(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(Color32::from_white_alpha(78))
        .corner_radius(16)
        .stroke(Stroke::new(1.0, Color32::from_white_alpha(145)))
        .inner_margin(Margin::symmetric(16, 14))
        .show(ui, add_contents);
}

fn version_pill(ui: &mut egui::Ui) {
    egui::Frame::new()
        .fill(Color32::from_white_alpha(100))
        .corner_radius(10)
        .inner_margin(Margin::symmetric(8, 3))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                    .size(11.0)
                    .color(MUTED),
            );
        });
}

fn nav_item(ui: &mut egui::Ui, active: &mut Tab, tab: Tab, icon: &str, label: &str) {
    let selected = *active == tab;
    let (rect, response) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 52.0), Sense::click());
    if response.clicked() {
        *active = tab;
    }
    let fill = if selected {
        Color32::from_white_alpha(160)
    } else {
        Color32::from_white_alpha(70)
    };
    ui.painter().rect_filled(rect, 12, fill);
    ui.painter().rect_stroke(
        rect,
        12,
        Stroke::new(
            1.0,
            Color32::from_white_alpha(if selected { 190 } else { 80 }),
        ),
        egui::StrokeKind::Inside,
    );
    ui.painter().text(
        Pos2::new(rect.left() + 24.0, rect.center().y),
        Align2::CENTER_CENTER,
        icon,
        icon_font(20.0),
        if selected { BLUE } else { INK },
    );
    ui.painter().text(
        Pos2::new(rect.left() + 50.0, rect.center().y),
        Align2::LEFT_CENTER,
        label,
        FontId::proportional(14.0),
        if selected { Color32::BLACK } else { INK },
    );
}

fn user_chip(ui: &mut egui::Ui, language: Language) {
    egui::Frame::new()
        .fill(Color32::from_white_alpha(94))
        .corner_radius(12)
        .stroke(Stroke::new(1.0, Color32::from_white_alpha(130)))
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (avatar, _) = ui.allocate_exact_size(Vec2::splat(42.0), Sense::hover());
                ui.painter()
                    .circle_filled(avatar.center(), 21.0, Color32::from_rgb(72, 118, 125));
                ui.painter().circle_filled(
                    avatar.center() + Vec2::new(0.0, -5.0),
                    7.0,
                    Color32::from_rgb(245, 202, 142),
                );
                ui.painter().circle_filled(
                    avatar.center() + Vec2::new(0.0, 12.0),
                    13.0,
                    Color32::from_rgb(24, 92, 72),
                );
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(tr(language, Text::EngineerRole))
                            .size(12.0)
                            .color(INK),
                    );
                    ui.horizontal(|ui| {
                        small_status_dot(ui, GREEN);
                        ui.label(
                            RichText::new(tr(language, Text::Online))
                                .size(12.0)
                                .color(INK),
                        );
                    });
                });
            });
        });
}

fn action_button(ui: &mut egui::Ui, text: &str, primary: bool, enabled: bool) -> egui::Response {
    let button = egui::Button::new(RichText::new(text).size(15.0).strong())
        .fill(if primary {
            BLUE
        } else if !enabled {
            Color32::from_white_alpha(80)
        } else {
            Color32::from_white_alpha(150)
        })
        .stroke(Stroke::new(1.0, Color32::from_white_alpha(150)))
        .corner_radius(12)
        .min_size(Vec2::new(HEADER_ACTION_WIDTH, HEADER_ACTION_HEIGHT));
    ui.add_enabled(enabled, button)
}

fn soft_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).size(13.0).color(INK))
            .fill(Color32::from_white_alpha(130))
            .stroke(Stroke::new(1.0, Color32::from_white_alpha(140)))
            .corner_radius(8),
    )
}

fn summary_card(
    ui: &mut egui::Ui,
    icon: &str,
    label: &str,
    value: &str,
    caption: &str,
    size: Vec2,
) {
    let margin_x = 14.0;
    let margin_y = 12.0;
    let icon_size = if size.x < 150.0 { 38.0 } else { 42.0 };
    let text_width = (size.x - margin_x * 2.0 - icon_size - 12.0).max(42.0);
    let value_limit = if text_width < 72.0 { 11 } else { 18 };
    let caption_limit = if text_width < 72.0 { 14 } else { 22 };

    let outer = Rect::from_min_size(ui.max_rect().min, size).shrink(0.75);
    ui.painter()
        .rect_filled(outer, 14, Color32::from_white_alpha(92));
    ui.painter().rect_stroke(
        outer,
        14,
        Stroke::new(1.0, Color32::from_white_alpha(150)),
        egui::StrokeKind::Inside,
    );

    let content_rect = outer.shrink2(Vec2::new(margin_x, margin_y));
    let icon_rect = Rect::from_center_size(
        Pos2::new(
            content_rect.left() + icon_size * 0.5,
            content_rect.center().y,
        ),
        Vec2::splat(icon_size),
    );
    icon_box_at(ui, icon_rect, icon, BLUE);

    let rows = summary_card_text_rows(content_rect.center().y, !caption.is_empty());
    let text_x = icon_rect.right() + 12.0;
    let value_size = if value.len() > 12 { 16.0 } else { 19.0 };
    ui.painter().text(
        Pos2::new(text_x, rows.label_y),
        Align2::LEFT_CENTER,
        compact_text(label, caption_limit),
        FontId::proportional(12.0),
        MUTED,
    );
    ui.painter().text(
        Pos2::new(text_x, rows.value_y),
        Align2::LEFT_CENTER,
        compact_text(value, value_limit),
        FontId::proportional(value_size),
        Color32::BLACK,
    );
    if let Some(caption_y) = rows.caption_y
        && !caption.is_empty()
    {
        ui.painter().text(
            Pos2::new(text_x, caption_y),
            Align2::LEFT_CENTER,
            compact_text(caption, caption_limit),
            FontId::proportional(11.0),
            MUTED,
        );
    }
}

#[derive(Debug, Clone, Copy)]
struct SummaryTextRows {
    label_y: f32,
    value_y: f32,
    caption_y: Option<f32>,
}

fn summary_card_text_rows(center_y: f32, has_caption: bool) -> SummaryTextRows {
    if has_caption {
        SummaryTextRows {
            label_y: center_y - 26.0,
            value_y: center_y,
            caption_y: Some(center_y + 26.0),
        }
    } else {
        SummaryTextRows {
            label_y: center_y - 22.0,
            value_y: center_y,
            caption_y: None,
        }
    }
}

fn compact_text(text: &str, max_chars: usize) -> String {
    let count = text.chars().count();
    if count <= max_chars || max_chars < 8 {
        return text.to_string();
    }
    let head = (max_chars - 1) / 2;
    let tail = max_chars - 1 - head;
    let prefix = text.chars().take(head).collect::<String>();
    let suffix = text
        .chars()
        .rev()
        .take(tail)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("{prefix}…{suffix}")
}

fn section_title(ui: &mut egui::Ui, text: &str) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(text)
                .size(15.0)
                .strong()
                .color(Color32::BLACK),
        );
        ui.label(
            RichText::new(icons::INFORMATION_LINE)
                .font(icon_font(12.0))
                .color(BLUE),
        );
    });
}

fn icon_box_at(ui: &mut egui::Ui, rect: Rect, icon: &str, color: Color32) {
    let size = rect.width().min(rect.height());
    let radius = (size * 0.29).round() as u8;
    let icon_size = size * 0.44;
    ui.painter()
        .rect_filled(rect, radius, Color32::from_white_alpha(110));
    ui.painter().rect_stroke(
        rect,
        radius,
        Stroke::new(1.0, Color32::from_white_alpha(90)),
        egui::StrokeKind::Inside,
    );
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        icon,
        icon_font(icon_size),
        color,
    );
}

fn metric_tile(
    ui: &mut egui::Ui,
    label: &str,
    value: String,
    color: Color32,
    points: &[f64],
    width: f32,
) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 86.0), Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 10, Color32::from_white_alpha(88));
    painter.rect_stroke(
        rect,
        10,
        Stroke::new(1.0, Color32::from_white_alpha(128)),
        egui::StrokeKind::Inside,
    );
    painter.text(
        rect.left_top() + Vec2::new(10.0, 12.0),
        Align2::LEFT_TOP,
        label,
        FontId::proportional(10.5),
        MUTED,
    );
    painter.text(
        rect.left_top() + Vec2::new(10.0, 34.0),
        Align2::LEFT_TOP,
        value,
        FontId::proportional(16.0),
        Color32::BLACK,
    );
    let spark = Rect::from_min_max(
        rect.left_bottom() + Vec2::new(10.0, -26.0),
        rect.right_bottom() + Vec2::new(-10.0, -8.0),
    );
    draw_sparkline(ui, spark, points, color);
}

fn draw_sparkline(ui: &mut egui::Ui, rect: Rect, values: &[f64], color: Color32) {
    let rect = Rect::from_min_size(rect.min, Vec2::new(rect.width().max(80.0), 24.0));
    let painter = ui.painter();
    let points = scaled_points(rect, values);
    for pair in points.windows(2) {
        painter.line_segment([pair[0], pair[1]], Stroke::new(1.5, color));
    }
}

fn draw_large_chart(
    ui: &mut egui::Ui,
    points: &[netdiag_app::trend::TrendPoint],
    range: TrendRange,
    height: f32,
) {
    let desired = Vec2::new(ui.available_width(), height.max(120.0));
    let (rect, _) = ui.allocate_exact_size(desired, Sense::hover());
    let inner = Rect::from_min_max(
        rect.left_top() + Vec2::new(48.0, 14.0),
        rect.right_bottom() - Vec2::new(18.0, 32.0),
    );
    let painter = ui.painter_at(rect);
    let max_value = points
        .iter()
        .map(|point| point.value_ms)
        .fold(0.0_f64, f64::max)
        .max(10.0);
    let y_max = nice_axis_max(max_value);
    for i in 0..4 {
        let y = inner.bottom() - inner.height() * i as f32 / 3.0;
        painter.line_segment(
            [Pos2::new(inner.left(), y), Pos2::new(inner.right(), y)],
            Stroke::new(1.0, Color32::from_gray(210)),
        );
        painter.text(
            Pos2::new(rect.left() + 6.0, y),
            Align2::LEFT_CENTER,
            format!("{:.0}ms", y_max * i as f64 / 3.0),
            FontId::proportional(12.0),
            MUTED,
        );
    }
    for i in 0..=6 {
        let x = inner.left() + inner.width() * i as f32 / 6.0;
        painter.line_segment(
            [Pos2::new(x, inner.top()), Pos2::new(x, inner.bottom())],
            Stroke::new(1.0, Color32::from_white_alpha(110)),
        );
        painter.text(
            Pos2::new(x, inner.bottom() + 16.0),
            Align2::CENTER_CENTER,
            format_time_tick(range.seconds() as f64 * i as f64 / 6.0),
            FontId::proportional(12.0),
            MUTED,
        );
    }
    let scaled = scaled_trend_points(inner, points, range.seconds() as f64, y_max);
    if scaled.len() >= 2 {
        let base_y = inner.bottom();
        let mut area = Mesh::default();
        for pair in scaled.windows(2) {
            let start = area.vertices.len() as u32;
            area.colored_vertex(pair[0], Color32::from_rgba_unmultiplied(126, 74, 232, 70));
            area.colored_vertex(pair[1], Color32::from_rgba_unmultiplied(126, 74, 232, 70));
            area.colored_vertex(
                Pos2::new(pair[0].x, base_y),
                Color32::from_rgba_unmultiplied(126, 74, 232, 22),
            );
            area.colored_vertex(
                Pos2::new(pair[1].x, base_y),
                Color32::from_rgba_unmultiplied(126, 74, 232, 22),
            );
            area.add_triangle(start, start + 1, start + 2);
            area.add_triangle(start + 1, start + 3, start + 2);
        }
        ui.painter().add(egui::Shape::mesh(area));
        for pair in scaled.windows(2) {
            painter.line_segment([pair[0], pair[1]], Stroke::new(2.0, PURPLE));
        }
    }
}

fn scaled_trend_points(
    rect: Rect,
    points: &[netdiag_app::trend::TrendPoint],
    range_seconds: f64,
    y_max: f64,
) -> Vec<Pos2> {
    if points.len() < 2 {
        return Vec::new();
    }
    let x_max = points
        .iter()
        .map(|point| point.elapsed_s)
        .fold(range_seconds.max(1.0), f64::max);
    points
        .iter()
        .map(|point| {
            let x = rect.left() + rect.width() * (point.elapsed_s / x_max).clamp(0.0, 1.0) as f32;
            let y = rect.bottom()
                - rect.height() * (point.value_ms / y_max.max(1.0)).clamp(0.0, 1.0) as f32;
            Pos2::new(x, y)
        })
        .collect()
}

fn nice_axis_max(value: f64) -> f64 {
    if value <= 50.0 {
        50.0
    } else if value <= 100.0 {
        100.0
    } else if value <= 300.0 {
        300.0
    } else if value <= 600.0 {
        600.0
    } else {
        (value / 100.0).ceil() * 100.0
    }
}

fn format_time_tick(seconds: f64) -> String {
    if seconds >= 60.0 {
        format!("{:.0}m", seconds / 60.0)
    } else {
        format!("{:.0}s", seconds)
    }
}

fn scaled_points(rect: Rect, values: &[f64]) -> Vec<Pos2> {
    if values.len() < 2 {
        return Vec::new();
    }
    let min_value = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max_value = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if !min_value.is_finite() || !max_value.is_finite() {
        return Vec::new();
    }
    let span = (max_value - min_value).max(1.0);
    values
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            let x = rect.left() + rect.width() * idx as f32 / (values.len() - 1) as f32;
            let normalized = ((*value - min_value) / span).clamp(0.0, 1.0) as f32;
            let y = rect.bottom() - rect.height() * normalized;
            Pos2::new(x, y)
        })
        .collect()
}

fn segmented_pill(ui: &mut egui::Ui, text: &str, selected: bool) -> egui::Response {
    let fill = if selected {
        Color32::from_white_alpha(170)
    } else {
        Color32::from_white_alpha(74)
    };
    ui.add(
        egui::Button::new(RichText::new(text).size(12.0).color(INK))
            .fill(fill)
            .stroke(Stroke::new(1.0, Color32::from_white_alpha(90)))
            .corner_radius(8)
            .min_size(Vec2::new(48.0, 28.0)),
    )
}

fn draw_topology(
    ui: &mut egui::Ui,
    width: f32,
    height: f32,
    topology: &str,
    action: &str,
    language: Language,
    model: Option<&TopologyModel>,
) {
    let desired = Vec2::new(width.max(320.0), height.max(180.0));
    let (rect, _) = ui.allocate_exact_size(desired, Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 16, Color32::from_white_alpha(82));
    painter.rect_stroke(
        rect,
        16,
        Stroke::new(1.0, Color32::from_white_alpha(130)),
        egui::StrokeKind::Inside,
    );

    let inner = rect.shrink2(Vec2::new(42.0, 34.0));
    let reroute = action.contains("reroute");
    let edge_color = if reroute { GREEN } else { BLUE };
    let (node_positions, labels, links): (Vec<Pos2>, Vec<String>, Vec<(usize, usize)>) =
        if let Some(model) = model {
            let count = model.nodes.len().clamp(2, 12);
            let radius_x = inner.width() * 0.38;
            let radius_y = inner.height() * 0.28;
            let center = inner.center();
            let positions = model
                .nodes
                .iter()
                .take(count)
                .enumerate()
                .map(|(idx, _)| {
                    let angle = std::f32::consts::TAU * idx as f32 / count as f32
                        - std::f32::consts::FRAC_PI_2;
                    Pos2::new(
                        center.x + radius_x * angle.cos(),
                        center.y + radius_y * angle.sin(),
                    )
                })
                .collect::<Vec<_>>();
            let index_by_id = model
                .nodes
                .iter()
                .take(count)
                .enumerate()
                .map(|(idx, node)| (node.id.as_str(), idx))
                .collect::<BTreeMap<_, _>>();
            let links = model
                .links
                .iter()
                .filter_map(|link| {
                    Some((
                        *index_by_id.get(link.source.as_str())?,
                        *index_by_id.get(link.target.as_str())?,
                    ))
                })
                .collect::<Vec<_>>();
            let labels = model
                .nodes
                .iter()
                .take(count)
                .map(|node| {
                    if node.label.is_empty() {
                        node.id.clone()
                    } else {
                        node.label.clone()
                    }
                })
                .collect::<Vec<_>>();
            (positions, labels, links)
        } else {
            let y = inner.center().y;
            let positions = vec![
                Pos2::new(inner.left(), y),
                Pos2::new(inner.left() + inner.width() * 0.34, y - 38.0),
                Pos2::new(inner.left() + inner.width() * 0.66, y + 34.0),
                Pos2::new(inner.right(), y),
            ];
            let labels = match language {
                Language::Zh => ["入口", "交换", "孪生", "服务"],
                Language::En => ["Ingress", "Switch", "Twin", "Service"],
            }
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
            (positions, labels, vec![(0, 1), (1, 2), (2, 3)])
        };

    for (left, right) in &links {
        painter.line_segment(
            [node_positions[*left], node_positions[*right]],
            Stroke::new(4.0, Color32::from_rgba_unmultiplied(55, 97, 220, 62)),
        );
        painter.line_segment(
            [node_positions[*left], node_positions[*right]],
            Stroke::new(1.8, edge_color),
        );
    }
    if reroute && node_positions.len() >= 4 {
        painter.line_segment(
            [node_positions[1], node_positions[3]],
            Stroke::new(2.5, Color32::from_rgba_unmultiplied(28, 160, 72, 145)),
        );
    }
    for (idx, pos) in node_positions.iter().enumerate() {
        let active = idx == 2 || (reroute && idx == 1);
        let color = if active { PURPLE } else { BLUE };
        painter.circle_filled(
            *pos,
            24.0,
            Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 42),
        );
        painter.circle_filled(*pos, 11.0, color);
        painter.text(
            *pos + Vec2::new(0.0, 36.0),
            Align2::CENTER_CENTER,
            labels.get(idx).map(String::as_str).unwrap_or("node"),
            FontId::proportional(13.0),
            INK,
        );
    }

    painter.text(
        rect.left_top() + Vec2::new(18.0, 16.0),
        Align2::LEFT_TOP,
        format!(
            "{}: {}  ·  {}: {}",
            tr(language, Text::Topology),
            topology,
            tr(language, Text::Action),
            action
        ),
        FontId::proportional(13.0),
        MUTED,
    );
}

fn alert_badge(ui: &mut egui::Ui, label: FaultLabel) {
    let color = if label == FaultLabel::Normal {
        GREEN
    } else {
        RED
    };
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
    ui.painter()
        .rect_filled(rect, 10, Color32::from_white_alpha(100));
    ui.painter().text(
        rect.center(),
        Align2::CENTER_CENTER,
        if label == FaultLabel::Normal {
            icons::CHECK_LINE
        } else {
            icons::ALERT_LINE
        },
        icon_font(22.0),
        color,
    );
}

fn confidence_chip(ui: &mut egui::Ui, confidence: f64, danger: bool) {
    egui::Frame::new()
        .fill(if danger {
            Color32::from_rgb(255, 216, 218)
        } else {
            Color32::from_rgb(214, 244, 218)
        })
        .corner_radius(10)
        .inner_margin(Margin::symmetric(10, 5))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("{confidence:.2}"))
                    .strong()
                    .color(if danger { RED } else { GREEN }),
            );
        });
}

fn bullet(ui: &mut egui::Ui, text: &str, color: Color32) {
    ui.horizontal(|ui| {
        small_status_dot(ui, color);
        ui.label(RichText::new(text).size(12.0).color(INK));
    });
}

fn comparison_box(
    ui: &mut egui::Ui,
    title: &str,
    label: &str,
    confidence: f64,
    color: Color32,
    confidence_label: &str,
) {
    egui::Frame::new()
        .fill(Color32::from_white_alpha(94))
        .corner_radius(12)
        .stroke(Stroke::new(1.0, Color32::from_white_alpha(130)))
        .inner_margin(Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_min_height(76.0);
            ui.label(RichText::new(title).size(12.0).color(MUTED));
            ui.label(RichText::new(label).size(16.0).strong().color(color));
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(confidence_label)
                        .size(11.0)
                        .color(Color32::BLACK),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    confidence_badge(ui, confidence, color);
                });
            });
        });
}

fn confidence_badge(ui: &mut egui::Ui, confidence: f64, color: Color32) {
    egui::Frame::new()
        .fill(Color32::from_rgba_unmultiplied(
            color.r(),
            color.g(),
            color.b(),
            32,
        ))
        .corner_radius(9)
        .inner_margin(Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("{confidence:.2}"))
                    .size(12.0)
                    .color(color),
            );
        });
}

fn status_circle(ui: &mut egui::Ui, ok: bool) {
    let color = if ok { GREEN } else { ORANGE };
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::hover());
    ui.painter().circle_filled(
        rect.center(),
        17.0,
        Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 45),
    );
    ui.painter().circle_filled(rect.center(), 9.0, color);
}

fn draw_donut(ui: &mut egui::Ui, rect: Rect, dashboard: &DashboardViewModel, language: Language) {
    let center = rect.center();
    let size = rect.width().min(rect.height());
    let outer = size * 0.48;
    let inner = outer * 0.65;
    if dashboard.top_talkers.is_empty() {
        donut_segment(
            ui,
            center,
            inner,
            outer,
            0.0,
            std::f32::consts::TAU,
            Color32::from_rgb(132, 150, 178),
        );
    } else {
        let mut start = -std::f32::consts::FRAC_PI_2;
        let mut covered = 0.0_f32;
        for (idx, talker) in dashboard.top_talkers.iter().take(4).enumerate() {
            let portion = talker.share.clamp(0.01, 1.0) as f32;
            let end = start + std::f32::consts::TAU * portion;
            donut_segment(ui, center, inner, outer, start, end, talker_color(idx));
            start = end;
            covered += portion;
        }
        if covered < 0.99 {
            donut_segment(
                ui,
                center,
                inner,
                outer,
                start,
                -std::f32::consts::FRAC_PI_2 + std::f32::consts::TAU,
                Color32::from_rgb(132, 150, 178),
            );
        }
    }
    ui.painter()
        .circle_filled(center, inner - 2.0, Color32::from_white_alpha(105));
    let caption_size = (size * 0.085).clamp(9.5, 11.5);
    let value_size = if dashboard.total_traffic.len() > 8 {
        (size * 0.11).clamp(12.0, 16.0)
    } else {
        (size * 0.125).clamp(13.0, 17.0)
    };
    let spread = (caption_size + value_size) * 0.45;
    ui.painter().text(
        center + Vec2::new(0.0, -spread),
        Align2::CENTER_CENTER,
        tr(language, Text::Total),
        FontId::proportional(caption_size),
        MUTED,
    );
    ui.painter().text(
        center + Vec2::new(0.0, spread),
        Align2::CENTER_CENTER,
        &dashboard.total_traffic,
        FontId::proportional(value_size),
        Color32::BLACK,
    );
}

fn talker_color(idx: usize) -> Color32 {
    match idx {
        0 => BLUE,
        1 => PURPLE,
        2 => ORANGE,
        _ => Color32::from_rgb(132, 150, 178),
    }
}

fn donut_segment(
    ui: &mut egui::Ui,
    center: Pos2,
    inner: f32,
    outer: f32,
    start: f32,
    end: f32,
    color: Color32,
) {
    let steps = 36;
    let mut mesh = Mesh::default();
    for idx in 0..=steps {
        let t = start + (end - start) * idx as f32 / steps as f32;
        let dir = Vec2::new(t.cos(), t.sin());
        mesh.colored_vertex(center + dir * outer, color);
        mesh.colored_vertex(
            center + dir * inner,
            Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 190),
        );
    }
    for idx in 0..steps {
        let base = (idx * 2) as u32;
        mesh.add_triangle(base, base + 1, base + 2);
        mesh.add_triangle(base + 1, base + 3, base + 2);
    }
    ui.painter().add(egui::Shape::mesh(mesh));
}

fn legend_row(ui: &mut egui::Ui, color: Color32, title: &str, detail: &str, row_h: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), row_h), Sense::hover());
    let painter = ui.painter_at(rect);
    let dot_center = Pos2::new(rect.left() + 7.0, rect.top() + row_h * 0.34);
    painter.circle_filled(dot_center, 5.0, color);

    let compact = row_h < 32.0;
    let title_size = if compact { 12.0 } else { 13.0 };
    let detail_size = if compact { 10.8 } else { 12.0 };
    let text_x = rect.left() + 22.0;
    painter.text(
        Pos2::new(text_x, rect.top()),
        Align2::LEFT_TOP,
        title,
        FontId::proportional(title_size),
        INK,
    );
    painter.text(
        Pos2::new(text_x, rect.top() + row_h * 0.52),
        Align2::LEFT_TOP,
        detail,
        FontId::proportional(detail_size),
        MUTED,
    );
}

fn small_status_dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 5.0, color);
}

fn format_number(value: u64) -> String {
    let text = value.to_string();
    let mut out = String::new();
    for (idx, ch) in text.chars().rev().enumerate() {
        if idx > 0 && idx % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

fn short_id(run_id: &str) -> String {
    run_id.chars().take(18).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_cjk_font_contains_required_chinese_glyphs() {
        let face = ttf_parser::Face::parse(CJK_FONT_BYTES, 0).expect("bundled CJK font parses");

        for ch in "概览诊断规则数字孪生设置导入仿真真实拥塞".chars() {
            assert!(
                face.glyph_index(ch).is_some(),
                "bundled CJK font is missing {ch}"
            );
        }
    }

    #[test]
    fn compact_text_middle_truncates_long_values() {
        let text = compact_text("sim.congestion.long.trace.name", 14);
        assert!(text.contains('…'));
        assert!(text.len() < "sim.congestion.long.trace.name".len());
    }

    #[test]
    fn summary_card_rows_center_value_with_icon_when_no_caption() {
        let rows = summary_card_text_rows(80.0, false);
        assert_eq!(rows.caption_y, None);
        assert_eq!(rows.label_y, 58.0);
        assert_eq!(rows.value_y, 80.0);
    }

    #[test]
    fn summary_card_rows_keep_trace_text_group_balanced() {
        let rows = summary_card_text_rows(80.0, true);
        assert_eq!(rows.label_y, 54.0);
        assert_eq!(rows.value_y, 80.0);
        assert_eq!(rows.caption_y, Some(106.0));
        let group_center = (rows.label_y + rows.caption_y.unwrap()) / 2.0;
        assert!((group_center - 80.0).abs() < 0.1);
    }
}
