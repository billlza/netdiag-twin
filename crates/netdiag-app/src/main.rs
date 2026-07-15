use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, FontId, Layout, Margin, Mesh, Pos2, Rect, RichText,
    Sense, Stroke, UiBuilder, Vec2,
};
use egui_remixicon::icons;
use netdiag_app::connector_auth::{bearer_scope_for_endpoint, profile_bearer_scope};
use netdiag_app::credential_lifecycle::{
    LegacyCredentialMigration, delete_bearer_credentials, delete_live_api_credentials,
    has_stale_active_binding, legacy_live_api_binding, migrate_legacy_live_api_credential,
    profile_binding, reconcile_inactive_profile_credentials,
    resume_pending_live_api_credential_deletion, store_bearer_credential,
};
use netdiag_app::data_source::{SimScenario, SourceMode, SourceSnapshot, native_pcap_source};
use netdiag_app::layout::{
    HEADER_ACTION_HEIGHT, HEADER_ACTION_WIDTH, OVERVIEW_MIN_CONTENT_HEIGHT, SUMMARY_CARD_HEIGHT,
    overview_content_height, summary_card_rects,
};
#[cfg(target_os = "macos")]
use netdiag_app::secrets::KeychainSecretStore;
#[cfg(not(target_os = "macos"))]
use netdiag_app::secrets::MemorySecretStore;
use netdiag_app::secrets::{BearerSecretPresence, BearerSecretPresenceCache, SecretStore};
use netdiag_app::settings::{
    self, AppSettings, BearerCredentialOwner, ConnectorAuthentication, ConnectorKind,
    DefaultSource, LanguageSetting, SettingsStore, StartupTab,
};
use netdiag_app::trend::{LatencyMetric, TrendRange, latency_trend_points};
use netdiag_app::updater::{UpdateCheckOutcome, sparkle_check_for_updates, sparkle_status};
use netdiag_app::view_model::{DashboardViewModel, format_bytes};
use netdiag_core::authentication::BearerSourceKind;
use netdiag_core::connectors::{
    CaptureControl, CaptureProgress, NativePcapConfig, OtlpGrpcReceiverConfig, OtlpReceiverSession,
    OtlpShutdownOutcome, SystemCountersConfig, load_native_pcap_with_control,
    load_system_counters_with_control,
};
use netdiag_core::hil_review::review_recommendation;
use netdiag_core::lab::{
    LabAcceptanceReport, LabPreflightReport, LabRunIndexEntry, LabRunResult, LabSummaryReport,
    read_lab_run_index,
};
use netdiag_core::ml::FeedbackExportSummary;
use netdiag_core::models::{
    ConnectorHealthSnapshot, ConnectorHealthStatus, FaultLabel, HilReviewSummary, HilState,
    MetricProvenance, MetricQuality, RunEvidenceSummary, RunHistoryFilter, RunTimelineEvent,
    TopologyModel,
};
use netdiag_core::storage::{
    clear_run_history as clear_stored_run_history, compare_runs, list_run_timeline, run_artifacts,
    run_evidence,
};
use netdiag_core::twin::{action_names, load_topology_file, policy_action, topology_names};
use netdiag_core::{
    PipelineResult, WhatIfRequest, diagnose_ingest_with_whatif_and_connector_health,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::Duration;
use std::{fs, thread};
use zeroize::{Zeroize, Zeroizing};

const BLUE: Color32 = Color32::from_rgb(37, 88, 225);
const PURPLE: Color32 = Color32::from_rgb(122, 56, 230);
const GREEN: Color32 = Color32::from_rgb(28, 160, 72);
const ORANGE: Color32 = Color32::from_rgb(238, 139, 24);
const RED: Color32 = Color32::from_rgb(232, 58, 53);
const INK: Color32 = Color32::from_rgb(18, 28, 48);
const MUTED: Color32 = Color32::from_rgb(78, 88, 118);

mod api_test;
#[cfg(test)]
mod app_tests;
mod capture_session;
mod confirmation;
mod connector_flow;
mod lab_runtime;
mod model_cache;
#[cfg(target_os = "macos")]
mod native_menu;
mod pilot_run_center;
mod run_history;
mod settings_runtime;
mod source_selection;
mod topology_state;
mod translations;

use api_test::{ApiTestJob, ApiTestPoll, ApiTestStatus};
use capture_session::{CaptureSessionEvent, CaptureSessionPhase, CaptureSessionState};
use confirmation::TargetConfirmation;
use connector_flow::{
    CaptureSessionCompletion, capture_session_completion, source_snapshot_from_connector_session,
};
use model_cache::{ModelCacheState, rebuild_model_bundle};
use run_history::apply_run_history_clear_state;
use source_selection::{connector_source_mode_from_profile, source_mode_from_settings};
use topology_state::{selected_topology_model, write_topology_export};
use translations::tr;

#[cfg(target_os = "macos")]
use native_menu::{NativeMenu, NativeMenuCommand};

#[cfg(any(target_os = "macos", test))]
fn optional_path_metadata(
    result: std::io::Result<fs::Metadata>,
) -> std::io::Result<Option<fs::Metadata>> {
    match result {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

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
    Lab,
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
#[repr(usize)]
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
    ReviewState,
    RootCauses,
    Recommendations,
    Evidence,
    EvidenceConsole,
    Timeline,
    SelectedRun,
    CompareLeft,
    CompareRight,
    CompareRuns,
    QualityStatus,
    WarningCount,
    QualityDelta,
    NoRunSelected,
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
    ConnectionStale,
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
    CaptureCancelling,
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
    StartupLab,
    StartupReports,
    StartupSettings,
    Count,
}

struct NetDiagApp {
    #[cfg(target_os = "macos")]
    native_menu: Option<NativeMenu>,
    tab: Tab,
    language: Language,
    settings: AppSettings,
    settings_store: SettingsStore,
    settings_persistence_authorized: bool,
    secrets: Arc<dyn SecretStore>,
    live_api_token_presence: BearerSecretPresenceCache,
    profile_token_presence: BearerSecretPresenceCache,
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
    token_input: Zeroizing<String>,
    profile_token_input: Zeroizing<String>,
    probe_targets_text: String,
    hil_notes: BTreeMap<String, String>,
    settings_notice: Option<String>,
    update_notice: Option<String>,
    api_test_status: Option<ApiTestStatus>,
    api_test_job: Option<ApiTestJob>,
    api_test_credential_revision: u64,
    capture_session: Option<CaptureSessionState>,
    evidence_timeline_loaded: bool,
    evidence_timeline: Vec<RunTimelineEvent>,
    evidence_timeline_error: Option<String>,
    selected_evidence: Option<RunEvidenceSummary>,
    evidence_compare_left: Option<String>,
    evidence_compare_right: Option<String>,
    lab_scenario_path: String,
    lab_preflight: Option<LabPreflightReport>,
    lab_last_run: Option<LabRunResult>,
    lab_runs: Vec<LabRunIndexEntry>,
    lab_summary: Option<LabSummaryReport>,
    lab_job: Option<LabJob>,
    lab_status: Option<String>,
    pilot_center: pilot_run_center::PilotRunCenterState,
    pending_delete_token: bool,
    pending_delete_profile_token: TargetConfirmation<String>,
    pending_clear_runs: TargetConfirmation<PathBuf>,
    pending_rebuild_model: TargetConfirmation<PathBuf>,
    model_cache_state: ModelCacheState,
    status: String,
    error: Option<String>,
}

type DiagnosisJob = mpsc::Receiver<anyhow::Result<(PipelineResult, SourceSnapshot)>>;
type LabJob = mpsc::Receiver<anyhow::Result<LabJobOutcome>>;

#[derive(Debug)]
enum LabJobOutcome {
    Preflight(LabPreflightReport),
    Run(Box<LabRunResult>),
    Summary(LabSummaryReport),
    DatasetExport(FeedbackExportSummary),
}

impl NetDiagApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        configure_fonts(&cc.egui_ctx);
        let settings_store = SettingsStore::new(SettingsStore::default_path());
        let settings_load = settings_store.load_for_startup();
        let startup_authorized = settings_load.startup_authorized();
        let settings_warning = settings_load.warning;
        let mut settings = settings_load.settings;
        let normalize_warning =
            if startup_authorized && settings::normalize_bundle_settings(&mut settings) {
                settings_store
                    .save(&mut settings)
                    .err()
                    .map(|error| format!("{error:#}"))
            } else {
                None
            };
        let secrets = default_secret_store();
        let (credential_notice, credential_warning) = if startup_authorized {
            let recovery = resume_pending_live_api_credential_deletion(
                &settings_store,
                &mut settings,
                secrets.as_ref(),
            );
            let migration = migrate_legacy_live_api_credential(
                &settings_store,
                &mut settings,
                secrets.as_ref(),
            );
            let cleanup = reconcile_inactive_profile_credentials(
                &settings_store,
                &mut settings,
                secrets.as_ref(),
            );
            let notice = matches!(&migration, Ok(LegacyCredentialMigration::Migrated)).then(|| {
                "Legacy Live API credential migrated to its scoped Keychain entry".to_string()
            });
            let warning = [recovery.err(), migration.err(), cleanup.err()]
                .into_iter()
                .flatten()
                .map(|error| format!("credential lifecycle: {error:#}"))
                .collect::<Vec<_>>();
            (notice, (!warning.is_empty()).then(|| warning.join("; ")))
        } else {
            (None, None)
        };
        let (source_mode, source_warning) = if startup_authorized {
            source_mode_from_settings(&settings)
        } else {
            (
                SourceMode::Unavailable {
                    reason: "Settings were rejected; source execution is disabled until settings are repaired"
                        .to_string(),
                },
                None,
            )
        };
        let initial_language = Language::from(settings.language);
        #[cfg(target_os = "macos")]
        let (native_menu, menu_warning) = match NativeMenu::install(&cc.egui_ctx, initial_language)
        {
            Ok(menu) => (Some(menu), None),
            Err(err) => (None, Some(format!("native menu: {err}"))),
        };
        #[cfg(not(target_os = "macos"))]
        let menu_warning: Option<String> = None;
        let (lab_runs, lab_runs_warning) = match load_lab_runs_from_index(&settings.artifacts_root)
        {
            Ok(runs) => (runs, None),
            Err(err) => (Vec::new(), Some(format!("lab run index: {err}"))),
        };
        let startup_warnings = [
            settings_warning,
            normalize_warning,
            source_warning,
            credential_warning,
            menu_warning,
            lab_runs_warning,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let startup_warning = (!startup_warnings.is_empty()).then(|| startup_warnings.join("; "));
        let model_cache_state = ModelCacheState::load(&settings.artifacts_root);
        Self {
            #[cfg(target_os = "macos")]
            native_menu,
            tab: Tab::from(settings.startup.default_tab),
            language: initial_language,
            settings: settings.clone(),
            settings_store,
            settings_persistence_authorized: startup_authorized,
            secrets,
            live_api_token_presence: BearerSecretPresenceCache::default(),
            profile_token_presence: BearerSecretPresenceCache::default(),
            pending_startup_diagnosis: startup_authorized && settings.startup.auto_run_diagnosis,
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
            token_input: Zeroizing::new(String::new()),
            profile_token_input: Zeroizing::new(String::new()),
            probe_targets_text: settings
                .data_connectors
                .active_profile()
                .map(|profile| profile.website_probe.targets.join("\n"))
                .unwrap_or_else(|| settings.data_connectors.website_probe.targets.join("\n")),
            hil_notes: BTreeMap::new(),
            settings_notice: credential_notice.or_else(|| startup_warning.clone()),
            update_notice: None,
            api_test_status: None,
            api_test_job: None,
            api_test_credential_revision: 0,
            capture_session: None,
            evidence_timeline_loaded: false,
            evidence_timeline: Vec::new(),
            evidence_timeline_error: None,
            selected_evidence: None,
            evidence_compare_left: None,
            evidence_compare_right: None,
            lab_scenario_path: "examples/scenarios/lab-congestion-001.yaml".to_string(),
            lab_preflight: None,
            lab_last_run: None,
            lab_runs,
            lab_summary: None,
            lab_job: None,
            lab_status: None,
            pilot_center: pilot_run_center::PilotRunCenterState::default(),
            pending_delete_token: false,
            pending_delete_profile_token: TargetConfirmation::default(),
            pending_clear_runs: TargetConfirmation::default(),
            pending_rebuild_model: TargetConfirmation::default(),
            model_cache_state,
            status: "Ready".to_string(),
            error: startup_warning,
        }
    }

    fn start_diagnosis(&mut self, restore_startup_warning: bool) {
        if self.diagnosis_job.is_some() {
            self.settings_notice =
                Some(tr(self.language, Text::AnalysisAlreadyRunning).to_string());
            return;
        }
        if !self.ensure_current_settings_for_operation() {
            return;
        }
        let source_mode = self.source_mode.clone();
        let secrets = Arc::clone(&self.secrets);
        let artifacts_root = self.artifacts_root.clone();
        let what_if = match self.current_what_if_request() {
            Ok(request) => request,
            Err(err) => {
                self.status = "Needs attention".to_string();
                self.error = Some(err.to_string());
                return;
            }
        };
        let (sender, receiver) = mpsc::channel();
        self.status = "Running".to_string();
        self.error = None;
        self.diagnosis_restore_startup_warning = restore_startup_warning;
        self.diagnosis_job = Some(receiver);
        thread::spawn(move || {
            let result = Self::run_source(source_mode, secrets, artifacts_root, what_if);
            let _ = sender.send(result);
        });
    }

    fn finish_diagnosis(
        &mut self,
        result: anyhow::Result<(PipelineResult, SourceSnapshot)>,
        restore_startup_warning: bool,
    ) {
        let result = result.and_then(|(result, source_snapshot)| {
            let dashboard = DashboardViewModel::build(&result, &source_snapshot)?;
            Ok((result, source_snapshot, dashboard))
        });
        match result {
            Ok((result, source_snapshot, dashboard)) => {
                self.status = status_for_result(&result).to_string();
                self.error = None;
                self.dashboard = Some(dashboard);
                self.source_snapshot = Some(source_snapshot);
                self.result = Some(result);
                self.hil_notes.clear();
                self.model_cache_state = ModelCacheState::load(&self.artifacts_root);
                self.refresh_evidence_timeline();
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

    fn refresh_evidence_timeline(&mut self) {
        match list_run_timeline(&self.artifacts_root, RunHistoryFilter::default(), 20) {
            Ok(timeline) => {
                self.evidence_timeline = timeline;
                self.evidence_timeline_error = None;
                self.evidence_timeline_loaded = true;
            }
            Err(err) => {
                self.evidence_timeline.clear();
                self.evidence_timeline_error = Some(err.to_string());
                self.evidence_timeline_loaded = true;
            }
        }
    }

    fn select_evidence_run(&mut self, run_id: &str) {
        match run_evidence(&self.artifacts_root, run_id) {
            Ok(evidence) => {
                self.selected_evidence = Some(evidence);
                self.settings_notice = None;
            }
            Err(err) => {
                self.selected_evidence = None;
                self.settings_notice =
                    Some(format!("{}: {err}", tr(self.language, Text::OpenFailed)));
            }
        }
    }

    fn run_source(
        source_mode: SourceMode,
        secrets: Arc<dyn SecretStore>,
        artifacts_root: PathBuf,
        what_if: WhatIfRequest,
    ) -> anyhow::Result<(PipelineResult, SourceSnapshot)> {
        let source_snapshot = source_mode.load(secrets.as_ref())?;
        let result = diagnose_ingest_with_whatif_and_connector_health(
            source_snapshot.ingest.clone(),
            &artifacts_root,
            Some(what_if),
            source_snapshot.connector_health(),
        )?;
        Ok((result, source_snapshot))
    }

    fn start_diagnosis_from_snapshot(&mut self, source_snapshot: SourceSnapshot) {
        if self.diagnosis_job.is_some() {
            self.settings_notice =
                Some(tr(self.language, Text::AnalysisAlreadyRunning).to_string());
            return;
        }
        let artifacts_root = self.artifacts_root.clone();
        let what_if = match self.current_what_if_request() {
            Ok(request) => request,
            Err(err) => {
                self.status = "Needs attention".to_string();
                self.error = Some(err.to_string());
                return;
            }
        };
        let (sender, receiver) = mpsc::channel();
        self.status = "Running".to_string();
        self.error = None;
        self.diagnosis_restore_startup_warning = false;
        self.diagnosis_job = Some(receiver);
        thread::spawn(move || {
            let result = diagnose_ingest_with_whatif_and_connector_health(
                source_snapshot.ingest.clone(),
                &artifacts_root,
                Some(what_if),
                source_snapshot.connector_health(),
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
        profile.otlp_grpc.validate()?;
        Ok(OtlpGrpcReceiverConfig {
            bind_addr: profile.otlp_grpc.bind_addr.clone(),
            timeout: Duration::from_secs(profile.otlp_grpc.timeout_secs),
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
        profile.native_pcap.validate()?;
        Ok((
            NativePcapConfig {
                source: native_pcap_source(&profile.native_pcap.source),
                timeout: Duration::from_secs(profile.native_pcap.timeout_secs),
                packet_limit: profile.native_pcap.packet_limit,
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
        profile.system_counters.validate()?;
        let interface = profile.system_counters.interface.trim().to_string();
        Ok((
            SystemCountersConfig {
                interface: (!interface.is_empty() && interface != "all")
                    .then_some(interface.clone()),
                interval: Duration::from_secs(profile.system_counters.interval_secs),
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
        if !self.ensure_current_settings_for_operation() {
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
            OtlpReceiverSession::start(&config)
                .map(|session| {
                    let status = format!("Listening on {}", session.local_addr());
                    (session, config.timeout, status)
                })
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
                    worker: None,
                    cancel: None,
                    otlp: Some(session),
                });
            }
            Err(err) => {
                self.capture_session = Some(CaptureSessionState::failed(
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
                let progress_cancel = Arc::clone(&cancel);
                let control =
                    CaptureControl::new(Arc::clone(&cancel)).with_progress(move |progress| {
                        if progress_sender
                            .send(CaptureSessionEvent::Progress(progress))
                            .is_err()
                        {
                            progress_cancel.store(true, Ordering::Relaxed);
                        }
                    });
                let timeout = config.timeout;
                let worker = thread::spawn(move || {
                    let completion = capture_session_completion(
                        load_native_pcap_with_control(&config, &control),
                        ConnectorKind::NativePcap,
                        "Captured",
                        source_label,
                    );
                    drop(sender.send(CaptureSessionEvent::Finished(completion)));
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
                    worker: Some(worker),
                    cancel: Some(cancel),
                    otlp: None,
                });
            }
            Err(err) => {
                self.capture_session = Some(CaptureSessionState::failed(
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
                let progress_cancel = Arc::clone(&cancel);
                let control =
                    CaptureControl::new(Arc::clone(&cancel)).with_progress(move |progress| {
                        if progress_sender
                            .send(CaptureSessionEvent::Progress(progress))
                            .is_err()
                        {
                            progress_cancel.store(true, Ordering::Relaxed);
                        }
                    });
                let timeout = config.interval;
                let worker = thread::spawn(move || {
                    let completion = capture_session_completion(
                        load_system_counters_with_control(&config, &control),
                        ConnectorKind::SystemCounters,
                        "Sampled",
                        source_label,
                    );
                    drop(sender.send(CaptureSessionEvent::Finished(completion)));
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
                    worker: Some(worker),
                    cancel: Some(cancel),
                    otlp: None,
                });
            }
            Err(err) => {
                self.capture_session = Some(CaptureSessionState::failed(
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
            let (sender, receiver) = mpsc::channel();
            let worker = thread::spawn(move || {
                let result = otlp.stop().map_err(anyhow::Error::from);
                drop(sender.send(CaptureSessionEvent::OtlpStopped(result)));
            });
            session.phase = CaptureSessionPhase::Cancelling;
            session.status = tr(self.language, Text::CaptureCancelling).to_string();
            session.job = Some(receiver);
            session.worker = Some(worker);
        } else if let Some(cancel) = &session.cancel {
            cancel.store(true, Ordering::Relaxed);
            session.phase = CaptureSessionPhase::Cancelling;
            session.status = tr(self.language, Text::CaptureCancelling).to_string();
        }
    }

    fn diagnose_capture_last_sample(&mut self) {
        if !self.ensure_current_settings_for_operation() {
            return;
        }
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
        let loaded = otlp.snapshot(session.timeout);
        match loaded {
            Ok(loaded) => match source_snapshot_from_connector_session(
                loaded,
                ConnectorKind::OtlpGrpcReceiver,
                "Buffered",
                "OTLP receiver".to_string(),
            ) {
                Ok(source_snapshot) => {
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
            },
            Err(err) => {
                let status = err.to_string();
                if session.stop_otlp_after_failure(err) {
                    session.phase = CaptureSessionPhase::Cancelling;
                    session.status = format!(
                        "{}: {status}; stopping receiver",
                        tr(self.language, Text::CaptureFailed)
                    );
                } else {
                    session.phase = CaptureSessionPhase::Failed;
                    session.status = status;
                }
            }
        }
        if let Some(source_snapshot) = diagnose_now {
            self.start_diagnosis_from_snapshot(source_snapshot);
        }
    }

    fn current_what_if_request(&self) -> netdiag_core::Result<WhatIfRequest> {
        let topology = self.current_topology_model()?;
        let action = policy_action(&self.action)?;
        Ok(WhatIfRequest { topology, action })
    }

    fn current_topology_model(&self) -> netdiag_core::Result<TopologyModel> {
        selected_topology_model(self.topology.as_str(), self.custom_topology.as_ref())
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

    fn poll_lab_job(&mut self, ctx: &egui::Context) {
        let message = match self.lab_job.as_ref().map(|receiver| receiver.try_recv()) {
            Some(Ok(message)) => Some(message),
            Some(Err(mpsc::TryRecvError::Disconnected)) => Some(Err(anyhow::anyhow!(
                "lab worker stopped before returning a result"
            ))),
            Some(Err(mpsc::TryRecvError::Empty)) => {
                ctx.request_repaint_after(Duration::from_millis(100));
                None
            }
            None => None,
        };

        if let Some(message) = message {
            self.lab_job = None;
            match message {
                Ok(LabJobOutcome::Preflight(report)) => {
                    self.lab_status = Some(if report.passed {
                        format!("Preflight passed for {}", report.scenario_id)
                    } else {
                        format!("Preflight failed for {}", report.scenario_id)
                    });
                    self.lab_preflight = Some(report);
                }
                Ok(LabJobOutcome::Run(result)) => {
                    self.lab_status = Some(format!(
                        "Lab run {} {}",
                        result.run_id,
                        if result.acceptance.passed {
                            "passed"
                        } else {
                            "failed"
                        }
                    ));
                    self.lab_last_run = Some(*result);
                    self.refresh_lab_runs();
                    self.refresh_evidence_timeline();
                }
                Ok(LabJobOutcome::Summary(summary)) => {
                    self.lab_status = Some(format!(
                        "Lab summary: {} passed / {} failed",
                        summary.passed, summary.failed
                    ));
                    self.lab_summary = Some(summary);
                    self.refresh_lab_runs();
                }
                Ok(LabJobOutcome::DatasetExport(summary)) => {
                    self.lab_status = Some(format!(
                        "Dataset export wrote {} rows to {}",
                        summary.rows, summary.output
                    ));
                }
                Err(err) => {
                    self.lab_status = Some(err.to_string());
                }
            }
            ctx.request_repaint();
        }
    }

    fn refresh_lab_runs(&mut self) {
        match load_lab_runs_from_index(&self.artifacts_root) {
            Ok(runs) => {
                self.lab_runs = runs;
            }
            Err(err) => {
                self.lab_status = Some(format!("Lab run index could not be loaded: {err}"));
            }
        }
    }

    fn choose_lab_scenario(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Lab scenario", &["yaml", "yml"])
            .set_directory("examples/scenarios")
            .pick_file()
        else {
            return;
        };
        self.lab_scenario_path = path.display().to_string();
    }

    fn start_api_test_connection(&mut self) {
        if self.api_test_job.is_some() {
            return;
        }
        if !self.ensure_current_settings_for_operation() {
            self.api_test_status = None;
            return;
        }
        let source_mode = match self.connector_source_mode() {
            Ok(source_mode) => source_mode,
            Err(err) => {
                self.api_test_status = None;
                self.settings_notice = Some(err.to_string());
                return;
            }
        };
        self.replace_api_test_status(tr(self.language, Text::TestingConnection).to_string());
        self.api_test_job = Some(ApiTestJob::start(
            source_mode,
            self.api_test_credential_revision,
            Arc::clone(&self.secrets),
        ));
    }

    fn poll_api_test_job(&mut self, ctx: &egui::Context) {
        let Some(job) = self.api_test_job.as_ref() else {
            return;
        };
        let message = match job.poll() {
            ApiTestPoll::Pending => {
                ctx.request_repaint_after(Duration::from_millis(100));
                return;
            }
            ApiTestPoll::Complete(message) => message,
        };
        let current_source = self.connector_source_mode().ok();
        let is_current = current_source
            .as_ref()
            .is_some_and(|source| job.matches_current(source, self.api_test_credential_revision));
        self.api_test_job = None;
        let status = if is_current {
            match message {
                Ok(outcome) => format!(
                    "{}: {} {} · {}",
                    tr(self.language, Text::ConnectionOk),
                    outcome.rows,
                    tr(self.language, Text::Rows),
                    outcome.sample
                ),
                Err(err) => err.to_string(),
            }
        } else {
            tr(self.language, Text::ConnectionStale).to_string()
        };
        self.replace_api_test_status(status);
        ctx.request_repaint();
    }

    fn poll_capture_session(&mut self, ctx: &egui::Context) {
        let Some(session) = &mut self.capture_session else {
            return;
        };
        if let Some(otlp) = &session.otlp
            && session.phase.is_active()
        {
            let (frames, last_sample_at) = match otlp.progress_snapshot() {
                Ok(progress) => progress,
                Err(err) => {
                    let status = err.to_string();
                    if session.stop_otlp_after_failure(err) {
                        session.phase = CaptureSessionPhase::Cancelling;
                        session.status = format!(
                            "{}: {status}; stopping receiver",
                            tr(self.language, Text::CaptureFailed)
                        );
                        ctx.request_repaint_after(Duration::from_millis(100));
                    } else {
                        session.phase = CaptureSessionPhase::Failed;
                        session.status = status;
                        ctx.request_repaint();
                    }
                    return;
                }
            };
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
                last_sample_at,
            });
            ctx.request_repaint_after(Duration::from_millis(500));
        }

        let mut finished = None;
        let mut otlp_stopped = None;
        if let Some(receiver) = session.job.as_ref() {
            loop {
                match receiver.try_recv() {
                    Ok(CaptureSessionEvent::Progress(progress)) => {
                        session.progress = Some(progress);
                    }
                    Ok(CaptureSessionEvent::Finished(result)) => {
                        finished = Some(result);
                        break;
                    }
                    Ok(CaptureSessionEvent::OtlpStopped(result)) => {
                        otlp_stopped = Some(result);
                        break;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        finished = Some(CaptureSessionCompletion::Failed(anyhow::anyhow!(
                            "capture worker stopped before returning a result"
                        )));
                        break;
                    }
                }
            }
        }

        if otlp_stopped.is_some() || finished.is_some() {
            let worker_result = session.worker.take().map(thread::JoinHandle::join);
            if worker_result.is_some_and(|result| result.is_err()) {
                session.job = None;
                session.cancel = None;
                session.phase = CaptureSessionPhase::Failed;
                session.status = format!(
                    "{}: capture worker panicked",
                    tr(self.language, Text::CaptureFailed)
                );
                ctx.request_repaint();
                return;
            }
        }

        if let Some(result) = otlp_stopped {
            session.job = None;
            session.cancel = None;
            match result {
                Ok(OtlpShutdownOutcome::Graceful) => {
                    session.phase = CaptureSessionPhase::Cancelled;
                    session.status = tr(self.language, Text::CaptureCancelled).to_string();
                }
                Ok(OtlpShutdownOutcome::Forced) => {
                    session.phase = CaptureSessionPhase::Cancelled;
                    session.status = format!(
                        "{} · active connections closed",
                        tr(self.language, Text::CaptureCancelled)
                    );
                }
                Err(err) => {
                    session.phase = CaptureSessionPhase::Failed;
                    session.status = format!("{}: {err}", tr(self.language, Text::CaptureFailed));
                }
            }
            ctx.request_repaint();
        } else if let Some(result) = finished {
            session.job = None;
            session.cancel = None;
            match result {
                CaptureSessionCompletion::Completed(snapshot) => {
                    let rows = snapshot.ingest.records.len();
                    session.phase = CaptureSessionPhase::Completed;
                    session.status = format!(
                        "{}: {} {}",
                        tr(self.language, Text::CaptureCompleted),
                        rows,
                        tr(self.language, Text::Rows)
                    );
                    session.last_sample = Some(*snapshot);
                }
                CaptureSessionCompletion::Cancelled => {
                    session.phase = CaptureSessionPhase::Cancelled;
                    session.status = tr(self.language, Text::CaptureCancelled).to_string();
                }
                CaptureSessionCompletion::Failed(err) => {
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
            self.start_diagnosis(false);
        }
    }

    fn run_simulation(&mut self) {
        self.simulation_scenario = self.settings.simulation_scenario;
        self.source_mode = SourceMode::Simulated(self.simulation_scenario);
        self.start_diagnosis(false);
    }

    fn run_live_api(&mut self) {
        match self.connector_source_mode() {
            Ok(source_mode) => {
                self.source_mode = source_mode;
                self.start_diagnosis(false);
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
}

fn save_settings_if_authorized(
    store: &SettingsStore,
    settings: &mut AppSettings,
    authorized: bool,
) -> anyhow::Result<()> {
    if !authorized {
        anyhow::bail!(
            "settings were rejected at startup; repair or remove the settings file and restart before saving"
        );
    }
    store.save(settings)
}

impl eframe::App for NetDiagApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        #[cfg(target_os = "macos")]
        self.poll_native_menu();
        self.poll_diagnosis_job(ui.ctx());
        self.poll_lab_job(ui.ctx());
        self.pilot_center.poll(ui.ctx());
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
            NativeMenuCommand::NewAnalysis => self.start_diagnosis(false),
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
            (Tab::Lab, icons::FLASK_LINE),
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
                        Tab::Lab => self.render_lab_page(ui),
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
            } else if let Ok(request) = self.current_what_if_request() {
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

    fn render_lab_page(&mut self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            section_title(ui, title_for_tab(Tab::Lab, self.language));
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Scenario").size(12.0).color(MUTED));
                ui.add(
                    egui::TextEdit::singleline(&mut self.lab_scenario_path)
                        .desired_width((ui.available_width() - 380.0).max(280.0)),
                );
                if soft_button(ui, "Load").clicked() {
                    self.choose_lab_scenario();
                }
            });
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                let job_ready = self.lab_job.is_none();
                if soft_button_enabled(ui, "Preflight", job_ready).clicked() {
                    self.start_lab_preflight();
                }
                if soft_button_enabled(ui, "Run", job_ready).clicked() {
                    self.start_lab_run();
                }
                if soft_button_enabled(ui, "Summary", job_ready).clicked() {
                    self.start_lab_summary();
                }
                if soft_button_enabled(ui, "Dataset export", job_ready).clicked() {
                    self.start_lab_dataset_export();
                }
            });
            if let Some(status) = &self.lab_status {
                ui.add_space(8.0);
                ui.label(RichText::new(status).size(13.0).color(INK));
            }
        });

        ui.add_space(16.0);
        glass_frame(ui, |ui| {
            if let Some(action) = self.pilot_center.render(ui) {
                self.handle_pilot_run_center_action(action);
            }
        });

        ui.add_space(16.0);
        glass_frame(ui, |ui| {
            section_title(ui, "Acceptance result");
            ui.add_space(10.0);
            if let Some(result) = &self.lab_last_run {
                let acceptance = result.acceptance.clone();
                let lab_run_dir = result.lab_run_dir.clone();
                let evidence_bundle = result.evidence_bundle.output.clone();
                render_lab_acceptance(ui, &acceptance);
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if soft_button(ui, "Open lab run").clicked() {
                        self.open_path_with_notice(Path::new(&lab_run_dir));
                    }
                    if soft_button(ui, "Evidence bundle").clicked() {
                        self.open_path_with_notice(Path::new(&evidence_bundle));
                    }
                });
            } else {
                ui.label(RichText::new("No lab run yet.").size(13.0).color(MUTED));
            }
        });

        ui.add_space(16.0);
        glass_frame(ui, |ui| {
            section_title(ui, "Preflight");
            ui.add_space(10.0);
            if let Some(report) = &self.lab_preflight {
                for check in &report.checks {
                    let color = match check.status {
                        netdiag_core::lab::LabPreflightCheckStatus::Passed => GREEN,
                        netdiag_core::lab::LabPreflightCheckStatus::Failed => RED,
                        netdiag_core::lab::LabPreflightCheckStatus::Skipped => ORANGE,
                    };
                    bullet(ui, &format!("{}: {}", check.name, check.message), color);
                }
            } else {
                ui.label(
                    RichText::new("Run preflight before the experiment.")
                        .size(13.0)
                        .color(MUTED),
                );
            }
        });

        ui.add_space(16.0);
        glass_frame(ui, |ui| {
            section_title(ui, "Previous lab runs");
            ui.add_space(10.0);
            if self.lab_runs.is_empty() {
                ui.label(
                    RichText::new("No indexed lab runs.")
                        .size(13.0)
                        .color(MUTED),
                );
            } else {
                for run in self.lab_runs.iter().take(8).cloned().collect::<Vec<_>>() {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(if run.passed { "pass" } else { "fail" })
                                .size(12.0)
                                .strong()
                                .color(if run.passed { GREEN } else { RED }),
                        );
                        ui.label(RichText::new(&run.scenario_id).size(12.0).color(INK));
                        ui.label(RichText::new(&run.run_id).size(12.0).color(MUTED));
                        if soft_button(ui, "Open").clicked() {
                            self.open_path_with_notice(Path::new(&run.lab_run_dir));
                        }
                    });
                }
            }
        });

        if let Some(summary) = &self.lab_summary {
            ui.add_space(16.0);
            glass_frame(ui, |ui| {
                section_title(ui, "Lab summary");
                ui.add_space(10.0);
                ui.label(
                    RichText::new(format!(
                        "{} runs · {} passed · {} failed",
                        summary.total_runs, summary.passed, summary.failed
                    ))
                    .size(14.0)
                    .color(INK),
                );
                ui.add_space(8.0);
                for (label, stats) in &summary.by_label {
                    bullet(
                        ui,
                        &format!(
                            "{}: runs {}, pass {}, rule {:.2}, ml {:.2}",
                            label, stats.runs, stats.passed, stats.rule_accuracy, stats.ml_accuracy
                        ),
                        BLUE,
                    );
                }
            });
        }
    }

    fn render_reports_page(&mut self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            section_title(ui, tr(self.language, Text::EvidenceConsole));
            ui.add_space(10.0);
            if !self.evidence_timeline_loaded {
                self.refresh_evidence_timeline();
            }
            if let Some(health) = self.current_connector_health_snapshot() {
                self.render_connector_health_snapshot(ui, &health);
                ui.add_space(14.0);
            }
            self.render_run_history(ui);
            ui.add_space(14.0);
            self.render_selected_evidence(ui);
            ui.add_space(18.0);

            section_title(ui, tr(self.language, Text::Artifacts));
            ui.add_space(10.0);
            if let Some(result) = &self.result {
                section_title(ui, tr(self.language, Text::CurrentRun));
                ui.add_space(6.0);
                let run_id = result.run_id.clone();
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
                match run_artifacts(&self.artifacts_root, &run_id) {
                    Ok(entries) if entries.is_empty() => {
                        ui.label(tr(self.language, Text::NoArtifacts));
                    }
                    Ok(entries) => {
                        for entry in entries {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(entry.key).size(12.0).strong().color(INK));
                                ui.label(
                                    RichText::new(entry.path).size(12.0).color(if entry.exists {
                                        MUTED
                                    } else {
                                        RED
                                    }),
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
        });
    }

    fn current_connector_health_snapshot(&self) -> Option<ConnectorHealthSnapshot> {
        self.result
            .as_ref()
            .map(|result| result.connector_health.clone())
            .or_else(|| {
                self.source_snapshot
                    .as_ref()
                    .map(SourceSnapshot::connector_health)
            })
    }

    fn render_connector_health_snapshot(
        &self,
        ui: &mut egui::Ui,
        health: &ConnectorHealthSnapshot,
    ) {
        section_title(ui, tr(self.language, Text::ConnectorHealth));
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!(
                    "{}: {}",
                    tr(self.language, Text::SourceProfile),
                    health.profile_name
                ))
                .size(12.0)
                .color(MUTED),
            );
            ui.label(
                RichText::new(format!(
                    "{}: {}",
                    tr(self.language, Text::ConnectorKind),
                    health.source_kind
                ))
                .size(12.0)
                .color(MUTED),
            );
            ui.label(
                RichText::new(format!(
                    "{}: {}",
                    tr(self.language, Text::QualityStatus),
                    health_status_display(health.status, self.language)
                ))
                .size(12.0)
                .color(health_status_color(health.status)),
            );
            ui.label(
                RichText::new(format!(
                    "{}: {}",
                    tr(self.language, Text::Rows),
                    health.rows
                ))
                .size(12.0)
                .color(MUTED),
            );
            ui.label(
                RichText::new(format!(
                    "{}: {}",
                    tr(self.language, Text::WarningCount),
                    health.warning_count
                ))
                .size(12.0)
                .color(if health.warning_count == 0 {
                    GREEN
                } else {
                    ORANGE
                }),
            );
            ui.label(
                RichText::new(format!(
                    "{}: {}",
                    tr(self.language, Text::LastSample),
                    health.captured_at.format("%H:%M:%S")
                ))
                .size(12.0)
                .color(MUTED),
            );
        });
        ui.label(
            RichText::new(format!(
                "{}: measured={} estimated={} fallback={} missing={}",
                tr(self.language, Text::MeasurementQuality),
                health.quality.measured,
                health.quality.estimated,
                health.quality.fallback,
                health.quality.missing
            ))
            .size(12.0)
            .color(health_status_color(health.status)),
        );
        if !health.missing_metrics.is_empty() {
            ui.label(
                RichText::new(format!(
                    "{}: {}",
                    tr(self.language, Text::MissingMetrics),
                    health.missing_metrics.join(", ")
                ))
                .size(12.0)
                .color(ORANGE),
            );
        }
    }

    fn render_run_history(&mut self, ui: &mut egui::Ui) {
        section_title(ui, tr(self.language, Text::Timeline));
        ui.add_space(8.0);
        if let Some(err) = &self.evidence_timeline_error {
            ui.label(
                RichText::new(format!("{}: {err}", tr(self.language, Text::OpenFailed)))
                    .size(12.0)
                    .color(RED),
            );
            return;
        }
        if self.evidence_timeline.is_empty() {
            ui.label(tr(self.language, Text::NoArtifacts));
            return;
        }
        if let (Some(left), Some(right)) =
            (&self.evidence_compare_left, &self.evidence_compare_right)
            && let Ok(comparison) = compare_runs(&self.artifacts_root, left, right)
        {
            ui.group(|ui| {
                ui.label(
                    RichText::new(tr(self.language, Text::CompareRuns))
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
                    ui.label(
                        RichText::new(format!(
                            "{}={}",
                            tr(self.language, Text::QualityDelta),
                            comparison.quality_status_changed
                        ))
                        .size(12.0)
                        .color(if comparison.quality_status_changed {
                            ORANGE
                        } else {
                            GREEN
                        }),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{} {:+}",
                            tr(self.language, Text::WarningCount),
                            comparison.warning_count_delta
                        ))
                        .size(12.0)
                        .color(MUTED),
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
        for event in self.evidence_timeline.clone() {
            ui.group(|ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!("{}  {}", short_run_id(&event.run_id), event.sample))
                            .size(13.0)
                            .strong()
                            .color(INK),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{}: {}",
                            tr(self.language, Text::ReviewState),
                            event.status
                        ))
                        .size(12.0)
                        .color(MUTED),
                    );
                    ui.label(
                        RichText::new(event.created_at.format("%Y-%m-%d %H:%M:%S").to_string())
                            .size(12.0)
                            .color(MUTED),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{}: {}",
                            tr(self.language, Text::QualityStatus),
                            health_status_display(event.quality_status, self.language)
                        ))
                        .size(12.0)
                        .color(health_status_color(event.quality_status)),
                    );
                    ui.label(
                        RichText::new(format!("diagnosis: {}", event.diagnosis_status.as_str()))
                            .size(12.0)
                            .color(MUTED),
                    );
                });
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "{}: {}",
                            tr(self.language, Text::RootCauses),
                            if event.root_causes.is_empty() {
                                "normal".to_string()
                            } else {
                                event.root_causes.join(", ")
                            }
                        ))
                        .size(12.0)
                        .color(INK),
                    );
                    if let Some(label) = &event.ml_top_label {
                        ui.label(
                            RichText::new(format!("ML: {label}"))
                                .size(12.0)
                                .color(MUTED),
                        );
                    }
                    if !event.uncertainty_reason_codes.is_empty() {
                        let reasons = event
                            .uncertainty_reason_codes
                            .iter()
                            .map(|code| code.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");
                        ui.label(RichText::new(reasons).size(12.0).color(MUTED));
                    }
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if soft_button(ui, tr(self.language, Text::ViewDetails)).clicked() {
                        self.select_evidence_run(&event.run_id);
                    }
                    if soft_button(ui, tr(self.language, Text::CompareLeft)).clicked() {
                        self.evidence_compare_left = Some(event.run_id.clone());
                    }
                    if soft_button(ui, tr(self.language, Text::CompareRight)).clicked() {
                        self.evidence_compare_right = Some(event.run_id.clone());
                    }
                });
            });
            ui.add_space(8.0);
        }
    }

    fn render_selected_evidence(&mut self, ui: &mut egui::Ui) {
        section_title(ui, tr(self.language, Text::SelectedRun));
        ui.add_space(8.0);
        let Some(evidence) = self.selected_evidence.clone() else {
            ui.label(
                RichText::new(tr(self.language, Text::NoRunSelected))
                    .size(12.0)
                    .color(MUTED),
            );
            return;
        };

        ui.group(|ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{}  {}",
                        short_run_id(&evidence.run.run_id),
                        evidence.run.sample
                    ))
                    .size(13.0)
                    .strong()
                    .color(INK),
                );
                ui.label(
                    RichText::new(format!(
                        "{}: {}",
                        tr(self.language, Text::ReviewState),
                        evidence.run.status
                    ))
                    .size(12.0)
                    .color(MUTED),
                );
                ui.label(
                    RichText::new(format!(
                        "{}: {}",
                        tr(self.language, Text::QualityStatus),
                        health_status_display(evidence.run.quality_status, self.language)
                    ))
                    .size(12.0)
                    .color(health_status_color(evidence.run.quality_status)),
                );
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{}: {}",
                        tr(self.language, Text::RootCauses),
                        if evidence.run.root_causes.is_empty() {
                            "normal".to_string()
                        } else {
                            evidence.run.root_causes.join(", ")
                        }
                    ))
                    .size(12.0)
                    .color(INK),
                );
                if let Some(label) = &evidence.run.ml_top_label {
                    ui.label(
                        RichText::new(format!(
                            "ML: {} ({:.2})",
                            label,
                            evidence.run.ml_top_probability.unwrap_or_default()
                        ))
                        .size(12.0)
                        .color(MUTED),
                    );
                }
            });
            ui.label(
                RichText::new(format!(
                    "{}: measured={} estimated={} fallback={} missing={}",
                    tr(self.language, Text::MeasurementQuality),
                    evidence.run.quality.measured,
                    evidence.run.quality.estimated,
                    evidence.run.quality.fallback,
                    evidence.run.quality.missing
                ))
                .size(12.0)
                .color(health_status_color(evidence.run.quality_status)),
            );
            ui.label(
                RichText::new(format!(
                    "{}: total={} pending={} accepted={} rejected={} uncertain={} rerun={}",
                    tr(self.language, Text::HilReview),
                    evidence.run.hil_summary.total,
                    evidence.run.hil_summary.pending,
                    evidence.run.hil_summary.accepted,
                    evidence.run.hil_summary.rejected,
                    evidence.run.hil_summary.uncertain,
                    evidence.run.hil_summary.requires_rerun
                ))
                .size(12.0)
                .color(MUTED),
            );
            if let Some(health) = &evidence.connector_health {
                ui.add_space(6.0);
                self.render_connector_health_snapshot(ui, health);
            }
            ui.add_space(6.0);
            section_title(ui, tr(self.language, Text::ArtifactFiles));
            for artifact in evidence.artifacts.iter().take(10) {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(&artifact.key).size(12.0).strong().color(INK));
                    ui.label(
                        RichText::new(&artifact.path)
                            .size(12.0)
                            .color(if artifact.exists { MUTED } else { RED }),
                    );
                });
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let run_dir = PathBuf::from(&evidence.run.run_dir);
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
    }

    fn render_settings_page(&mut self, ui: &mut egui::Ui) {
        glass_frame(ui, |ui| {
            section_title(ui, title_for_tab(Tab::Settings, self.language));
            ui.add_space(10.0);
            if let Some(notice) = &self.settings_notice {
                ui.label(RichText::new(notice).size(12.0).color(MUTED));
            }
            if let Some(status) = self.current_api_test_status() {
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
            let (source_mode, warning) = source_mode_from_settings(&self.settings);
            self.source_mode = source_mode;
            if warning.is_some() {
                self.settings_notice = warning;
            }
            self.start_diagnosis(false);
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

        let token_scope = bearer_scope_for_endpoint(
            "legacy_live_api",
            BearerSourceKind::HttpJson,
            &self.settings.api.endpoint,
        );
        let token_presence = token_scope
            .as_ref()
            .map_err(ToString::to_string)
            .map(|scope| {
                self.live_api_token_presence
                    .for_scope(self.secrets.as_ref(), scope)
                    .clone()
            });
        let stale_binding = legacy_live_api_binding(&self.settings.api.endpoint)
            .ok()
            .is_some_and(|desired| has_stale_active_binding(&self.settings, &desired));
        let (token_status, token_color) = match token_presence {
            Ok(BearerSecretPresence::Present) => (
                format!(
                    "{}: {}",
                    tr(self.language, Text::TokenStatus),
                    tr(self.language, Text::ApiSet)
                ),
                MUTED,
            ),
            Ok(BearerSecretPresence::Missing) if stale_binding => (
                stale_bearer_credential_hint(self.language).to_string(),
                ORANGE,
            ),
            Ok(BearerSecretPresence::Missing) => (
                format!(
                    "{}: {}",
                    tr(self.language, Text::TokenStatus),
                    tr(self.language, Text::ApiUnset)
                ),
                MUTED,
            ),
            Ok(BearerSecretPresence::ReadFailed(error)) | Err(error) => (
                format!("{}: {error}", tr(self.language, Text::KeychainError)),
                RED,
            ),
        };
        ui.label(RichText::new(token_status).size(12.0).color(token_color));
        ui.horizontal(|ui| {
            setting_caption(ui, tr(self.language, Text::KeychainProtection));
            ui.add(
                egui::TextEdit::singleline(&mut *self.token_input)
                    .password(true)
                    .desired_width(220.0),
            );
            if soft_button(ui, tr(self.language, Text::SaveToken)).clicked() {
                self.advance_api_test_credential_revision();
                let result =
                    legacy_live_api_binding(&self.settings.api.endpoint).and_then(|binding| {
                        store_bearer_credential(
                            &self.settings_store,
                            &mut self.settings,
                            self.secrets.as_ref(),
                            binding,
                            &self.token_input,
                        )
                    });
                self.token_input.zeroize();
                self.live_api_token_presence.invalidate();
                match result {
                    Ok(()) => {
                        self.pending_delete_token = false;
                        if let Ok(scope) = token_scope.as_ref() {
                            self.live_api_token_presence.mark_present(scope);
                        }
                        self.settings_notice = Some(tr(self.language, Text::Saved).to_string());
                    }
                    Err(error) => self.settings_notice = Some(format!("{error:#}")),
                }
            }
            let delete_label = if self.pending_delete_token {
                tr(self.language, Text::ConfirmDeleteToken)
            } else {
                tr(self.language, Text::DeleteToken)
            };
            if soft_button(ui, delete_label).clicked() {
                if self.pending_delete_token {
                    self.advance_api_test_credential_revision();
                    let result = delete_live_api_credentials(
                        &self.settings_store,
                        &mut self.settings,
                        self.secrets.as_ref(),
                    );
                    self.token_input.zeroize();
                    self.live_api_token_presence.invalidate();
                    match result {
                        Ok(()) => {
                            self.pending_delete_token = false;
                            if let Ok(scope) = token_scope.as_ref() {
                                self.live_api_token_presence.mark_missing(scope);
                            }
                            self.settings_notice = Some(tr(self.language, Text::Saved).to_string());
                        }
                        Err(error) => self.settings_notice = Some(format!("{error:#}")),
                    }
                } else {
                    self.pending_delete_token = true;
                }
            }
        });
    }

    fn render_profile_bearer_token_settings(&mut self, ui: &mut egui::Ui, profile_index: usize) {
        let profile = self.settings.data_connectors.profiles[profile_index].clone();
        if profile.authentication == ConnectorAuthentication::None {
            ui.label(
                RichText::new(connector_authentication_disabled_hint(self.language))
                    .size(12.0)
                    .color(MUTED),
            );
            return;
        }

        let scope = profile_bearer_scope(&profile).and_then(|scope| {
            scope.ok_or_else(|| anyhow::anyhow!("bearer authentication is not enabled"))
        });
        let presence = scope.as_ref().map_err(ToString::to_string).map(|scope| {
            self.profile_token_presence
                .for_scope(self.secrets.as_ref(), scope)
                .clone()
        });
        let stale_binding = profile_binding(&profile)
            .ok()
            .flatten()
            .is_some_and(|desired| has_stale_active_binding(&self.settings, &desired));
        let (status, color) = match presence {
            Ok(BearerSecretPresence::Present) => {
                (tr(self.language, Text::ApiSet).to_string(), MUTED)
            }
            Ok(BearerSecretPresence::Missing) if stale_binding => (
                stale_bearer_credential_hint(self.language).to_string(),
                ORANGE,
            ),
            Ok(BearerSecretPresence::Missing) => {
                (tr(self.language, Text::ApiUnset).to_string(), ORANGE)
            }
            Ok(BearerSecretPresence::ReadFailed(error)) | Err(error) => (error, RED),
        };
        ui.label(
            RichText::new(format!(
                "{}: {status}",
                tr(self.language, Text::TokenStatus)
            ))
            .size(12.0)
            .color(color),
        );
        ui.horizontal(|ui| {
            setting_caption(ui, tr(self.language, Text::KeychainProtection));
            ui.add(
                egui::TextEdit::singleline(&mut *self.profile_token_input)
                    .password(true)
                    .desired_width(220.0),
            );
            if soft_button(ui, tr(self.language, Text::SaveToken)).clicked() {
                self.advance_api_test_credential_revision();
                self.pending_delete_profile_token.clear();
                let desired = profile_binding(&profile).and_then(|binding| {
                    binding.ok_or_else(|| anyhow::anyhow!("bearer authentication is not enabled"))
                });
                let result = desired.and_then(|binding| {
                    store_bearer_credential(
                        &self.settings_store,
                        &mut self.settings,
                        self.secrets.as_ref(),
                        binding,
                        &self.profile_token_input,
                    )
                });
                self.profile_token_input.zeroize();
                self.profile_token_presence.invalidate();
                match result {
                    Ok(()) => {
                        if let Ok(scope) = scope.as_ref() {
                            self.profile_token_presence.mark_present(scope);
                        }
                        self.settings_notice = Some(tr(self.language, Text::Saved).to_string());
                    }
                    Err(error) => self.settings_notice = Some(format!("{error:#}")),
                }
            }
            let delete_label = if self.pending_delete_profile_token.is_armed_for(&profile.id) {
                tr(self.language, Text::ConfirmDeleteToken)
            } else {
                tr(self.language, Text::DeleteToken)
            };
            if soft_button(ui, delete_label).clicked()
                && self
                    .pending_delete_profile_token
                    .request(profile.id.clone())
            {
                self.advance_api_test_credential_revision();
                let owner = BearerCredentialOwner::profile(profile.id.clone());
                let current = profile_binding(&profile).ok().flatten();
                let result = delete_bearer_credentials(
                    &self.settings_store,
                    &mut self.settings,
                    self.secrets.as_ref(),
                    &owner,
                    current,
                );
                self.profile_token_input.zeroize();
                self.profile_token_presence.invalidate();
                match result {
                    Ok(()) => {
                        if let Ok(scope) = scope.as_ref() {
                            self.profile_token_presence.mark_missing(scope);
                        }
                        self.settings_notice = Some(tr(self.language, Text::Saved).to_string());
                    }
                    Err(error) => self.settings_notice = Some(format!("{error:#}")),
                }
            }
        });
    }

    fn render_data_connector_settings(&mut self, ui: &mut egui::Ui) {
        section_title(ui, tr(self.language, Text::DataConnectors));
        ui.add_space(8.0);
        let mut changed = false;
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
                            let kind_changed = ui
                                .selectable_value(
                                    &mut profile.kind,
                                    connector,
                                    connector_kind_label(connector, self.language),
                                )
                                .changed();
                            changed |= kind_changed;
                            if kind_changed && !profile.kind.supports_bearer_authentication() {
                                profile.authentication = ConnectorAuthentication::None;
                            }
                        }
                    });
            });
            if profile.kind.supports_bearer_authentication() {
                ui.horizontal(|ui| {
                    setting_caption(ui, tr(self.language, Text::TokenStatus));
                    egui::ComboBox::from_id_salt("profile_authentication")
                        .selected_text(connector_authentication_label(
                            profile.authentication,
                            self.language,
                        ))
                        .show_ui(ui, |ui| {
                            for authentication in [
                                ConnectorAuthentication::None,
                                ConnectorAuthentication::BearerToken,
                            ] {
                                changed |= ui
                                    .selectable_value(
                                        &mut profile.authentication,
                                        authentication,
                                        connector_authentication_label(
                                            authentication,
                                            self.language,
                                        ),
                                    )
                                    .changed();
                            }
                        });
                });
            }
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
                                    .range(1..=netdiag_core::MAX_PCAP_PACKET_LIMIT),
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
        if active_kind.supports_bearer_authentication() {
            self.render_profile_bearer_token_settings(ui, profile_index);
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
            let (source_mode, warning) = source_mode_from_settings(&self.settings);
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
            let phase = self.capture_session.as_ref().map(|session| session.phase);
            let active = phase.is_some_and(CaptureSessionPhase::is_active);
            let running = phase == Some(CaptureSessionPhase::Running);
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
            if ui.add_enabled(!active, start).clicked() {
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
            self.start_diagnosis(false);
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
                self.pending_clear_runs.clear();
                self.pending_rebuild_model.clear();
                self.model_cache_state = ModelCacheState::load(&path);
                self.settings.artifacts_root = path.clone();
                self.artifacts_root = path;
                self.persist_settings();
                self.start_diagnosis(false);
            }
            if soft_button(ui, tr(self.language, Text::OpenFolder)).clicked() {
                let path = self.settings.artifacts_root.clone();
                self.open_path_with_notice(&path);
            }
            let clear_target = self.settings.artifacts_root.clone();
            let clear_label = if self.pending_clear_runs.is_armed_for(&clear_target) {
                tr(self.language, Text::ConfirmClearRunHistory)
            } else {
                tr(self.language, Text::ClearRunHistory)
            };
            if soft_button(ui, clear_label).clicked()
                && self.pending_clear_runs.request(clear_target)
            {
                self.clear_run_history();
            }
        });
        ui.label(
            RichText::new(format!(
                "{}: {}",
                tr(self.language, Text::ModelCache),
                self.model_cache_state.status(self.language.into())
            ))
            .size(12.0)
            .color(MUTED),
        );
        let rebuild_target = self.settings.artifacts_root.clone();
        let rebuild_label = if self.pending_rebuild_model.is_armed_for(&rebuild_target) {
            tr(self.language, Text::ConfirmRebuildModel)
        } else {
            tr(self.language, Text::RebuildModel)
        };
        if soft_button(ui, rebuild_label).clicked()
            && self.pending_rebuild_model.request(rebuild_target)
        {
            self.rebuild_model_cache();
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
            Ok(UpdateCheckOutcome::FeedReachable) => {
                let message = tr(self.language, Text::UpdateFeedReachable).to_string();
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
        match load_topology_file(&path) {
            Ok(model) => {
                self.settings.what_if.topology = "custom".to_string();
                self.settings.what_if.custom_topology = Some(model.clone());
                self.topology = "custom".to_string();
                self.custom_topology = Some(model);
                self.persist_settings();
                self.start_diagnosis(false);
            }
            Err(err) => {
                self.settings_notice =
                    Some(format!("{}: {err}", tr(self.language, Text::OpenFailed)));
            }
        }
    }

    fn export_topology(&mut self) {
        let topology = match self.current_topology_model() {
            Ok(topology) => topology,
            Err(error) => {
                self.settings_notice = Some(error.to_string());
                return;
            }
        };
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("{}_topology.json", topology.key))
            .save_file()
        else {
            return;
        };
        match write_topology_export(&path, &topology) {
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
        match optional_path_metadata(fs::metadata(&help_path)) {
            Ok(Some(metadata)) if metadata.is_file() => self.open_path_with_notice(&help_path),
            Ok(_) => {
                self.tab = Tab::Settings;
                self.settings_notice = Some(tr(self.language, Text::NotAvailable).to_string());
            }
            Err(error) => {
                self.tab = Tab::Settings;
                self.settings_notice = Some(format!(
                    "{}: {}: {error}",
                    tr(self.language, Text::OpenFailed),
                    help_path.display()
                ));
            }
        }
    }

    fn apply_hil_review(&mut self, recommendation_id: &str, state: HilState) {
        let Some(result) = &self.result else {
            return;
        };
        let run_id = result.run_id.clone();
        let Some(artifact_root) = artifact_root_for_result(result) else {
            self.settings_notice = Some(format!(
                "HIL review cannot resolve the artifact root from run directory {}",
                result.run_dir.display()
            ));
            return;
        };
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
                self.refresh_evidence_timeline();
                if self
                    .selected_evidence
                    .as_ref()
                    .is_some_and(|evidence| evidence.run.run_id == run_id)
                {
                    self.select_evidence_run(&run_id);
                }
            }
            Err(err) => {
                self.settings_notice = Some(err.to_string());
            }
        }
    }

    fn clear_run_history(&mut self) {
        let result = clear_stored_run_history(&self.settings.artifacts_root);
        apply_run_history_clear_state(
            &result,
            &mut self.evidence_timeline,
            &mut self.evidence_timeline_loaded,
            &mut self.selected_evidence,
        );
        match result {
            Ok(()) => {
                self.settings_notice = Some(tr(self.language, Text::Saved).to_string());
            }
            Err(error) => {
                self.settings_notice = Some(error.to_string());
            }
        }
    }

    fn rebuild_model_cache(&mut self) {
        let model_dir = self.settings.artifacts_root.join("model");
        let result = rebuild_model_bundle(&model_dir);
        self.model_cache_state = ModelCacheState::load(&self.settings.artifacts_root);
        match result {
            Ok(()) => {
                self.settings_notice = Some(tr(self.language, Text::Saved).to_string());
                self.start_diagnosis(false);
            }
            Err(err) => {
                self.settings_notice = Some(err.to_string());
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
                    self.start_diagnosis(false);
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
            egui::containers::menu::MenuButton::from_button(button).ui(ui, |ui| {
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
        (Language::Zh, Tab::Lab) => "实验室",
        (Language::Zh, Tab::Reports) => "报告",
        (Language::Zh, Tab::Settings) => "设置",
        (Language::En, Tab::Overview) => "Overview",
        (Language::En, Tab::Telemetry) => "Telemetry",
        (Language::En, Tab::Diagnosis) => "Diagnosis",
        (Language::En, Tab::RuleMl) => "Rule vs ML",
        (Language::En, Tab::DigitalTwin) => "Digital Twin",
        (Language::En, Tab::WhatIf) => "What-if",
        (Language::En, Tab::Lab) => "Lab",
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
            StartupTab::Lab => Tab::Lab,
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
            Tab::Lab => StartupTab::Lab,
            Tab::Reports => StartupTab::Reports,
            Tab::Settings => StartupTab::Settings,
        }
    }
}

#[cfg(target_os = "macos")]
fn default_secret_store() -> Arc<dyn SecretStore> {
    Arc::new(KeychainSecretStore)
}

#[cfg(not(target_os = "macos"))]
fn default_secret_store() -> Arc<dyn SecretStore> {
    Arc::new(MemorySecretStore::default())
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

fn load_lab_runs_from_index(artifact_root: &Path) -> anyhow::Result<Vec<LabRunIndexEntry>> {
    Ok(read_lab_run_index(artifact_root)?.map_or_else(Vec::new, |index| index.runs))
}

fn render_lab_acceptance(ui: &mut egui::Ui, acceptance: &LabAcceptanceReport) {
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(if acceptance.passed {
                "passed"
            } else {
                "failed"
            })
            .size(16.0)
            .strong()
            .color(if acceptance.passed { GREEN } else { RED }),
        );
        ui.label(
            RichText::new(format!(
                "{} · ML {} {:.2}",
                acceptance
                    .expected_label
                    .map(|label| label.as_str())
                    .unwrap_or(acceptance.actual_diagnosis_status.as_str()),
                acceptance.actual_ml_top,
                acceptance.actual_ml_probability
            ))
            .size(13.0)
            .color(INK),
        );
    });
    if acceptance.failures.is_empty() {
        bullet(ui, "acceptance gate passed", GREEN);
    } else {
        for failure in &acceptance.failures {
            bullet(ui, failure, RED);
        }
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

fn connector_authentication_label(
    authentication: ConnectorAuthentication,
    lang: Language,
) -> &'static str {
    match (authentication, lang) {
        (ConnectorAuthentication::None, Language::Zh) => "不使用认证",
        (ConnectorAuthentication::None, Language::En) => "No authentication",
        (ConnectorAuthentication::BearerToken, _) => "Bearer token",
    }
}

fn connector_authentication_disabled_hint(lang: Language) -> &'static str {
    match lang {
        Language::Zh => "此配置默认不读取或发送任何令牌。",
        Language::En => "This profile does not read or send any token by default.",
    }
}

fn stale_bearer_credential_hint(lang: Language) -> &'static str {
    match lang {
        Language::Zh => "令牌仍绑定到先前的端点；请保存新令牌完成轮换，或显式删除旧令牌。",
        Language::En => {
            "The token remains bound to the previous endpoint; save a new token to rotate it or explicitly delete it."
        }
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
        StartupTab::Lab => tr(lang, Text::StartupLab),
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

#[cfg(target_os = "macos")]
fn open_path(path: &Path) -> std::io::Result<()> {
    use objc2_app_kit::NSWorkspace;
    use objc2_foundation::{NSString, NSURL};

    let path = path.to_str().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path must be valid Unicode before opening it with macOS Workspace",
        )
    })?;
    let url = NSURL::fileURLWithPath(&NSString::from_str(path));
    if NSWorkspace::sharedWorkspace().openURL(&url) {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "macOS Workspace declined to open the path",
        ))
    }
}

#[cfg(not(target_os = "macos"))]
fn open_path(path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "opening paths is supported only by the macOS desktop build: {}",
            path.display()
        ),
    ))
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

fn health_status_display(status: ConnectorHealthStatus, lang: Language) -> &'static str {
    match (lang, status) {
        (Language::Zh, ConnectorHealthStatus::Ok) => "可信",
        (Language::Zh, ConnectorHealthStatus::Degraded) => "降级",
        (Language::Zh, ConnectorHealthStatus::Error) => "错误",
        (Language::En, ConnectorHealthStatus::Ok) => "ok",
        (Language::En, ConnectorHealthStatus::Degraded) => "degraded",
        (Language::En, ConnectorHealthStatus::Error) => "error",
    }
}

fn health_status_color(status: ConnectorHealthStatus) -> Color32 {
    match status {
        ConnectorHealthStatus::Ok => GREEN,
        ConnectorHealthStatus::Degraded => ORANGE,
        ConnectorHealthStatus::Error => RED,
    }
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

fn soft_button_enabled(ui: &mut egui::Ui, text: &str, enabled: bool) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(text).size(13.0).color(INK))
            .fill(Color32::from_white_alpha(if enabled { 130 } else { 70 }))
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
