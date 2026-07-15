use anyhow::Result;
use netdiag_app::connector_auth::profile_bearer_scope;
use netdiag_app::credential_lifecycle::{has_active_binding, profile_binding};
use netdiag_app::data_source::SourceMode;
use netdiag_app::settings::{ApiConfig, AppSettings, ConnectorKind, DefaultSource};
use std::time::Duration;

pub(super) fn source_mode_from_settings(settings: &AppSettings) -> (SourceMode, Option<String>) {
    match settings.default_source {
        DefaultSource::Simulation => (SourceMode::Simulated(settings.simulation_scenario), None),
        DefaultSource::LastImportedFile => match &settings.last_imported_trace {
            Some(path) => match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    (SourceMode::File(path.clone()), None)
                }
                Ok(_) => unavailable_source(format!(
                    "last imported trace is not a regular file: {}",
                    path.display()
                )),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => unavailable_source(
                    format!("last imported trace is unavailable: {}", path.display()),
                ),
                Err(error) => unavailable_source(format!(
                    "failed to inspect last imported trace {}: {error}",
                    path.display()
                )),
            },
            None => unavailable_source("no last imported trace is saved".to_string()),
        },
        DefaultSource::LiveApi => match connector_source_mode_from_profile(settings) {
            Ok(source) => (source, None),
            Err(error) => unavailable_source(format!("live collection is not ready: {error}")),
        },
    }
}

fn unavailable_source(reason: String) -> (SourceMode, Option<String>) {
    (
        SourceMode::Unavailable {
            reason: reason.clone(),
        },
        Some(reason),
    )
}

pub(super) fn connector_source_mode_from_profile(settings: &AppSettings) -> Result<SourceMode> {
    let profile = settings
        .data_connectors
        .active_profile()
        .ok_or_else(|| anyhow::anyhow!("no active source profile"))?;
    let bearer_scope = profile_bearer_scope(profile)?;
    if bearer_scope.is_some() {
        let binding = profile_binding(profile)?
            .ok_or_else(|| anyhow::anyhow!("bearer authentication has no credential binding"))?;
        if !has_active_binding(settings, &binding) {
            anyhow::bail!(
                "bearer authentication is enabled, but the current credential scope is not registered; save the token for this endpoint"
            );
        }
    }
    Ok(match profile.kind {
        ConnectorKind::LocalProbe => SourceMode::LocalProbe(profile.local_probe.clone()),
        ConnectorKind::WebsiteProbe => SourceMode::WebsiteProbe(profile.website_probe.clone()),
        ConnectorKind::HttpJson => SourceMode::Api(
            ApiConfig::new(
                profile.http_json.endpoint.clone(),
                Duration::from_secs(profile.http_json.validated_timeout_secs()?),
            ),
            bearer_scope,
        ),
        ConnectorKind::PrometheusQueryRange => {
            SourceMode::PrometheusQueryRange(profile.prometheus_query.clone(), bearer_scope)
        }
        ConnectorKind::PrometheusExposition => {
            SourceMode::PrometheusExposition(profile.prometheus_exposition.clone(), bearer_scope)
        }
        ConnectorKind::OtlpGrpcReceiver => SourceMode::OtlpGrpcReceiver(profile.otlp_grpc.clone()),
        ConnectorKind::NativePcap => SourceMode::NativePcap(profile.native_pcap.clone()),
        ConnectorKind::SystemCounters => {
            SourceMode::SystemCounters(profile.system_counters.clone())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use netdiag_app::connector_auth::profile_bearer_scope;
    use netdiag_app::settings::ConnectorAuthentication;

    fn activate_http_profile(
        settings: &mut AppSettings,
    ) -> &mut netdiag_app::settings::SourceProfile {
        settings.data_connectors.active_profile_id = "http_json_lab".to_string();
        settings
            .data_connectors
            .active_profile_mut()
            .expect("HTTP profile")
    }

    #[test]
    fn missing_requested_file_stays_unavailable() {
        let settings = AppSettings {
            default_source: DefaultSource::LastImportedFile,
            last_imported_trace: Some(std::path::PathBuf::from("missing-trace.csv")),
            ..AppSettings::default()
        };
        let (source, warning) = source_mode_from_settings(&settings);
        assert!(matches!(source, SourceMode::Unavailable { .. }));
        assert!(warning.is_some());
    }

    #[test]
    fn non_file_requested_source_reports_its_real_type() {
        let settings = AppSettings {
            default_source: DefaultSource::LastImportedFile,
            last_imported_trace: Some(std::path::PathBuf::from(".")),
            ..AppSettings::default()
        };
        let (source, warning) = source_mode_from_settings(&settings);

        assert!(matches!(source, SourceMode::Unavailable { .. }));
        assert!(warning.expect("warning").contains("not a regular file"));
    }

    #[test]
    fn missing_active_profile_fails_instead_of_using_legacy_settings() {
        let mut settings = AppSettings::default();
        settings.data_connectors.profiles.clear();
        let error =
            connector_source_mode_from_profile(&settings).expect_err("missing profile must fail");
        assert!(error.to_string().contains("no active source profile"));
    }

    #[test]
    fn unauthenticated_profile_carries_no_secret_scope() {
        let mut settings = AppSettings::default();
        let profile = activate_http_profile(&mut settings);
        profile.http_json.endpoint = "https://one.example.test/traces".to_string();
        profile.authentication = ConnectorAuthentication::None;

        let source = connector_source_mode_from_profile(&settings).expect("unauthenticated source");
        let SourceMode::Api(_, scope) = source else {
            panic!("expected HTTP source")
        };
        assert_eq!(scope, None);
    }

    #[test]
    fn bearer_scope_requires_an_active_registry_binding_for_the_exact_origin() {
        let mut settings = AppSettings::default();
        let profile = activate_http_profile(&mut settings);
        profile.http_json.endpoint = "https://one.example.test/traces".to_string();
        profile.authentication = ConnectorAuthentication::BearerToken;
        let expected_scope = profile_bearer_scope(profile)
            .expect("valid scope")
            .expect("enabled scope");
        let binding = profile_binding(profile)
            .expect("valid binding")
            .expect("enabled binding");
        settings.bearer_credentials.push(binding);
        let source = connector_source_mode_from_profile(&settings).expect("exact source binding");
        let SourceMode::Api(_, Some(scope)) = source else {
            panic!("expected HTTP source")
        };
        assert_eq!(scope, expected_scope);

        activate_http_profile(&mut settings).http_json.endpoint =
            "https://two.example.test/traces".to_string();
        let error = connector_source_mode_from_profile(&settings)
            .expect_err("changed origin must require an explicit credential rotation");
        assert!(
            error
                .to_string()
                .contains("current credential scope is not registered")
        );
    }
}
