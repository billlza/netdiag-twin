use super::{
    Language, LanguageSetting, NetDiagApp, SourceMode, Text, connector_source_mode_from_profile,
    reconcile_inactive_profile_credentials, save_settings_if_authorized, tr,
};

impl NetDiagApp {
    pub(super) fn connector_source_mode(&self) -> anyhow::Result<SourceMode> {
        connector_source_mode_from_profile(&self.settings)
    }

    pub(super) fn ensure_current_settings_for_operation(&mut self) -> bool {
        match self.settings_store.verify_current(&self.settings) {
            Ok(()) => true,
            Err(error) => {
                let message = error.to_string();
                self.status = "Needs attention".to_string();
                self.error = Some(message.clone());
                self.settings_notice = Some(message);
                false
            }
        }
    }

    pub(super) fn persist_settings(&mut self) {
        match save_settings_if_authorized(
            &self.settings_store,
            &mut self.settings,
            self.settings_persistence_authorized,
        ) {
            Ok(()) => {
                let credentials_before = self.settings.bearer_credentials.clone();
                let reconciliation = reconcile_inactive_profile_credentials(
                    &self.settings_store,
                    &mut self.settings,
                    self.secrets.as_ref(),
                );
                if reconciliation.is_err() || self.settings.bearer_credentials != credentials_before
                {
                    self.live_api_token_presence.invalidate();
                    self.profile_token_presence.invalidate();
                    self.advance_api_test_credential_revision();
                }
                self.settings_notice = match reconciliation {
                    Ok(()) => Some(tr(self.language, Text::Saved).to_string()),
                    Err(error) => Some(format!("{error:#}")),
                };
            }
            Err(error) => self.settings_notice = Some(format!("{error:#}")),
        }
    }

    pub(super) fn set_language(&mut self, language: Language) {
        self.language = language;
        self.settings.language = LanguageSetting::from(language);
        self.persist_settings();
    }
}
