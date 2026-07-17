use netdiag_app::settings::LanguageSetting;
use netdiag_core::NetdiagError;
use netdiag_core::ml::{
    ModelBundleIdentity, load_existing_model_bundle_identity_if_present,
    rebuild_synthetic_model_bundle_in_artifact_root,
};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(super) enum ModelCacheState {
    Available { training_examples: usize },
    Missing,
    Error { model_dir: PathBuf, message: String },
}

impl ModelCacheState {
    pub(super) fn load(artifact_root: &Path) -> Self {
        let model_dir = artifact_root.join("model");
        Self::from_identity_result(
            &model_dir,
            load_existing_model_bundle_identity_if_present(&model_dir),
        )
    }

    pub(super) fn from_identity_result(
        model_dir: &Path,
        result: Result<Option<ModelBundleIdentity>, NetdiagError>,
    ) -> Self {
        match result {
            Ok(Some(identity)) => Self::Available {
                training_examples: identity.manifest.training_examples,
            },
            Ok(None) => Self::Missing,
            Err(error) => Self::Error {
                model_dir: model_dir.to_path_buf(),
                message: error.to_string(),
            },
        }
    }

    pub(super) fn status(&self, language: LanguageSetting) -> String {
        let labels = Labels::for_language(language);
        match self {
            Self::Available { training_examples } => {
                format!(
                    "{} · {} {}",
                    labels.available, training_examples, labels.rows
                )
            }
            Self::Missing => labels.unavailable.to_string(),
            Self::Error { model_dir, message } => {
                format!("{}: {}: {message}", labels.open_failed, model_dir.display())
            }
        }
    }
}

pub(super) fn rebuild_model_bundle(model_dir: &Path) -> Result<(), NetdiagError> {
    let artifact_root = model_dir.parent().ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "model directory has no artifact root: {}",
            model_dir.display()
        ))
    })?;
    rebuild_synthetic_model_bundle_in_artifact_root(artifact_root).map(drop)
}

struct Labels {
    available: &'static str,
    unavailable: &'static str,
    open_failed: &'static str,
    rows: &'static str,
}

impl Labels {
    fn for_language(language: LanguageSetting) -> Self {
        match language {
            LanguageSetting::Zh => Self {
                available: "可用",
                unavailable: "不可用",
                open_failed: "打开失败",
                rows: "行",
            },
            LanguageSetting::En => Self {
                available: "Available",
                unavailable: "Unavailable",
                open_failed: "Open failed",
                rows: "rows",
            },
        }
    }
}
