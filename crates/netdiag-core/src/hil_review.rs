use crate::error::{NetdiagError, Result};
use crate::evidence_bundle::{EvidenceSourceOverride, export_evidence_bundle_for_transaction};
use crate::lab::LabReviewArtifactPlan;
use crate::models::{FaultLabel, HilReview, HilReviewSummary, HilState, Recommendation};
use crate::storage::hil_transaction::{
    HilReviewJournal, JournalPublisher, PreparedTarget, ensure_transaction_durability,
    load_journal, save_journal,
};
use crate::storage::{
    RunLocation, ensure_no_pending_action_verification_transaction, find_run_location, path_status,
    with_owned_artifact_root, with_transaction_target_locks,
};
use std::path::{Path, PathBuf};

mod plan;
use plan::{PipelineReviewPlan, plan_pipeline_review, read_recommendations};

const MAX_TRANSACTION_JSON_BYTES: u64 = crate::storage::hil_transaction::MAX_TRANSACTION_JSON_BYTES;

#[cfg(test)]
pub(crate) use crate::storage::hil_transaction::fail_before_publishing;
#[cfg(test)]
use crate::storage::hil_transaction::journal_path;

#[derive(Debug, Clone)]
pub struct HilReviewOutcome {
    pub review: HilReview,
    pub recommendations: Vec<Recommendation>,
    pub status: String,
    pub evidence_bundle_stale: bool,
    pub next_step: Option<String>,
}

pub fn review_recommendation(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
    recommendation_id: &str,
    state: HilState,
    notes: &str,
    reviewer: &str,
    final_label: Option<FaultLabel>,
) -> Result<HilReviewOutcome> {
    ensure_transaction_durability()?;
    let artifact_root = artifact_root.as_ref();
    with_owned_artifact_root(artifact_root, |_| {
        let location = resolve_review_location(artifact_root, run_id)?;
        with_transaction_target_locks(&location, run_id, || {
            review_under_locks(
                &location,
                run_id,
                recommendation_id,
                state,
                notes,
                reviewer,
                final_label,
            )
        })
    })
}

fn resolve_review_location(artifact_root: &Path, run_id: &str) -> Result<RunLocation> {
    if let Some(location) = find_run_location(artifact_root, run_id)? {
        return Ok(location);
    }
    let direct_run_dir = crate::storage::run_dir(artifact_root, run_id)?;
    let metadata = match std::fs::symlink_metadata(&direct_run_dir) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(NetdiagError::InvalidTrace(format!(
                "unknown run id: {run_id}"
            )));
        }
        Err(source) => {
            return Err(NetdiagError::Io {
                path: direct_run_dir,
                source,
            });
        }
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(NetdiagError::InvalidTrace(format!(
            "run directory is not a regular directory: {}",
            direct_run_dir.display()
        )));
    }
    let canonical_root =
        std::fs::canonicalize(artifact_root).map_err(|source| NetdiagError::Io {
            path: artifact_root.to_path_buf(),
            source,
        })?;
    let canonical_run =
        std::fs::canonicalize(&direct_run_dir).map_err(|source| NetdiagError::Io {
            path: direct_run_dir.clone(),
            source,
        })?;
    if !canonical_run.starts_with(&canonical_root) {
        return Err(NetdiagError::InvalidTrace(format!(
            "run directory is outside the artifact root: {}",
            direct_run_dir.display()
        )));
    }
    let lab_run_dir = (path_status(&artifact_root.join("scenario.yaml"))?.exists()
        || path_status(&artifact_root.join("pilot.yaml"))?.exists())
    .then(|| artifact_root.to_path_buf());
    Ok(RunLocation {
        artifact_root: artifact_root.to_path_buf(),
        run_dir: direct_run_dir,
        lab_run_dir,
        lab_index_root: None,
    })
}

fn review_under_locks(
    location: &RunLocation,
    run_id: &str,
    recommendation_id: &str,
    state: HilState,
    notes: &str,
    reviewer: &str,
    final_label: Option<FaultLabel>,
) -> Result<HilReviewOutcome> {
    ensure_no_pending_action_verification_transaction(&location.run_dir, run_id)?;
    if let Some(mut existing) = load_journal(&location.run_dir, run_id)? {
        execute_transaction(location, &mut existing)?;
        if request_matches(
            &existing,
            recommendation_id,
            state,
            notes,
            reviewer,
            final_label,
        ) {
            return outcome(location, &existing);
        }
    }

    let mut journal = prepare_transaction(
        location,
        run_id,
        recommendation_id,
        state,
        notes,
        reviewer,
        final_label,
    )?;
    preflight_transaction(location, &journal)?;
    save_journal(&location.run_dir, &journal)?;
    execute_transaction(location, &mut journal)?;
    outcome(location, &journal)
}

fn prepare_transaction(
    location: &RunLocation,
    run_id: &str,
    recommendation_id: &str,
    state: HilState,
    notes: &str,
    reviewer: &str,
    final_label: Option<FaultLabel>,
) -> Result<HilReviewJournal> {
    let mut recommendations = read_recommendations(&location.run_dir)?;
    let recommendation = recommendations
        .iter_mut()
        .find(|recommendation| recommendation.recommendation_id == recommendation_id)
        .ok_or_else(|| NetdiagError::UnknownRecommendation(recommendation_id.to_string()))?;
    let review = HilReview::with_final_label(state, notes.trim(), reviewer.trim(), final_label);
    recommendation.hil_state = state;
    recommendation.review = Some(review.clone());
    let status = HilReviewSummary::from_recommendations(&recommendations)
        .run_status()
        .to_string();
    Ok(HilReviewJournal::new(
        run_id,
        recommendation_id,
        review,
        recommendations,
        status,
    ))
}

fn preflight_transaction(location: &RunLocation, journal: &HilReviewJournal) -> Result<()> {
    plan_pipeline_review(location, journal)?;
    crate::lab::preflight_lab_review_artifacts(
        location,
        &journal.run_id,
        &journal.recommendations,
        journal.review.reviewed_at,
    )
}

fn execute_transaction(location: &RunLocation, journal: &mut HilReviewJournal) -> Result<()> {
    journal.validate(&journal.run_id)?;
    let plan = ReviewTransactionPlan {
        pipeline: plan_pipeline_review(location, journal)?,
        lab: crate::lab::plan_lab_review_artifacts(
            location,
            &journal.run_id,
            &journal.recommendations,
            journal.review.reviewed_at,
        )?,
    };
    let run_id = journal.run_id.clone();
    let recommendations = journal.recommendations.clone();
    let reviewed_at = journal.review.reviewed_at;
    let expected = plan.expected_targets();
    let expected_refs = expected
        .iter()
        .map(|(key, path)| (*key, path.as_path()))
        .collect::<Vec<_>>();
    let mut publisher = JournalPublisher::new(&location.run_dir, journal);
    if publisher.has_no_targets() {
        let prepared = prepare_all_targets(
            location,
            &publisher,
            &plan,
            &run_id,
            &recommendations,
            reviewed_at,
        )?;
        publisher.register_all(&prepared)?;
    }
    publisher.begin_commit()?;
    publisher.verify_or_publish_all(&expected_refs)?;
    publisher.finish_commit()
}

struct ReviewTransactionPlan {
    pipeline: PipelineReviewPlan,
    lab: Option<LabReviewArtifactPlan>,
}

impl ReviewTransactionPlan {
    fn expected_targets(&self) -> Vec<(&'static str, PathBuf)> {
        let mut targets = vec![
            (
                "recommendations",
                self.pipeline.recommendations_path.clone(),
            ),
            ("report", self.pipeline.report_path.clone()),
            ("hil_feedback", self.pipeline.feedback_path.clone()),
            ("manifest", self.pipeline.manifest_path.clone()),
            ("run_index", self.pipeline.run_index_path.clone()),
        ];
        if let Some(lab) = &self.lab {
            targets.extend([
                ("lab_report", lab.report_path.clone()),
                ("lab_acceptance", lab.acceptance_path.clone()),
                ("lab_comparison", lab.comparison_path.clone()),
                ("lab_evidence_archive", lab.archive_path.clone()),
                ("lab_evidence_manifest", lab.bundle_manifest_path.clone()),
            ]);
            if let Some((index_path, _)) = &lab.index {
                targets.push(("lab_run_index", index_path.clone()));
            }
        }
        targets
    }
}

fn prepare_all_targets(
    location: &RunLocation,
    publisher: &JournalPublisher<'_>,
    plan: &ReviewTransactionPlan,
    run_id: &str,
    recommendations: &[Recommendation],
    reviewed_at: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<PreparedTarget>> {
    let mut prepared = vec![
        publisher.prepare_json(
            "recommendations",
            &plan.pipeline.recommendations_path,
            recommendations,
        )?,
        publisher.prepare_json("report", &plan.pipeline.report_path, &plan.pipeline.report)?,
        publisher.prepare_json(
            "hil_feedback",
            &plan.pipeline.feedback_path,
            &plan.pipeline.feedback,
        )?,
        publisher.prepare_json(
            "manifest",
            &plan.pipeline.manifest_path,
            &plan.pipeline.manifest,
        )?,
        publisher.prepare_json(
            "run_index",
            &plan.pipeline.run_index_path,
            &plan.pipeline.run_index,
        )?,
    ];
    if let Some(lab) = &plan.lab {
        prepared.push(publisher.prepare_json("lab_report", &lab.report_path, &lab.report)?);
        prepared.push(publisher.prepare_json(
            "lab_acceptance",
            &lab.acceptance_path,
            &lab.acceptance,
        )?);
        prepared.push(publisher.prepare_json(
            "lab_comparison",
            &lab.comparison_path,
            &lab.comparison,
        )?);
        let overrides = evidence_source_overrides(&prepared);
        let (archive, bundle) = publisher.prepare_generated(
            "lab_evidence_archive",
            &lab.archive_path,
            |staged_output| {
                export_evidence_bundle_for_transaction(
                    location,
                    run_id,
                    staged_output,
                    &lab.archive_path,
                    reviewed_at,
                    &overrides,
                )
            },
        )?;
        prepared.push(archive);
        prepared.push(publisher.prepare_json(
            "lab_evidence_manifest",
            &lab.bundle_manifest_path,
            &bundle,
        )?);
        if let Some((index_path, index)) = &lab.index {
            prepared.push(publisher.prepare_json("lab_run_index", index_path, index)?);
        }
    }
    Ok(prepared)
}

fn evidence_source_overrides(prepared: &[PreparedTarget]) -> Vec<EvidenceSourceOverride> {
    prepared
        .iter()
        .filter_map(|target| {
            let include_if_missing = match target.key() {
                "hil_feedback" => true,
                "manifest" | "report" | "recommendations" | "lab_acceptance" | "lab_comparison" => {
                    false
                }
                _ => return None,
            };
            Some(EvidenceSourceOverride {
                key: target.key().to_string(),
                target_path: target.target().to_path_buf(),
                staged_path: target.staged().to_path_buf(),
                include_if_missing,
            })
        })
        .collect()
}

fn request_matches(
    journal: &HilReviewJournal,
    recommendation_id: &str,
    state: HilState,
    notes: &str,
    reviewer: &str,
    final_label: Option<FaultLabel>,
) -> bool {
    journal.recommendation_id == recommendation_id
        && journal.review.state == state
        && journal.review.notes == notes.trim()
        && journal.review.reviewer == reviewer.trim()
        && journal.review.final_label == final_label
}

fn outcome(location: &RunLocation, journal: &HilReviewJournal) -> Result<HilReviewOutcome> {
    let (evidence_bundle_stale, next_step) = evidence_bundle_staleness(location)?;
    Ok(HilReviewOutcome {
        review: journal.review.clone(),
        recommendations: journal.recommendations.clone(),
        status: journal.status.clone(),
        evidence_bundle_stale,
        next_step,
    })
}

fn evidence_bundle_staleness(location: &RunLocation) -> Result<(bool, Option<String>)> {
    if location.lab_run_dir.is_some() {
        return Ok((false, None));
    }
    let bundle = location.run_dir.join("evidence_bundle.json");
    match std::fs::symlink_metadata(&bundle) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok((
            true,
            Some("run evidence-bundle again after review".to_string()),
        )),
        Ok(_) => Err(NetdiagError::InvalidTrace(format!(
            "evidence bundle manifest is not a regular file: {}",
            bundle.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((false, None)),
        Err(error) => Err(NetdiagError::Io {
            path: bundle,
            source: error,
        }),
    }
}

#[cfg(test)]
mod tests;
