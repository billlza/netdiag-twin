use crate::error::{IoContext, NetdiagError, Result};
use crate::models::{
    HilFeedbackRecord, HilReview, HilReviewSummary, HilState, Recommendation, RunIndexEntry,
    RunManifest,
};
use crate::report::Report;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

pub fn run_dir(artifact_root: impl AsRef<Path>, run_id: &str) -> PathBuf {
    artifact_root.as_ref().join("runs").join(run_id)
}

pub fn save_json<T: Serialize + ?Sized>(path: impl AsRef<Path>, value: &T) -> Result<PathBuf> {
    save_json_atomic(path, value)
}

pub fn save_json_atomic<T: Serialize + ?Sized>(
    path: impl AsRef<Path>,
    value: &T,
) -> Result<PathBuf> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_path(parent)?;
    }
    let tmp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("json")
    ));
    let write_result = (|| -> Result<()> {
        let file = File::create(&tmp_path).with_path(&tmp_path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, value)?;
        writer.flush().with_path(&tmp_path)?;
        writer.get_ref().sync_all().with_path(&tmp_path)?;
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    fs::rename(&tmp_path, path).with_path(path)?;
    Ok(path.to_path_buf())
}

pub fn read_json(path: impl AsRef<Path>) -> Result<Value> {
    let path = path.as_ref();
    let file = File::open(path).with_path(path)?;
    Ok(serde_json::from_reader(BufReader::new(file))?)
}

pub fn read_manifest(artifact_root: impl AsRef<Path>, run_id: &str) -> Result<RunManifest> {
    let path = run_dir(artifact_root, run_id).join("manifest.json");
    let file = File::open(&path).with_path(&path)?;
    Ok(serde_json::from_reader(BufReader::new(file))?)
}

#[derive(Debug, Clone)]
pub struct HilReviewOutcome {
    pub review: HilReview,
    pub recommendations: Vec<Recommendation>,
    pub status: String,
}

pub fn review_recommendation(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
    recommendation_id: &str,
    state: HilState,
    notes: &str,
    reviewer: &str,
) -> Result<HilReviewOutcome> {
    let artifact_root = artifact_root.as_ref();
    let dir = run_dir(artifact_root, run_id);
    let recommendations_path = dir.join("recommendations.json");
    let mut recommendations: Vec<Recommendation> =
        serde_json::from_value(read_json(&recommendations_path)?)?;
    let Some(recommendation) = recommendations
        .iter_mut()
        .find(|recommendation| recommendation.recommendation_id == recommendation_id)
    else {
        return Err(NetdiagError::UnknownRecommendation(
            recommendation_id.to_string(),
        ));
    };

    let review = HilReview::new(state, notes.trim(), reviewer.trim());
    recommendation.hil_state = state;
    recommendation.review = Some(review.clone());
    save_json_atomic(&recommendations_path, &recommendations)?;

    update_report(&dir, &recommendations)?;
    write_feedback_record(
        &dir,
        HilFeedbackRecord {
            run_id: run_id.to_string(),
            recommendation_id: recommendation_id.to_string(),
            review: review.clone(),
        },
    )?;
    update_manifest_feedback_path(&dir)?;

    let status = HilReviewSummary::from_recommendations(&recommendations)
        .run_status()
        .to_string();
    update_run_index_status(artifact_root, run_id, status.as_str())?;

    Ok(HilReviewOutcome {
        review,
        recommendations,
        status,
    })
}

pub fn write_feedback(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
    item_id: &str,
    state: HilState,
    notes: &str,
) -> Result<PathBuf> {
    let path = run_dir(artifact_root, run_id).join("hil_feedback.json");
    let mut feedback = if path.exists() {
        read_json(&path)?
            .as_object()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<BTreeMap<_, _>>()
    } else {
        BTreeMap::new()
    };
    feedback.insert(
        item_id.to_string(),
        serde_json::json!({
            "state": state,
            "notes": notes,
        }),
    );
    save_json_atomic(path, &feedback)
}

fn update_report(dir: &Path, recommendations: &[Recommendation]) -> Result<()> {
    let report_path = dir.join("report.json");
    if !report_path.exists() {
        return Ok(());
    }
    let mut report: Report = serde_json::from_value(read_json(&report_path)?)?;
    report.recommendations = recommendations.to_vec();
    report.hil_summary = HilReviewSummary::from_recommendations(recommendations);
    save_json_atomic(report_path, &report)?;
    Ok(())
}

fn write_feedback_record(dir: &Path, record: HilFeedbackRecord) -> Result<()> {
    let path = dir.join("hil_feedback.json");
    let mut feedback = if path.exists() {
        serde_json::from_value::<BTreeMap<String, HilFeedbackRecord>>(read_json(&path)?)?
    } else {
        BTreeMap::new()
    };
    feedback.insert(record.recommendation_id.clone(), record);
    save_json_atomic(path, &feedback)?;
    Ok(())
}

fn update_manifest_feedback_path(dir: &Path) -> Result<()> {
    let manifest_path = dir.join("manifest.json");
    if !manifest_path.exists() {
        return Ok(());
    }
    let mut manifest: RunManifest = serde_json::from_value(read_json(&manifest_path)?)?;
    manifest.artifact_paths.insert(
        "hil_feedback".to_string(),
        dir.join("hil_feedback.json").display().to_string(),
    );
    save_json_atomic(manifest_path, &manifest)?;
    Ok(())
}

fn update_run_index_status(artifact_root: &Path, run_id: &str, status: &str) -> Result<()> {
    let index_path = artifact_root.join("run_index.json");
    if !index_path.exists() {
        return Ok(());
    }
    let mut entries: Vec<RunIndexEntry> = serde_json::from_value(read_json(&index_path)?)?;
    for entry in &mut entries {
        if entry.run_id == run_id {
            entry.status = status.to_string();
            break;
        }
    }
    save_json_atomic(index_path, &entries)?;
    Ok(())
}
