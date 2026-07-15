use super::*;
use crate::dataset::rows::DatasetRow;
use crate::dataset::split_publication::plan::PartitionPlan;
use crate::error::{AtomicPublishPhase, NetdiagError};
use crate::models::FaultLabel;

#[test]
fn created_partition_is_durably_removed_when_verification_fails() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = TrustedDatasetRoot::open(temp.path()).expect("trusted dataset root");
    let plan = PartitionPlan::new(
        root.target("train.jsonl").expect("bound train target"),
        &[row()],
    )
    .expect("partition plan");

    let error = recover_or_publish_with(&root, &plan, &[row()], |_| {
        Err(NetdiagError::InvalidTrace(
            "injected created partition verification failure".to_string(),
        ))
    })
    .expect_err("verification failure must roll back the exact created target");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    let NetdiagError::AtomicPublish { path, source, .. } = error else {
        panic!("expected exact partition publication state");
    };
    assert_eq!(path, plan.target.resolved_path());
    assert!(matches!(
        source.as_ref(),
        NetdiagError::InvalidTrace(message)
            if message == "injected created partition verification failure"
    ));
    assert!(!plan.target.resolved_path().exists());
}

fn row() -> DatasetRow {
    DatasetRow {
        line_number: 1,
        line: "{}".to_string(),
        label: FaultLabel::Normal,
    }
}
