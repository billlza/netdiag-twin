use super::{PrepareRequest, PreparedEvidenceSnapshots, SnapshotBuilder};
use crate::error::Result;
use crate::evidence_bundle::context::EvidenceContext;
use crate::evidence_bundle::source::CanonicalRoots;
use crate::storage::run_artifacts_for_location;
use std::collections::BTreeSet;
use std::path::Path;

impl PreparedEvidenceSnapshots {
    pub(in crate::evidence_bundle) fn capture_with_store_observer(
        request: PrepareRequest<'_>,
        after_store_created: impl FnOnce(&Path),
    ) -> Result<Self> {
        let PrepareRequest {
            location,
            run_id,
            context,
            requested_extras,
            allow_pending_transaction,
            source_overrides,
        } = request;
        let context_root = match context {
            EvidenceContext::Plain => None,
            EvidenceContext::Lab | EvidenceContext::Pilot => location
                .lab_run_dir
                .as_deref()
                .or(Some(location.artifact_root.as_path())),
        };
        let roots = CanonicalRoots::new(&location.run_dir, context_root)?;
        let mut builder = SnapshotBuilder::new()?;
        after_store_created(builder.store.path());
        let operation = (|| {
            let artifacts =
                run_artifacts_for_location(location, run_id, allow_pending_transaction)?;
            let mut included_keys = BTreeSet::new();
            for artifact in artifacts {
                included_keys.insert(artifact.key.clone());
                builder.capture_artifact(artifact, &roots, source_overrides)?;
            }
            builder.capture_missing_overrides(&included_keys, &roots, source_overrides)?;
            for required in context.required_files(context_root)? {
                builder.capture_context_file(&required, &roots, source_overrides)?;
            }
            for extra in requested_extras {
                builder.capture_requested_extra(extra)?;
            }
            builder.store.validate_identity()
        })();
        match operation {
            Ok(()) => Ok(builder.into_prepared()),
            Err(error) => builder.finish(Err(error)),
        }
    }
}
