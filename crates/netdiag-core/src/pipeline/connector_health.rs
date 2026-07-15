use crate::error::{NetdiagError, Result};
use crate::models::{ConnectorHealthSnapshot, IngestResult};

pub(super) fn validated_connector_health(
    ingest: &IngestResult,
    supplied: Option<ConnectorHealthSnapshot>,
) -> Result<ConnectorHealthSnapshot> {
    let Some(supplied) = supplied else {
        return Ok(ConnectorHealthSnapshot::from_ingest(
            "ingest",
            &ingest.schema.sample,
            &ingest.schema.sample,
            ingest,
        ));
    };
    let expected = ConnectorHealthSnapshot::from_ingest(
        &supplied.source_kind,
        &supplied.profile_name,
        &supplied.sample,
        ingest,
    );
    if supplied != expected {
        return Err(NetdiagError::InvalidTrace(
            "connector health does not match the supplied ingest result".to_string(),
        ));
    }
    Ok(supplied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::ingest_trace;
    use std::path::PathBuf;

    fn ingest() -> IngestResult {
        ingest_trace(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/samples/normal.csv"),
        )
        .expect("sample ingest")
    }

    #[test]
    fn supplied_health_must_match_all_ingest_derived_fields() {
        let ingest = ingest();
        let mut health =
            ConnectorHealthSnapshot::from_ingest("http-json", "lab-router", "sample", &ingest);
        health.rows += 1;

        let error = validated_connector_health(&ingest, Some(health))
            .expect_err("mismatched health must fail before publication");
        assert!(error.to_string().contains("does not match"), "{error}");
    }
}
