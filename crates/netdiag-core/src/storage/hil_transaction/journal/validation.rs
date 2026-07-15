use super::{HilReviewJournal, JOURNAL_SCHEMA};
use crate::error::{NetdiagError, Result};
use crate::models::HilReviewSummary;
use std::collections::BTreeSet;

impl HilReviewJournal {
    pub(crate) fn validate(&self, expected_run_id: &str) -> Result<()> {
        if self.schema != JOURNAL_SCHEMA {
            return Err(NetdiagError::InvalidTrace(format!(
                "unsupported HIL transaction schema {}",
                self.schema
            )));
        }
        uuid::Uuid::parse_str(&self.transaction_id).map_err(|error| {
            NetdiagError::InvalidTrace(format!(
                "invalid HIL transaction id {}: {error}",
                self.transaction_id
            ))
        })?;
        if self.run_id != expected_run_id {
            return Err(NetdiagError::InvalidTrace(format!(
                "HIL transaction run id {} does not match {expected_run_id}",
                self.run_id
            )));
        }
        validate_targets(self)?;
        self.validate_review_and_status()
    }

    fn validate_review_and_status(&self) -> Result<()> {
        let recommendation = self
            .recommendations
            .iter()
            .find(|recommendation| recommendation.recommendation_id == self.recommendation_id)
            .ok_or_else(|| {
                NetdiagError::InvalidTrace(format!(
                    "HIL transaction recommendation {} is absent",
                    self.recommendation_id
                ))
            })?;
        let review_matches = recommendation.hil_state == self.review.state
            && recommendation.review.as_ref().is_some_and(|review| {
                review.state == self.review.state
                    && review.notes == self.review.notes
                    && review.reviewer == self.review.reviewer
                    && review.reviewed_at == self.review.reviewed_at
                    && review.final_label == self.review.final_label
            });
        if !review_matches {
            return Err(NetdiagError::InvalidTrace(
                "HIL transaction review does not match its recommendation".to_string(),
            ));
        }
        let expected_status =
            HilReviewSummary::from_recommendations(&self.recommendations).run_status();
        if self.status != expected_status {
            return Err(NetdiagError::InvalidTrace(format!(
                "HIL transaction status {} does not match {expected_status}",
                self.status
            )));
        }
        Ok(())
    }
}

fn validate_targets(journal: &HilReviewJournal) -> Result<()> {
    let mut keys = BTreeSet::new();
    for target in &journal.targets {
        if !keys.insert(target.key.as_str()) {
            return Err(NetdiagError::InvalidTrace(format!(
                "duplicate HIL transaction target key: {}",
                target.key
            )));
        }
        if !valid_sha256(&target.new_sha256)
            || target
                .expected_old_sha256
                .as_deref()
                .is_some_and(|hash| !valid_sha256(hash))
        {
            return Err(NetdiagError::InvalidTrace(format!(
                "invalid HIL transaction target hash for {}",
                target.key
            )));
        }
    }
    Ok(())
}

fn valid_sha256(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
