//! Durable HIL transaction journal and publisher primitives.
//!
//! Application orchestration belongs in [`crate::hil_review`]. This module must
//! remain independent of Lab and evidence-bundle application services.

mod durability;
mod feedback;
mod journal;
mod publisher;

pub(crate) const MAX_TRANSACTION_JSON_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) use durability::platform::ensure_transaction_durability;
pub(crate) use feedback::read_optional_hil_feedback;
#[cfg(test)]
pub(crate) use journal::journal_path;
pub(crate) use journal::{
    HilReviewJournal, ensure_no_pending_transaction, load_journal, save_journal,
};
pub(crate) use publisher::{JournalPublisher, PreparedTarget};

#[cfg(test)]
pub(crate) use durability::platform::reject_unsupported_durability_for_test;
#[cfg(test)]
pub(crate) use journal::JournalPhase;
#[cfg(test)]
pub(crate) use publisher::fail_before_publishing;
