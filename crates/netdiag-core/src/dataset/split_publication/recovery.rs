mod claim;
mod collision;
mod committed;
mod partition;
mod target;

pub(super) use claim::claim;
pub(super) use collision::preserve_failed_noclobber_state;
pub(super) use committed::{
    publish as publish_manifest, verify as verify_committed_manifest,
    verify_partition as verify_committed_partition,
};
pub(super) use partition::{recover_or_publish, verify_owned_partition};
pub(super) use target::{ensure_absent, exists as target_exists};
