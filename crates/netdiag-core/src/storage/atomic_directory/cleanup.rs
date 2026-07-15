use super::StagedAtomicDirectory;
use crate::error::NetdiagError;

mod removal;

impl StagedAtomicDirectory {
    pub(super) fn cleanup(self, primary: NetdiagError) -> NetdiagError {
        let context = self.context;
        match self.remove_stage() {
            Ok(()) => primary,
            Err(cleanup) => primary.with_secondary_failure(
                context,
                "staging directory cleanup also failed",
                cleanup,
            ),
        }
    }
}
