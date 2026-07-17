use super::errors::{
    combine_action_and_identity, combine_publication_completion, combine_with_unlock,
};
use crate::error::Result;
use std::path::Path;

#[derive(Clone, Copy)]
pub(super) enum CompletionMode {
    Ordinary,
    AtomicPublication,
}

#[derive(Clone, Copy)]
pub(super) enum CompletionStep {
    Identity,
    Unlock,
}

impl CompletionStep {
    fn context(self) -> &'static str {
        match self {
            Self::Identity => "coordination lock identity validation also failed",
            Self::Unlock => "lock release also failed",
        }
    }
}

impl CompletionMode {
    pub(super) fn combine<T>(
        self,
        result: Result<T>,
        completion: Result<()>,
        target: &Path,
        step: CompletionStep,
    ) -> Result<T> {
        match (self, step) {
            (Self::Ordinary, CompletionStep::Identity) => {
                combine_action_and_identity(result, completion)
            }
            (Self::Ordinary, CompletionStep::Unlock) => combine_with_unlock(result, completion),
            (Self::AtomicPublication, step) => {
                combine_publication_completion(result, completion, target, step.context())
            }
        }
    }
}
