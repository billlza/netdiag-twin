use crate::error::{IoContext, NetdiagError, Result};
use completion::{CompletionMode, CompletionStep};
use prepared::PreparedLock;
use process::{HeldLockKey, is_held, process_lock_for};
use std::path::{Path, PathBuf};

mod completion;
mod errors;
mod key;
mod parent_scope;
mod platform;
mod prepared;
mod process;
pub(crate) use parent_scope::{CoordinationParentScope, prospective_component_alias};

#[cfg(test)]
mod tests;

pub fn with_exclusive_file_lock<T>(target: &Path, action: impl FnOnce() -> Result<T>) -> Result<T> {
    with_prepared_lock(PreparedLock::open(target)?, action)
}

pub(crate) fn with_exclusive_bound_file_lock<T>(
    target: &crate::storage::BoundAtomicFileTarget,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    with_prepared_lock_mode(
        PreparedLock::open_bound(target)?,
        action,
        CompletionMode::AtomicPublication,
    )
}

pub(crate) fn with_exclusive_file_locks<T>(
    targets: &[PathBuf],
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    with_prepared_lock_set(prepare_lock_set(targets)?.into_iter(), action)
}

fn prepare_lock_set(targets: &[PathBuf]) -> Result<Vec<PreparedLock>> {
    let mut prepared = targets
        .iter()
        .map(|target| PreparedLock::open(target))
        .collect::<Result<Vec<_>>>()?;
    prepared.sort_by(|left, right| {
        left.key()
            .cmp(right.key())
            .then_with(|| left.target().cmp(right.target()))
    });
    Ok(prepared)
}

#[cfg(test)]
fn with_exclusive_file_lock_in_namespace<T>(
    target: &Path,
    namespace: &Path,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    with_prepared_lock(PreparedLock::open_in_namespace(target, namespace)?, action)
}

fn with_prepared_lock<T>(prepared: PreparedLock, action: impl FnOnce() -> Result<T>) -> Result<T> {
    with_prepared_lock_mode(prepared, action, CompletionMode::Ordinary)
}

fn with_prepared_lock_mode<T>(
    prepared: PreparedLock,
    action: impl FnOnce() -> Result<T>,
    mode: CompletionMode,
) -> Result<T> {
    if is_held(prepared.key()) {
        prepared.validate()?;
        let result = action();
        return mode.combine(
            result,
            prepared.validate(),
            prepared.target(),
            CompletionStep::Identity,
        );
    }

    let process_lock = process_lock_for(prepared.key())?;
    let _process_guard = process_lock.lock().map_err(|_| {
        NetdiagError::InvalidTrace(format!(
            "coordination lock state is poisoned for {}",
            prepared.target().display()
        ))
    })?;
    let lock = prepared.open_lock_file()?;
    lock.lock().with_path(prepared.lock_path())?;
    if let Err(identity_error) = prepared.validate_lock_file(&lock) {
        let unlock_result = lock.unlock().with_path(prepared.lock_path());
        return match unlock_result {
            Ok(()) => Err(identity_error),
            Err(unlock_error) => Err(identity_error.with_secondary_failure(
                "coordination lock validation failed",
                "lock release also failed",
                unlock_error,
            )),
        };
    }
    prepared.validate()?;

    let _held = HeldLockKey::insert(prepared.key().to_string())?;
    let action_result = action();
    let identity_result = prepared
        .validate()
        .and_then(|()| prepared.validate_lock_file(&lock));
    let result = mode.combine(
        action_result,
        identity_result,
        prepared.target(),
        CompletionStep::Identity,
    );
    let unlock_result = lock.unlock().with_path(prepared.lock_path());
    mode.combine(
        result,
        unlock_result,
        prepared.target(),
        CompletionStep::Unlock,
    )
}

fn with_prepared_lock_set<T>(
    mut prepared: std::vec::IntoIter<PreparedLock>,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    match prepared.next() {
        Some(lock) => with_prepared_lock(lock, || with_prepared_lock_set(prepared, action)),
        None => action(),
    }
}

#[cfg(test)]
pub(crate) fn exclusive_file_lock_path(target: &Path) -> Result<PathBuf> {
    PreparedLock::open(target).map(|prepared| prepared.lock_path().to_path_buf())
}

#[cfg(test)]
fn exclusive_bound_file_lock_path(
    target: &crate::storage::BoundAtomicFileTarget,
) -> Result<PathBuf> {
    PreparedLock::open_bound(target).map(|prepared| prepared.lock_path().to_path_buf())
}

pub(crate) fn coordination_parent_scope(target: &Path) -> Result<CoordinationParentScope> {
    parent_scope::inspect(target)
}

#[cfg(all(test, unix))]
fn exclusive_file_lock_path_in_namespace(target: &Path, namespace: &Path) -> Result<PathBuf> {
    PreparedLock::open_in_namespace(target, namespace)
        .map(|prepared| prepared.lock_path().to_path_buf())
}
