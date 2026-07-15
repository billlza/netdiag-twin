use crate::error::{NetdiagError, Result};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock, Weak};

const MAX_LOCK_STRIPES: usize = 4096;

thread_local! {
    static HELD_LOCK_KEYS: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
}

static PROCESS_LOCKS: OnceLock<Mutex<HashMap<String, Weak<Mutex<()>>>>> = OnceLock::new();

pub(super) fn is_held(key: &str) -> bool {
    HELD_LOCK_KEYS.with(|held| held.borrow().contains(key))
}

pub(super) fn process_lock_for(key: &str) -> Result<Arc<Mutex<()>>> {
    let locks = PROCESS_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut locks = locks.lock().map_err(|_| {
        NetdiagError::InvalidTrace("coordination process-lock registry is poisoned".to_string())
    })?;
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(existing) = locks.get(key).and_then(Weak::upgrade) {
        return Ok(existing);
    }
    if locks.len() >= MAX_LOCK_STRIPES {
        return Err(NetdiagError::InvalidTrace(format!(
            "coordination process-lock registry reached its {MAX_LOCK_STRIPES}-stripe limit"
        )));
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(key.to_string(), Arc::downgrade(&lock));
    Ok(lock)
}

pub(super) struct HeldLockKey(String);

impl HeldLockKey {
    pub(super) fn insert(key: String) -> Result<Self> {
        let inserted = HELD_LOCK_KEYS.with(|held| held.borrow_mut().insert(key.clone()));
        if !inserted {
            return Err(NetdiagError::InvalidTrace(format!(
                "coordination lock key was already held without reentrant dispatch: {key}"
            )));
        }
        Ok(Self(key))
    }
}

impl Drop for HeldLockKey {
    fn drop(&mut self) {
        HELD_LOCK_KEYS.with(|held| {
            held.borrow_mut().remove(&self.0);
        });
    }
}
