//! Filesystem + JSON implementation of StateMgr.

use crate::err::{Action, ErrorSource, Resource};
use crate::{Error, LockStatus, Result, StateMgr};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Implementation of StateMgr that stores state in memory.
/// We fake locking by using a boolean flag to satisfy the trait
#[derive(Clone, Debug)]
pub struct MemStateMgr {
    /// Inner reference-counted object.
    inner: Arc<MemStateMgrInner>,
}

/// Inner reference-counted object, used by `MemStateMgr`.
#[derive(Debug)]
struct MemStateMgrInner {
    data: Mutex<HashMap<String, Vec<u8>>>,
    lock: Mutex<bool>,
}

impl MemStateMgr {
    /// Create a new `MemStateMgr`.
    pub fn new() -> Self {
        let inner = MemStateMgrInner {
            data: Mutex::new(HashMap::new()),
            lock: Mutex::new(false),
        };
        Self {
            inner: Arc::new(inner),
        }
    }
}

impl StateMgr for MemStateMgr {
    fn can_store(&self) -> bool {
        true
    }
    fn try_lock(&self) -> Result<LockStatus> {
        let mut lock = self.inner.lock.lock().unwrap();
        if *lock {
            return Ok(LockStatus::AlreadyHeld);
        }
        *lock = true;
        Ok(LockStatus::NewlyAcquired)
    }
    fn unlock(&self) -> Result<()> {
        let mut lock = self.inner.lock.lock().unwrap();
        if !*lock {
            return Err(Error::new(
                ErrorSource::NoLock,
                Action::Unlocking,
                Resource::Manager,
            ));
        }
        *lock = false;
        Ok(())
    }
    fn load<D>(&self, key: &str) -> Result<Option<D>>
    where
        D: DeserializeOwned,
    {
        let data = self.inner.data.lock().unwrap();
        if let Some(bytes) = data.get(key) {
            let value = serde_json::from_slice(bytes).unwrap();
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    fn store<S>(&self, key: &str, val: &S) -> Result<()>
    where
        S: Serialize,
    {
        if !self.can_store() {
            return Err(Error::new(
                ErrorSource::NoLock,
                Action::Storing,
                Resource::Manager,
            ));
        }
        let mut data = self.inner.data.lock().unwrap();
        let bytes = serde_json::to_vec(val).unwrap();
        data.insert(key.to_string(), bytes);
        Ok(())
    }
}
