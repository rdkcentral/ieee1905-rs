use super::RBusError;
use std::collections::HashSet;
use std::ffi::CStr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

pub(super) struct RBusHandleName(Arc<CStr>);

impl RBusHandleName {
    pub(super) fn reserve(name: &CStr) -> Result<Self, RBusError> {
        let mut names = Self::names();
        if names.contains(name) {
            return Err(RBusError::ComponentNameDuplication);
        }

        let name = Arc::<CStr>::from(name);
        names.insert(name.clone());
        Ok(Self(name))
    }

    fn names() -> MutexGuard<'static, HashSet<Arc<CStr>>> {
        static NAMES: OnceLock<Mutex<HashSet<Arc<CStr>>>> = OnceLock::new();
        NAMES
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

impl Drop for RBusHandleName {
    fn drop(&mut self) {
        Self::names().remove(self.0.as_ref());
    }
}
