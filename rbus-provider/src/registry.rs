use crate::element::RBusProviderElement;
use crate::registry::instance::{RBusRegistryInstance, RBusRegistryInstanceTrait};
use indexmap::IndexMap;
use indexmap::map::Entry;
use parking_lot::Mutex;
use rbus_core::{RBusDataElementGet, RBusError, RBusHandle, RBusProperty, RBusTableSyncHandler};
use std::ffi::CStr;
use std::sync::OnceLock;

pub mod instance;

///
/// Singleton responsible for handling handlers/callbacks
///
pub(crate) struct RBusRegistryGlobal {
    instances: IndexMap<usize, Box<dyn RBusRegistryInstanceTrait>>,
}

impl RBusRegistryGlobal {
    ///
    /// Get singleton instance
    ///
    fn get() -> &'static Mutex<RBusRegistryGlobal> {
        static SELF: OnceLock<Mutex<RBusRegistryGlobal>> = OnceLock::new();
        SELF.get_or_init(|| {
            Mutex::new(RBusRegistryGlobal {
                instances: Default::default(),
            })
        })
    }

    ///
    /// Register new more handlers
    ///
    /// # Arguments
    /// * `handle`  - rbus handle, used as a user data to distinguish handlers
    /// * `element` - DSL element with handlers
    ///
    pub fn register<T>(handle: &RBusHandle, element: T) -> Result<RBusRegistryHandle, T>
    where
        T: RBusProviderElement,
    {
        let key = handle.to_raw().addr();
        match Self::get().lock().instances.entry(key) {
            Entry::Occupied(_) => Err(element),
            Entry::Vacant(e) => {
                e.insert(Box::new(RBusRegistryInstance::new(element)));
                Ok(RBusRegistryHandle(key))
            }
        }
    }
}

///
/// Handle which unregisters provider when dropped
///
pub(crate) struct RBusRegistryHandle(usize);

impl Drop for RBusRegistryHandle {
    fn drop(&mut self) {
        RBusRegistryGlobal::get()
            .lock()
            .instances
            .swap_remove(&self.0);
    }
}

///
/// Global getter handler
///
pub(crate) struct RBusProviderGetter;

impl RBusDataElementGet for RBusProviderGetter {
    fn get(handle: &RBusHandle, property: &RBusProperty) -> Result<(), RBusError> {
        let mut lock = RBusRegistryGlobal::get().lock();
        let Some(instance) = lock.instances.get_mut(&handle.to_raw().addr()) else {
            return Err(RBusError::InvalidHandle);
        };

        let path = property.get_name().to_bytes().into();
        instance.invoke_get(property, path)
    }
}

///
/// Global table sync handler
///
pub(crate) struct RBusProviderTableSync;

impl RBusTableSyncHandler for RBusProviderTableSync {
    fn sync_rows(handle: &RBusHandle, table_name: &CStr) -> Result<(), RBusError> {
        let mut lock = RBusRegistryGlobal::get().lock();
        let Some(instance) = lock.instances.get_mut(&handle.to_raw().addr()) else {
            return Err(RBusError::InvalidHandle);
        };

        let path = table_name.to_bytes().into();
        instance.invoke_table_sync(handle, path)
    }
}
