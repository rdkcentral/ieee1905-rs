use crate::element::RBusProviderElement;
use crate::element::elements::RBusProviderElements;
use crate::registry::{RBusRegistryGlobal, RBusRegistryHandle};
use rbus_core::{RBusError, RBusHandle};
use std::ffi::CStr;
use thiserror::Error;

///
/// Provider errors that can happen during registration
///
#[derive(Debug, Error)]
pub enum RBusProviderError {
    #[error("Handle already registered")]
    HandleAlreadyRegistered,
    #[error("{0}")]
    RBus(#[from] RBusError),
}

///
/// Provider which registers elements via DSL syntax
///
pub struct RBusProvider {
    handle: RBusHandle,
    _instance_handle: RBusRegistryHandle,
}

impl RBusProvider {
    ///
    /// Open and register a new provider
    ///
    /// # Arguments
    /// * `name`    - device name
    /// * `builder` - elements DSL builder
    ///
    pub fn open<F, T>(name: &CStr, builder: F) -> Result<Self, RBusProviderError>
    where
        F: FnOnce() -> T,
        T: RBusProviderElement,
    {
        let handle = RBusHandle::open(name)?;

        let mut root_element = builder();
        let mut data_elements = RBusProviderElements::default();

        root_element.initialize("".into());
        root_element.collect_data_elements(&mut data_elements);

        data_elements.register(&handle)?;

        let Ok(instance_handle) = RBusRegistryGlobal::register(&handle, root_element) else {
            return Err(RBusProviderError::HandleAlreadyRegistered);
        };

        Ok(Self {
            handle,
            _instance_handle: instance_handle,
        })
    }

    ///
    /// Gets RBus handle used by this provider
    ///
    pub fn handle(&self) -> &RBusHandle {
        &self.handle
    }
}
