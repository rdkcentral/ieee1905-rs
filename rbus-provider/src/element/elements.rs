use crate::registry::{RBusProviderGetter, RBusProviderTableSync};
use rbus_core::{RBusDataElement, RBusError, RBusHandle};
use std::ffi::CStr;

///
/// Data elements collection used to register provider elements
///
#[derive(Default)]
pub(crate) struct RBusProviderElements<'a> {
    tables: Vec<&'a CStr>,
    elements: Vec<RBusDataElement<'a>>,
}

impl<'a> RBusProviderElements<'a> {
    ///
    /// Add table for registration
    ///
    pub fn push_table(&mut self, path: &'a CStr) {
        self.tables.push(path);
        self.elements.push(RBusDataElement::table(path));
    }

    ///
    /// Add property for registration
    ///
    pub fn push_property(&mut self, path: &'a CStr) {
        self.elements
            .push(RBusDataElement::property_ro::<RBusProviderGetter>(path));
    }

    ///
    /// Register elements
    ///
    pub fn register(self, handle: &RBusHandle) -> Result<(), RBusError> {
        handle.register_data_elements(&self.elements)?;

        for path in self.tables.iter() {
            handle
                .register_dynamic_table_sync_handler::<RBusProviderTableSync>(path)
                .inspect_err(|_| {
                    let _ = handle.unregister_data_elements(&self.elements);
                })?;
        }
        Ok(())
    }
}
