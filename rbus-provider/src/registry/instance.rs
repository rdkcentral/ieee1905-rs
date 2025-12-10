use crate::element::{
    RBusProviderElement, RBusProviderElementError, RBusProviderGetterArgsInner,
    RBusProviderTableSyncArgsInner,
};
use bstr::BStr;
use rbus_core::{RBusError, RBusHandle, RBusProperty};

///
/// Specific provider registry instance trait
///
/// Note: used to hide generic requirements of the DSL element
///
pub(crate) trait RBusRegistryInstanceTrait: Send + 'static {
    ///
    /// Handle property getter
    ///
    fn invoke_get(&mut self, property: &RBusProperty, path: &BStr) -> Result<(), RBusError>;

    ///
    /// Handle table sync
    ///
    fn invoke_table_sync(&mut self, handle: &RBusHandle, path: &BStr) -> Result<(), RBusError>;
}

///
/// Specific provider registry instance
///
pub(crate) struct RBusRegistryInstance<T: RBusProviderElement> {
    elements: T,
    elements_data: T::UserData,
}

impl<T: RBusProviderElement> RBusRegistryInstance<T> {
    ///
    /// Create new provider registry instance
    ///
    pub fn new(value: T) -> Self {
        Self {
            elements: value,
            elements_data: T::UserData::default(),
        }
    }
}

impl<T> RBusRegistryInstanceTrait for RBusRegistryInstance<T>
where
    T: RBusProviderElement,
{
    fn invoke_get(&mut self, property: &RBusProperty, path: &BStr) -> Result<(), RBusError> {
        let path = path.split(|e| *e == b'.').filter(|e| !e.is_empty());
        let path = path.map(BStr::new).collect::<Vec<_>>();

        let result = self.elements.invoke_get(
            &path,
            RBusProviderGetterArgsInner {
                property,
                table_idx: &mut Vec::new(),
                user_data: &mut self.elements_data,
            },
        );

        result.map_err(|e| match e {
            RBusProviderElementError::WrongElement => RBusError::ElementDoesNotExists,
            RBusProviderElementError::RBus(e) => e,
        })
    }

    fn invoke_table_sync(&mut self, handle: &RBusHandle, path: &BStr) -> Result<(), RBusError> {
        let path_chunks = path.split(|e| *e == b'.').filter(|e| !e.is_empty());
        let path_chunks = path_chunks.map(BStr::new).collect::<Vec<_>>();

        let result = self.elements.invoke_table_sync(
            &path_chunks,
            RBusProviderTableSyncArgsInner {
                handle,
                full_path: path,
                table_idx: &mut Vec::new(),
                user_data: &mut self.elements_data,
            },
        );

        result.map_err(|e| match e {
            RBusProviderElementError::WrongElement => RBusError::ElementDoesNotExists,
            RBusProviderElementError::RBus(e) => e,
        })
    }
}
