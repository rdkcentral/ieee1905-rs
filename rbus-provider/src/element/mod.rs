use bstr::BStr;
use elements::RBusProviderElements;
use rbus_core::{RBusError, RBusHandle, RBusProperty};
use thiserror::Error;

pub mod elements;
pub mod object;
pub mod property;
pub mod table;
pub mod tuples;

///
/// Base element representing structure of the provider with DSL syntax
///
#[allow(private_interfaces)]
pub trait RBusProviderElement: Send + 'static {
    type UserData: Default + Send;

    ///
    /// Element initialization (like building full path)
    ///
    fn initialize(&mut self, parent: &BStr);

    ///
    /// Collect data elements that are used during registration
    ///
    fn collect_data_elements<'a>(&'a self, target: &mut RBusProviderElements<'a>);

    ///
    /// Handle property getter
    ///
    fn invoke_get(
        &mut self,
        path: &[&BStr],
        args: RBusProviderGetterArgsInner<Self::UserData>,
    ) -> Result<(), RBusProviderElementError>;

    ///
    /// Handle table sync
    ///
    fn invoke_table_sync(
        &mut self,
        path: &[&BStr],
        args: RBusProviderTableSyncArgsInner<Self::UserData>,
    ) -> Result<(), RBusProviderElementError>;
}

///
/// Handler error
///
#[derive(Debug, Error)]
pub(crate) enum RBusProviderElementError {
    #[error("Wrong element")]
    WrongElement,
    #[error("{0}")]
    RBus(#[from] RBusError),
}

///
/// Arguments used by property getter handler
///
pub(crate) struct RBusProviderGetterArgsInner<'a, UserData> {
    pub property: &'a RBusProperty,
    pub path_full: &'a BStr,
    pub path_chunks: &'a [&'a BStr],
    pub table_idx: &'a mut Vec<u32>,
    pub user_data: &'a mut UserData,
}

///
/// Arguments used by table sync handler
///
pub(crate) struct RBusProviderTableSyncArgsInner<'a, UserData> {
    pub handle: &'a RBusHandle,
    pub path_full: &'a BStr,
    pub path_chunks: &'a [&'a BStr],
    pub table_idx: &'a mut Vec<u32>,
    pub user_data: &'a mut UserData,
}
