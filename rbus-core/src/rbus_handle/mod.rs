mod element;
mod error;
mod status;

use crate::rbus_value::RBusValue;
use crate::{RBusValueReadable, RBusValueWritable};
use rbus_sys::*;
use std::ffi::CStr;
use std::mem::ManuallyDrop;
use std::os::raw::{c_char, c_int};

pub use element::*;
pub use error::*;
pub use status::*;

///
/// An RBus handle which identifies an opened component
///
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct RBusHandle(pub(crate) rbusHandle_t);

unsafe impl Send for RBusHandle {}
unsafe impl Sync for RBusHandle {}

impl RBusHandle {
    ///
    /// Open a bus connection for a software component.
    ///
    /// If multiple components share a software process, the first component that
    /// calls this API will establish a new socket connection to the bus broker.
    /// All calls to this API will receive a dedicated bus handle for that component.
    ///
    /// If a component calls this API more than once, any previous busHandle and all
    /// previous data element registrations will be canceled.
    ///
    /// Note: This API supports a single component per software process and also
    /// supports multiple components that share a software process. In the case of
    /// multiple components that share a software process, each component must call
    /// this API to open a bus connection. Only a single socket connection is opened
    /// per software process but each component within that process receives a
    /// separate busHandle.
    ///
    /// Used by: All RBus components to begin a connection with the bus.
    ///
    pub fn open(name: &CStr) -> Result<Self, RBusError> {
        let mut handle = rbusHandle_t::default();
        let result = unsafe { rbus_open(&mut handle, name.as_ptr()) };
        RBusError::map(result, || Self(handle))
    }

    ///
    /// Components use this API to check whether the rbus-provider is enabled in this device/platform
    ///
    /// Used by: Components that uses rbus-provider to register events, tables and parameters.
    ///
    pub fn check_status() -> RBusStatus {
        let raw = unsafe { rbus_checkStatus() };
        RBusStatus::from_raw(raw)
    }

    ///
    /// A Component uses this API to register one or more named Data Elements
    /// (i.e., parameters and/or event names) that will be accessible/subscribable
    /// by other components. This also registers the callback functions
    /// associated with each data element using the dataElement structure.
    ///
    /// Used by: All components that provide named parameters and/or events that
    /// may be accessed/subscribed by other component(s)
    ///
    pub fn register_data_elements(&self, elements: &[RBusDataElement]) -> Result<(), RBusError> {
        let result = unsafe {
            rbus_regDataElements(
                self.0,
                elements.len() as c_int,
                elements.as_ptr().cast_mut().cast(),
            )
        };
        RBusError::map(result, || ())
    }

    ///
    /// A Component uses this API to unregister one or more previously
    /// registered Data Elements (i.e., named parameters and/or event names) that
    /// will no longer be accessible / subscribable by other components.
    ///
    /// Used by: All components that provide named parameters and/or events that
    /// may be accessed/subscribed by other component(s)
    ///
    pub fn unregister_data_elements(&self, elements: &[RBusDataElement]) -> Result<(), RBusError> {
        let result = unsafe {
            rbus_unregDataElements(
                self.0,
                elements.len() as c_int,
                elements.as_ptr().cast_mut().cast(),
            )
        };
        RBusError::map(result, || ())
    }

    ///
    /// Register a row that the provider has added to its own table.
    ///
    /// This method allows a provider to register a row that it adds to its own table.
    /// A provider can add a row internally without the need to call rbusTable_addRow which would
    /// call the provider's tableAddRow handler. However, in order for consumers to know the row exists,
    /// it must be registered.
    ///
    /// Used by: Any provider that adds a row to its own table.
    ///
    /// # Arguments
    /// * `table_name`    - The name of a table (e.g. "Device.IP.Interface.")
    /// * `instance_id`   - The unique instance number the provider has assigned this row.
    /// * `alias_name`    - An optional name for the new row. Must be unique in the table.
    ///
    pub fn register_table_row(
        &self,
        table_name: &CStr,
        instance_id: u32,
        alias_name: Option<&CStr>,
    ) -> Result<(), RBusError> {
        let result = unsafe {
            rbusTable_registerRow(
                self.0,
                table_name.as_ptr(),
                instance_id,
                alias_name.map(|e| e.as_ptr()).unwrap_or_default(),
            )
        };
        RBusError::map(result, || ())
    }

    ///
    /// Unregister a row that the provider has removed from its own table.
    ///
    /// The method allows a provider to unregister a row that it removes from its own table.
    /// A provider can remove a row internally without the need to call rbusTable_removeRow which would
    /// call the provider's tableRemoveRow handler. However, in order for consumer to know the row no
    /// longer exists, it must be unregistered.
    ///
    /// Used by: Any provider that removes a row from its own table.
    ///
    /// # Arguments
    /// * `row_name` - The name of a table row (e.g. "Device.IP.Interface.1")
    ///
    pub fn unregister_table_row(&self, row_name: &CStr) -> Result<(), RBusError> {
        let result = unsafe { rbusTable_unregisterRow(self.0, row_name.as_ptr()) };
        RBusError::map(result, || ())
    }

    ///
    /// Register tableSyncHandler for table element with dynamic rows.
    ///
    /// Used by: Component that wants to register tableSyncHandler that will register/unregister rows of dynamic table.
    ///
    /// # Arguments
    /// * `table_name` - The name of a table (e.g. "Device.IP.Interface.")
    ///
    pub fn register_dynamic_table_sync_handler<T>(&self, table_name: &CStr) -> Result<(), RBusError>
    where
        T: RBusTableSyncHandler,
    {
        unsafe extern "C" fn handler<T: RBusTableSyncHandler>(
            handle: rbusHandle_t,
            table_name: *const c_char,
        ) -> rbusError_t {
            if handle.is_null() {
                return rbusError_t::RBUS_ERROR_INVALID_HANDLE;
            }
            if table_name.is_null() {
                return rbusError_t::RBUS_ERROR_INVALID_INPUT;
            }

            let handle = ManuallyDrop::new(RBusHandle(handle));
            let table_name = unsafe { CStr::from_ptr(table_name) };
            match T::sync_rows(&handle, table_name) {
                Ok(_) => rbusError_t::RBUS_ERROR_SUCCESS,
                Err(e) => e.to_raw(),
            }
        }
        let result = unsafe {
            rbus_registerDynamicTableSyncHandler(self.0, table_name.as_ptr(), Some(handler::<T>))
        };
        RBusError::map(result, || ())
    }

    ///
    /// Get the value of a single parameter.
    ///
    /// Used by: All components that need to get an individual parameter
    ///
    pub fn get<T>(&self, name: &CStr) -> Result<T, RBusGetError>
    where
        T: RBusValueReadable,
    {
        let value = self.get_value(name).map_err(RBusGetError::RBus)?;
        let value = value.get().map_err(RBusGetError::RBusValue)?;
        Ok(value)
    }

    ///
    /// Get the value of a single parameter.
    ///
    /// Used by: All components that need to get an individual parameter
    ///
    pub fn get_value(&self, name: &CStr) -> Result<RBusValue, RBusError> {
        let mut value = rbusValue_t::default();
        let result = unsafe { rbus_get(self.0, name.as_ptr(), &mut value) };
        RBusError::map(result, || RBusValue(value))
    }

    ///
    /// A component uses this to perform a set operation for a single
    /// explicit parameter and has the option to used delayed (coordinated)
    /// commit commands.
    ///
    /// Used by: All components that need to set an individual parameter
    ///
    pub fn set<T>(&self, name: &CStr, value: &T) -> Result<(), RBusError>
    where
        T: RBusValueWritable + ?Sized,
    {
        self.set_value(name, &RBusValue::from(value))
    }

    ///
    /// A component uses this to perform a set operation for a single
    /// explicit parameter and has the option to used delayed (coordinated)
    /// commit commands.
    ///
    /// Used by: All components that need to set an individual parameter
    ///
    pub fn set_value(&self, name: &CStr, value: &RBusValue) -> Result<(), RBusError> {
        let result = unsafe { rbus_set(self.0, name.as_ptr(), value.0, std::ptr::null_mut()) };
        RBusError::map(result, || ())
    }

    ///
    /// Get a list of the row names in a table
    /// This method allows a consumer to get the names of all rows on a table.
    ///
    /// Used by:  Any component that needs to know the rows in a table.
    ///
    /// # Arguments
    /// * `table_name` - The name of a table (e.g. "Device.IP.Interface.")
    ///
    pub fn get_table_row_names(&self, table_name: &CStr) -> Result<RBusRowNameIter<'_>, RBusError> {
        let mut row_info = std::ptr::null_mut();
        let result = unsafe { rbusTable_getRowNames(self.0, table_name.as_ptr(), &mut row_info) };
        RBusError::map(result, || RBusRowNameIter {
            handle: self,
            root: row_info,
            head: row_info,
        })
    }

    ///
    /// Returns raw handle
    ///
    pub fn to_raw(&self) -> *const () {
        self.0.cast()
    }
}

impl Drop for RBusHandle {
    fn drop(&mut self) {
        unsafe { rbus_close(self.0) };
    }
}

///
/// Table row name
///
pub struct RBusRowName<'a> {
    /// Instance number of the row
    pub instance: u32,
    /// Fully qualified row name
    pub name: &'a CStr,
    /// Alias of the row.
    pub alias: Option<&'a CStr>,
}

///
/// Iterator over table rows
///
pub struct RBusRowNameIter<'a> {
    handle: &'a RBusHandle,
    root: *mut rbusRowName_t,
    head: *mut rbusRowName_t,
}

impl<'a> Drop for RBusRowNameIter<'a> {
    fn drop(&mut self) {
        unsafe { rbusTable_freeRowNames(self.handle.0, self.root) };
    }
}

impl<'a> Iterator for RBusRowNameIter<'a> {
    type Item = RBusRowName<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.head.is_null() {
            return None;
        }

        unsafe {
            let head = &*self.head;
            self.head = head.next;

            let name = CStr::from_ptr(head.name);
            let alias = match head.alias.is_null() {
                true => None,
                false => Some(CStr::from_ptr(head.alias)),
            };

            Some(RBusRowName {
                instance: head.instNum,
                name,
                alias,
            })
        }
    }
}
