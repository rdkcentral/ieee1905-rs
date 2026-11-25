mod element;
mod error;
mod status;

use crate::rbus_event::dispatch_event;
use crate::rbus_library::{RBusComponentNameReservation, RBusLibrary};
use crate::rbus_value::RBusValue;
use crate::{
    RBusEventHandler, RBusEventSubscription, RBusSubscribeOptions, RBusValueReadable,
    RBusValueWritable,
};
pub use element::*;
pub use error::*;
use rbus_sys::*;
pub use status::*;
use std::ffi::CStr;
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::raw::{c_char, c_int};

///
/// An RBus handle which identifies an opened component
/// Dereferences to [`RBusHandleRef`] for connection operations.
/// Dropping the owner closes the connection and releases its component name.
///
pub struct RBusHandle {
    inner: RBusHandleRef,
    _component_name_reservation: RBusComponentNameReservation,
}

///
/// Operations on a connection, borrowed as `&RBusHandleRef`.
/// Only [`crate::RBusHandle`] owns and closes the native connection.
/// Callback-local instances drop their `RBusLibrary` field normally without
/// closing the native connection. This type cannot be cloned or copied out of
/// a borrow.
///
/// ```compile_fail,E0597
/// use rbus_core::{RBusHandle, RBusLibrary};
/// fn example(library: &RBusLibrary) -> Result<(), Box<dyn std::error::Error>> {
///     let borrowed: &rbus_core::RBusHandleRef = {
///         let owner = RBusHandle::open(library, c"borrowed-connection")?;
///         &owner
///     };
///     borrowed.get::<i32>(c"Device.Test.Value")?;
///     Ok(())
/// }
/// ```
///
/// ```compile_fail,E0507
/// use rbus_core::RBusHandleRef;
/// fn take_connection(handle: &RBusHandleRef) -> RBusHandleRef {
///     *handle
/// }
/// ```
pub struct RBusHandleRef {
    pub(crate) handle: rbusHandle_t,
    pub(crate) library: RBusLibrary,
}

// Native connections support shared access across threads.
unsafe impl Send for RBusHandleRef {}
unsafe impl Sync for RBusHandleRef {}

impl RBusHandle {
    ///
    /// Open a bus connection for a software component.
    ///
    /// If multiple components share a software process, the first component that
    /// calls this API will establish a new socket connection to the bus broker.
    /// All calls to this API will receive a dedicated bus handle for that component.
    ///
    /// Opening a component name that is already in use returns
    /// RBusError::ComponentNameDuplication without closing the existing connection.
    /// The name can be reused after its handle is dropped.
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
    pub fn open(library: &RBusLibrary, name: &CStr) -> Result<Self, RBusError> {
        let reserved_component_name = library.reserve_component_name(name)?;
        let mut handle = rbusHandle_t::default();
        let result = unsafe { library.as_raw().rbus_open(&mut handle, name.as_ptr()) };

        RBusError::map(result, || Self {
            inner: RBusHandleRef {
                handle,
                library: library.clone(),
            },
            _component_name_reservation: reserved_component_name,
        })
    }
}

impl RBusHandleRef {
    /// Get library this handle was created with
    pub fn library(&self) -> &RBusLibrary {
        &self.library
    }

    ///
    /// Subscribe with no retry when no provider is available.
    /// See [`Self::subscribe_event_with_options`] for callback behavior.
    ///
    pub fn subscribe_event<T: RBusEventHandler>(
        &self,
        event_name: &CStr,
    ) -> Result<RBusEventSubscription<'_>, RBusError> {
        self.subscribe_event_with_options::<T>(event_name, RBusSubscribeOptions::default())
    }

    ///
    /// Subscribe with options controlling retries during establishment.
    /// The callback runs on an RBus thread and may begin before this returns.
    /// With `panic = "unwind"`, callback panics are caught before returning to C.
    /// With `panic = "abort"`, including this workspace's release profile,
    /// a callback panic terminates the process.
    /// Create and drop subscriptions from outside event callbacks.
    /// Do not close the receiving connection from an event callback.
    ///
    pub fn subscribe_event_with_options<T: RBusEventHandler>(
        &self,
        event_name: &CStr,
        options: RBusSubscribeOptions,
    ) -> Result<RBusEventSubscription<'_>, RBusError> {
        let mut timeout =
            i32::try_from(options.timeout.as_secs()).map_err(|_| RBusError::InvalidInput)?;

        // Round fractional seconds up so the final timeout is never smaller than requested.
        if options.timeout.subsec_nanos() != 0 {
            timeout = timeout.checked_add(1).ok_or(RBusError::InvalidInput)?;
        }

        // Native RBus multiplies the timeout by 1000 using a signed int.
        if timeout > i32::MAX / 1000 {
            return Err(RBusError::InvalidInput);
        }

        let event_name = event_name.to_owned();
        let result = unsafe {
            self.library().as_raw().rbusEvent_Subscribe(
                self.handle,
                event_name.as_ptr(),
                Some(dispatch_event::<T>),
                std::ptr::null_mut(),
                timeout,
            )
        };
        RBusError::map(result, || RBusEventSubscription {
            handle: self,
            event_name,
        })
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
        let library = self.library.as_raw();
        let result = unsafe {
            library.rbus_regDataElements(
                self.handle,
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
        let library = self.library.as_raw();
        let result = unsafe {
            library.rbus_unregDataElements(
                self.handle,
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
        let library = self.library.as_raw();
        let result = unsafe {
            library.rbusTable_registerRow(
                self.handle,
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
        let library = self.library.as_raw();
        let result = unsafe { library.rbusTable_unregisterRow(self.handle, row_name.as_ptr()) };
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

            // SAFETY: RBus keeps the connection and terminated name valid for this callback.
            let result = unsafe {
                RBusHandleRef::run_with_raw(handle, |handle| {
                    let table_name = CStr::from_ptr(table_name);
                    T::sync_rows(handle, table_name)
                })
            };

            match result {
                Ok(_) => rbusError_t::RBUS_ERROR_SUCCESS,
                Err(e) => e.to_raw(),
            }
        }
        let library = self.library.as_raw();
        let result = unsafe {
            library.rbus_registerDynamicTableSyncHandler(
                self.handle,
                table_name.as_ptr(),
                Some(handler::<T>),
            )
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
        let library = self.library.as_raw();
        let result = unsafe { library.rbus_get(self.handle, name.as_ptr(), &mut value) };

        RBusError::map(result, || RBusValue {
            handle: value,
            library: self.library.clone(),
        })
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
        self.set_value(name, &RBusValue::from(&self.library, value))
    }

    ///
    /// A component uses this to perform a set operation for a single
    /// explicit parameter and has the option to used delayed (coordinated)
    /// commit commands.
    ///
    /// Used by: All components that need to set an individual parameter
    ///
    pub fn set_value(&self, name: &CStr, value: &RBusValue) -> Result<(), RBusError> {
        let library = self.library.as_raw();
        let result = unsafe {
            library.rbus_set(
                self.handle,
                name.as_ptr(),
                value.handle,
                std::ptr::null_mut(),
            )
        };
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
    pub fn get_table_row_names(&self, table_name: &CStr) -> Result<RBusRowNames<'_>, RBusError> {
        let mut row_info = std::ptr::null_mut();
        let library = self.library.as_raw();
        let result = unsafe {
            library.rbusTable_getRowNames(self.handle, table_name.as_ptr(), &mut row_info)
        };
        RBusError::map(result, || RBusRowNames {
            handle: self,
            root: row_info,
        })
    }

    ///
    /// Returns raw handle
    ///
    pub fn to_raw(&self) -> *const () {
        self.handle.cast()
    }

    ///
    /// Borrow a connection for the duration of a native callback.
    /// The temporary wrapper drops its library reference normally.
    ///
    /// # Safety
    /// The native handle must remain valid until the callback returns.
    ///
    pub(crate) unsafe fn run_with_raw<T, F>(handle: rbusHandle_t, f: F) -> Result<T, RBusError>
    where
        F: FnOnce(&Self) -> Result<T, RBusError>,
    {
        let library = RBusLibrary::load().map_err(|_| RBusError::GeneralError)?;
        let handle = Self { handle, library };
        f(&handle)
    }
}

impl Deref for RBusHandle {
    type Target = RBusHandleRef;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for RBusHandle {
    fn drop(&mut self) {
        unsafe { self.inner.library.as_raw().rbus_close(self.inner.handle) };
    }
}

pub struct RBusRowName<'a> {
    /// Instance number of the row
    pub instance: u32,
    /// Fully qualified row name
    pub name: &'a CStr,
    /// Alias of the row.
    pub alias: Option<&'a CStr>,
}

pub struct RBusRowNames<'a> {
    handle: &'a RBusHandleRef,
    root: *mut rbusRowName_t,
}

impl RBusRowNames<'_> {
    /// Iterate over borrowed rows.
    pub fn iter(&self) -> RBusRowNameIter<'_> {
        RBusRowNameIter {
            head: self.root,
            phantom_data: PhantomData,
        }
    }
}

impl Drop for RBusRowNames<'_> {
    fn drop(&mut self) {
        unsafe {
            let library = self.handle.library.as_raw();
            library.rbusTable_freeRowNames(self.handle.handle, self.root)
        };
    }
}

pub struct RBusRowNameIter<'a> {
    head: *mut rbusRowName_t,
    phantom_data: PhantomData<&'a rbusRowName_t>,
}

impl<'a> Iterator for RBusRowNameIter<'a> {
    type Item = RBusRowName<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.head.is_null() {
            return None;
        }

        // SAFETY: the collection keeps the list and strings valid for 'a.
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
