use crate::RBusHandle;
use crate::rbus_handle::RBusError;
use crate::rbus_property::RBusProperty;
use rbus_sys::*;
use std::ffi::CStr;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::os::raw::c_char;

///
/// The list of callback handlers supported by a data element.
/// This table also specifies the possible usage for each data element.
///
/// For properties, the callbacks can be set to control usage as follows:
///
/// |Callback|Property Usage|Table Usage
/// |-|-|-
/// |getHandler|allow read access and value-change events|unused
/// |setHandler|allow write access|unused
/// |updateTableHandler|unused|all table row add and remove
/// |eventSubHandler|allow a provider to know when value-change was subscribed to|allow a provider to know when a table update event is subscribed to
///
/// If a particular usage is supported, then that callback must be set to a
/// function pointer for the handler. If a particular usage is not supported by
/// the component, the callback shall be set "NULL". On call to register the
/// data element, the rbus-provider library checks for NULL and substitutes a pointer
/// to an error handler function for all unused features
///
#[repr(transparent)]
pub struct RBusDataElement<'a> {
    inner: rbusDataElement_t,
    phantom_data: PhantomData<&'a ()>,
}

///
/// A provider must implement this handler to allow a property to be read.
/// The property parameter passed to this function will have the name of the property
/// already set.
/// The provider can use this name to identify the property if needed.
/// The provider's responsibility is to set the value of the property parameter.
///
/// A provider may install this get handler on a table if the provider doesn't
/// use rbusTable_addRow to add rows and instead will handle partial path queries
/// through this get handler.
///
pub trait RBusDataElementGet {
    fn get(handle: &RBusHandle, property: &RBusProperty) -> Result<(), RBusError>;
}

///
/// A provider must implement this handler to allow a property to be written.
/// The property parameter passed to this function will have the name of the property
/// already set.
/// The provider can use this name to identify the property if needed.
/// The property parameter will also have the value. The rbusSetHandlerOptions_t contains
/// addition information which the provider must use to handle how write should
/// occur.
///
/// It is the provider's responsibility to set its internal representation
/// of that property's value with the value contained within the property parameter.
///
pub trait RBusDataElementSet {
    fn set(handle: &RBusHandle, property: &RBusProperty) -> Result<(), RBusError>;
}

///
/// A table sync callback handler
///
/// A provider can implement this handler to allow dynamic tables to synchronize rows.
/// The tableName parameter will be a fully qualified name, specifying table's name
/// (e.g. "Device.IP.Interface.").
///
/// # Arguments
/// * `table_name` - The name of a table (e.g. "Device.IP.Interface.")
///
pub trait RBusTableSyncHandler {
    fn sync_rows(handle: &RBusHandle, table_name: &CStr) -> Result<(), RBusError>;
}

///
/// A table row add callback handler
///
pub trait RBusDataElementAddRow {
    ///
    /// A provider must implement this handler to allow rows to be added to a table.
    /// The tableName parameter will end in "." such as "Device.IP.Interface."
    /// The aliasName parameter can optionally be used to specify a unique name for the row.
    ///
    /// A new row should be assigned a unique instance number and this number should be
    /// returned in the instNum output parameter.
    ///
    /// # Arguments
    /// * `handle`     - Bus Handle
    /// * `table_name` - The name of a table (e.g. "Device.IP.Interface.")
    /// * `alias_name` - An optional name for the new row. Must be unique in the table. Can be NULL.
    ///
    /// # Returns
    /// Instance number for the new row
    ///
    fn add_row(table_name: &CStr, alias_name: Option<&CStr>) -> Result<u32, RBusError>;
}

///
/// A table row remove callback handler
///
pub trait RBusDataElementRemoveRow {
    ///
    /// A table row remove callback handler
    ///
    /// A provider must implement this handler to allow rows to be removed from a table.
    /// The rowName parameter will be a fully qualified name, specifying either the row's instance
    /// number (e.g. "Device.IP.Interface.1") or the row's alias (e.g. "Device.IP.Interface.[lan1]").
    ///
    /// # Arguments
    /// * `row_name`    The name of a table row (e.g. "Device.IP.Interface.1")
    ///
    fn remove_row(row_name: &CStr) -> Result<(), RBusError>;
}

impl<'a> RBusDataElement<'a> {
    const fn new(name: &'a CStr, kind: rbusElementType_t) -> Self {
        let inner = rbusDataElement_t {
            name: name.as_ptr().cast_mut(),
            type_: kind,
            cbTable: rbusCallbackTable_t {
                getHandler: None,
                setHandler: None,
                tableAddRowHandler: None,
                tableRemoveRowHandler: None,
                eventSubHandler: None,
                methodHandler: std::ptr::null_mut(),
            },
        };

        Self {
            inner,
            phantom_data: PhantomData,
        }
    }

    ///
    /// Property Element
    ///
    /// Sample names: x.y, p.q.{i}.r, aaa, etc.
    /// Can also be monitored and event notifications be obtained in the form of events.
    ///
    pub const fn property(name: &'a CStr) -> Self {
        Self::new(name, rbusElementType_t::RBUS_ELEMENT_TYPE_PROPERTY)
    }

    ///
    /// Create a read-only property
    ///
    pub const fn property_ro<T>(name: &'a CStr) -> Self
    where
        T: RBusDataElementGet,
    {
        Self::property(name).with_getter::<T>()
    }

    ///
    /// Create a read-write property
    ///
    pub const fn property_rw<T>(name: &'a CStr) -> Self
    where
        T: RBusDataElementGet + RBusDataElementSet,
    {
        Self::property(name).with_getter::<T>().with_setter::<T>()
    }

    ///
    /// Property Table (e.g. multi-instance object)
    ///
    /// Sample names: a.b.{i}, a.b.{i}.x.y.{i}
    ///
    pub const fn table(name: &'a CStr) -> Self {
        Self::new(name, rbusElementType_t::RBUS_ELEMENT_TYPE_TABLE)
    }

    ///
    /// Register get handler for this parameter
    ///
    pub const fn with_getter<T>(mut self) -> Self
    where
        T: RBusDataElementGet,
    {
        unsafe extern "C" fn handler<T: RBusDataElementGet>(
            handle: rbusHandle_t,
            property: rbusProperty_t,
            _options: *mut rbusGetHandlerOptions_t,
        ) -> rbusError_t {
            if handle.is_null() || property.is_null() {
                return rbusError_t::RBUS_ERROR_INVALID_HANDLE;
            }

            let handle = ManuallyDrop::new(RBusHandle(handle));
            let property = ManuallyDrop::new(RBusProperty(property));
            match T::get(&handle, &property) {
                Ok(_) => rbusError_t::RBUS_ERROR_SUCCESS,
                Err(e) => e.to_raw(),
            }
        }
        self.inner.cbTable.getHandler = Some(handler::<T>);
        self
    }

    ///
    /// Register set handler for this parameter
    ///
    pub const fn with_setter<T>(mut self) -> Self
    where
        T: RBusDataElementSet,
    {
        unsafe extern "C" fn handler<T: RBusDataElementSet>(
            handle: rbusHandle_t,
            property: rbusProperty_t,
            _options: *mut rbusSetHandlerOptions_t,
        ) -> rbusError_t {
            if handle.is_null() || property.is_null() {
                return rbusError_t::RBUS_ERROR_INVALID_HANDLE;
            }

            let handle = ManuallyDrop::new(RBusHandle(handle));
            let property = ManuallyDrop::new(RBusProperty(property));
            match T::set(&handle, &property) {
                Ok(_) => rbusError_t::RBUS_ERROR_SUCCESS,
                Err(e) => e.to_raw(),
            }
        }
        self.inner.cbTable.setHandler = Some(handler::<T>);
        self
    }

    ///
    /// Register a table row add callback handler
    ///
    pub const fn with_add_row_handler<T>(mut self) -> Self
    where
        T: RBusDataElementAddRow,
    {
        unsafe extern "C" fn handler<T: RBusDataElementAddRow>(
            handle: rbusHandle_t,
            table_name: *const c_char,
            alias_name: *const c_char,
            inst_num: *mut u32,
        ) -> rbusError_t {
            if handle.is_null() {
                return rbusError_t::RBUS_ERROR_INVALID_HANDLE;
            }
            if table_name.is_null() || inst_num.is_null() {
                return rbusError_t::RBUS_ERROR_INVALID_INPUT;
            }

            let table_name = unsafe { CStr::from_ptr(table_name) };
            let alias_name = match alias_name.is_null() {
                true => None,
                false => Some(unsafe { CStr::from_ptr(alias_name) }),
            };

            match T::add_row(table_name, alias_name) {
                Ok(e) => {
                    unsafe {
                        std::ptr::write(inst_num, e);
                    }
                    rbusError_t::RBUS_ERROR_SUCCESS
                }
                Err(e) => e.to_raw(),
            }
        }
        self.inner.cbTable.tableAddRowHandler = Some(handler::<T>);
        self
    }

    ///
    /// Register a table row remove callback handler
    ///
    pub const fn with_remove_row_handler<T>(mut self) -> Self
    where
        T: RBusDataElementRemoveRow,
    {
        unsafe extern "C" fn handler<T: RBusDataElementRemoveRow>(
            handle: rbusHandle_t,
            row_name: *const c_char,
        ) -> rbusError_t {
            if handle.is_null() {
                return rbusError_t::RBUS_ERROR_INVALID_HANDLE;
            }
            if row_name.is_null() {
                return rbusError_t::RBUS_ERROR_INVALID_INPUT;
            }

            let row_name = unsafe { CStr::from_ptr(row_name) };
            match T::remove_row(row_name) {
                Ok(_) => rbusError_t::RBUS_ERROR_SUCCESS,
                Err(e) => e.to_raw(),
            }
        }
        self.inner.cbTable.tableRemoveRowHandler = Some(handler::<T>);
        self
    }
}
