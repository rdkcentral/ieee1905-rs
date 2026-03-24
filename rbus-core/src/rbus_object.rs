use crate::RBusValue;
use crate::rbus_library::RBusLibrary;
use crate::rbus_property::RBusProperty;
use rbus_sys::*;
use std::ffi::CStr;

pub struct RBusObject {
    pub(super) handle: rbusObject_t,
    pub(crate) library: RBusLibrary,
}

impl RBusObject {
    ///
    /// Allocate, initialize, and take ownership of an object.
    ///
    pub fn new(library: &RBusLibrary, name: &CStr) -> Self {
        let mut handle = rbusObject_t::default();
        unsafe {
            library.as_raw().rbusObject_Init(&mut handle, name.as_ptr());
        }
        Self {
            handle,
            library: library.clone(),
        }
    }

    ///
    /// Get the name of the object.
    ///
    pub fn get_name(&self) -> &CStr {
        let library = self.library.as_raw();
        unsafe {
            let ptr = library.rbusObject_GetName(self.handle);
            if ptr.is_null() {
                return c"";
            }
            CStr::from_ptr(ptr)
        }
    }

    ///
    /// Set the name of the object.
    ///
    pub fn set_name(&self, name: &CStr) {
        let library = self.library.as_raw();
        unsafe {
            library.rbusObject_SetName(self.handle, name.as_ptr());
        }
    }

    ///
    /// Set the value of the object.
    ///
    pub fn set_value(&self, name: &CStr, value: &RBusValue) {
        let library = self.library.as_raw();
        unsafe {
            library.rbusObject_SetValue(self.handle, name.as_ptr(), value.handle);
        }
    }

    ///
    /// Get the property list of an object.
    ///
    pub fn get_properties(&self) -> RBusProperty {
        let library = self.library.as_raw();
        unsafe {
            let handle = library.rbusObject_GetProperties(self.handle);
            RBusProperty::retain(&self.library, handle)
        }
    }

    ///
    /// Set the property list of an object.
    ///
    pub fn set_properties(&self, value: &RBusProperty) {
        let library = self.library.as_raw();
        unsafe {
            library.rbusObject_SetProperties(self.handle, value.handle);
        }
    }

    ///
    /// Get a property by name from an object.
    ///
    pub fn get_property(&self, name: &CStr) -> Option<RBusProperty> {
        let library = self.library.as_raw();
        unsafe {
            let handle = library.rbusObject_GetProperty(self.handle, name.as_ptr());
            if handle.is_null() {
                return None;
            }
            Some(RBusProperty::retain(&self.library, handle))
        }
    }

    ///
    /// Set a property on an object.
    /// If a property with the same name already exists, its ownership released.
    ///
    /// The caller should set the name on this property before calling this method.
    ///
    pub fn set_property(&self, value: &RBusProperty) {
        let library = self.library.as_raw();
        unsafe {
            library.rbusObject_SetProperty(self.handle, value.handle);
        }
    }
}

impl Drop for RBusObject {
    fn drop(&mut self) {
        unsafe {
            self.library.as_raw().rbusObject_Release(self.handle);
        }
    }
}

impl Clone for RBusObject {
    fn clone(&self) -> Self {
        let library = self.library.as_raw();
        unsafe {
            library.rbusObject_Retain(self.handle);
        }
        Self {
            handle: self.handle,
            library: self.library.clone(),
        }
    }
}
