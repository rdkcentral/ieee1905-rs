use crate::rbus_property::RBusProperty;
use rbus_sys::*;
use std::ffi::CStr;
use crate::RBusValue;

#[repr(transparent)]
pub struct RBusObject(pub(super) rbusObject_t);

impl RBusObject {
    ///
    /// Allocate, initialize, and take ownership of an object.
    ///
    pub fn new(name: &CStr) -> Self {
        let mut handle = rbusObject_t::default();
        unsafe {
            rbusObject_Init(&mut handle, name.as_ptr());
        }
        Self(handle)
    }

    ///
    /// Get the name of the object.
    ///
    pub fn get_name(&self) -> &CStr {
        unsafe {
            let ptr = rbusObject_GetName(self.0);
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
        unsafe {
            rbusObject_SetName(self.0, name.as_ptr());
        }
    }

    ///
    /// Set the value of the object.
    ///
    pub fn set_value(&self, name: &CStr, value: &RBusValue) {
        unsafe {
            rbusObject_SetValue(self.0, name.as_ptr(), value.0);
        }
    }

    ///
    /// Get the property list of an object.
    ///
    pub fn get_properties(&self) -> RBusProperty {
        unsafe {
            let handle = rbusObject_GetProperties(self.0);
            RBusProperty::retain(handle)
        }
    }

    ///
    /// Set the property list of an object.
    ///
    pub fn set_properties(&self, value: &RBusProperty) {
        unsafe {
            rbusObject_SetProperties(self.0, value.0);
        }
    }

    ///
    /// Get a property by name from an object.
    ///
    pub fn get_property(&self, name: &CStr) -> Option<RBusProperty> {
        unsafe {
            let handle = rbusObject_GetProperty(self.0, name.as_ptr());
            if handle.is_null() {
                return None;
            }
            Some(RBusProperty::retain(handle))
        }
    }

    ///
    /// Set a property on an object.
    /// If a property with the same name already exists, its ownership released.
    ///
    /// The caller should set the name on this property before calling this method.
    ///
    pub fn set_property(&self, value: &RBusProperty) {
        unsafe {
            rbusObject_SetProperty(self.0, value.0);
        }
    }
}

impl Drop for RBusObject {
    fn drop(&mut self) {
        unsafe {
            rbusObject_Release(self.0);
        }
    }
}

impl Clone for RBusObject {
    fn clone(&self) -> Self {
        unsafe {
            rbusObject_Retain(self.0);
        }
        Self(self.0)
    }
}
