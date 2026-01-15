use crate::rbus_value::RBusValue;
use crate::{RBusObject, RBusValueGetError, RBusValueReadable, RBusValueWritable};
use rbus_sys::*;
use std::cmp::Ordering;
use std::ffi::CStr;
use std::mem::ManuallyDrop;

#[repr(transparent)]
pub struct RBusProperty(pub(super) rbusProperty_t);

impl RBusProperty {
    ///
    /// Allocate and initialize a property.
    ///
    pub fn new(name: &CStr, value: &RBusValue) -> Self {
        let handle = unsafe { rbusProperty_Init(std::ptr::null_mut(), name.as_ptr(), value.0) };
        Self(handle)
    }

    pub(crate) fn retain(handle: rbusProperty_t) -> Self {
        unsafe {
            rbusProperty_Retain(handle);
        }
        Self(handle)
    }

    ///
    /// Get the name of a property.
    ///
    pub fn get_name(&self) -> &CStr {
        unsafe {
            let ptr = rbusProperty_GetName(self.0);
            if ptr.is_null() {
                return c"";
            }
            CStr::from_ptr(ptr)
        }
    }

    ///
    /// Set the name of a property.
    ///
    pub fn set_name(&self, name: &CStr) {
        unsafe {
            rbusProperty_SetName(self.0, name.as_ptr());
        }
    }

    ///
    /// Get the value of a property.
    ///
    pub fn get<T>(&self) -> Result<T, RBusValueGetError>
    where
        T: RBusValueReadable,
    {
        let handle = unsafe { rbusProperty_GetValue(self.0) };
        let handle = ManuallyDrop::new(RBusValue(handle));
        handle.get()
    }

    ///
    /// Get the value of a property.
    ///
    pub fn get_value(&self) -> RBusValue {
        unsafe {
            let handle = rbusProperty_GetValue(self.0);
            RBusValue::retain(handle)
        }
    }

    ///
    /// Set the value of a property.
    ///
    pub fn set<T>(&self, value: &T)
    where
        T: RBusValueWritable + ?Sized,
    {
        self.set_value(&RBusValue::from(value));
    }

    ///
    /// Set the value of a property.
    ///
    pub fn set_value(&self, value: &RBusValue) {
        unsafe {
            rbusProperty_SetValue(self.0, value.0);
        }
    }

    ///
    /// Set the object of a property.
    ///
    pub fn set_object(&self, value: &RBusObject) {
        unsafe {
            rbusProperty_SetObject(self.0, value.0);
        }
    }

    ///
    /// Set the property of a property.
    ///
    pub fn set_property(&self, value: &RBusProperty) {
        unsafe {
            rbusProperty_SetProperty(self.0, value.0);
        }
    }

    ///
    /// Append a property to the end of a property list.  
    ///
    pub fn append_property(&self, value: &RBusProperty) {
        unsafe {
            rbusProperty_Append(self.0, value.0);
        }
    }
}

impl Drop for RBusProperty {
    fn drop(&mut self) {
        unsafe {
            rbusProperty_Release(self.0);
        }
    }
}

impl Clone for RBusProperty {
    fn clone(&self) -> Self {
        unsafe {
            rbusProperty_Retain(self.0);
        }
        Self(self.0)
    }
}

impl Eq for RBusProperty {}

impl PartialEq for RBusProperty {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Ord for RBusProperty {
    fn cmp(&self, other: &Self) -> Ordering {
        let result = unsafe { rbusProperty_Compare(self.0, other.0) };
        if result < 0 {
            return Ordering::Less;
        }
        if result > 0 {
            return Ordering::Greater;
        }
        Ordering::Equal
    }
}

impl PartialOrd for RBusProperty {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
