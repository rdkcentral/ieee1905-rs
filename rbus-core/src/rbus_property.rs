use crate::rbus_library::RBusLibrary;
use crate::rbus_value::RBusValue;
use crate::{RBusError, RBusObject, RBusValueGetError, RBusValueReadable, RBusValueWritable};
use rbus_sys::*;
use std::cmp::Ordering;
use std::ffi::CStr;
use std::mem::ManuallyDrop;

pub struct RBusProperty {
    pub(super) handle: rbusProperty_t,
    pub(crate) library: RBusLibrary,
}

impl RBusProperty {
    ///
    /// Allocate and initialize a property.
    ///
    pub fn new(library: &RBusLibrary, name: &CStr, value: &RBusValue) -> Result<Self, RBusError> {
        let library_raw = library.as_raw();
        let handle = unsafe {
            library_raw.rbusProperty_Init(std::ptr::null_mut(), name.as_ptr(), value.handle)
        };
        Ok(Self {
            handle,
            library: library.clone(),
        })
    }

    pub(crate) fn retain(library: &RBusLibrary, handle: rbusProperty_t) -> Self {
        unsafe {
            library.as_raw().rbusProperty_Retain(handle);
        }
        Self {
            handle,
            library: library.clone(),
        }
    }

    ///
    /// Get the name of a property.
    ///
    pub fn get_name(&self) -> &CStr {
        let library = self.library.as_raw();
        unsafe {
            let ptr = library.rbusProperty_GetName(self.handle);
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
        let library = self.library.as_raw();
        unsafe {
            library.rbusProperty_SetName(self.handle, name.as_ptr());
        }
    }

    ///
    /// Get the value of a property.
    ///
    pub fn get<T>(&self) -> Result<T, RBusValueGetError>
    where
        T: RBusValueReadable,
    {
        let library = self.library.as_raw();
        let handle = unsafe { library.rbusProperty_GetValue(self.handle) };
        let handle = ManuallyDrop::new(RBusValue {
            handle,
            library: self.library.clone(),
        });
        handle.get()
    }

    ///
    /// Get the value of a property.
    ///
    pub fn get_value(&self) -> RBusValue {
        let library = self.library.as_raw();
        unsafe {
            let handle = library.rbusProperty_GetValue(self.handle);
            RBusValue::retain(&self.library, handle)
        }
    }

    ///
    /// Set the value of a property.
    ///
    pub fn set<T>(&self, value: &T)
    where
        T: RBusValueWritable + ?Sized,
    {
        self.set_value(&RBusValue::from(&self.library, value));
    }

    ///
    /// Set the value of a property.
    ///
    pub fn set_value(&self, value: &RBusValue) {
        let library = self.library.as_raw();
        unsafe {
            library.rbusProperty_SetValue(self.handle, value.handle);
        }
    }

    ///
    /// Set the object of a property.
    ///
    pub fn set_object(&self, value: &RBusObject) {
        let library = self.library.as_raw();
        unsafe {
            library.rbusProperty_SetObject(self.handle, value.handle);
        }
    }

    ///
    /// Set the property of a property.
    ///
    pub fn set_property(&self, value: &RBusProperty) {
        let library = self.library.as_raw();
        unsafe {
            library.rbusProperty_SetProperty(self.handle, value.handle);
        }
    }

    ///
    /// Append a property to the end of a property list.  
    ///
    pub fn append_property(&self, value: &RBusProperty) {
        let library = self.library.as_raw();
        unsafe {
            library.rbusProperty_Append(self.handle, value.handle);
        }
    }
}

impl Drop for RBusProperty {
    fn drop(&mut self) {
        let library = self.library.as_raw();
        unsafe {
            library.rbusProperty_Release(self.handle);
        }
    }
}

impl Clone for RBusProperty {
    fn clone(&self) -> Self {
        let library = self.library.as_raw();
        unsafe {
            library.rbusProperty_Retain(self.handle);
        }
        Self {
            handle: self.handle,
            library: self.library.clone(),
        }
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
        let library = self.library.as_raw();
        let result = unsafe { library.rbusProperty_Compare(self.handle, other.handle) };
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
