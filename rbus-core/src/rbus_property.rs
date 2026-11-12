use crate::rbus_library::{RBusLibrary, RBusOpenError};
use crate::rbus_value::RBusValue;
use crate::{RBusObject, RBusValueGetError, RBusValueReadable, RBusValueWritable};
use rbus_sys::*;
use std::cmp::Ordering;
use std::ffi::{CStr, CString};
use std::ops::Deref;

/// An owning reference to a native property.
/// Dereferences to [`RBusPropertyRef`] for property operations.
/// Cloning retains native ownership; dropping releases it.
#[derive(Eq, PartialEq, Ord, PartialOrd)]
pub struct RBusProperty {
    inner: RBusPropertyRef,
}

///
/// Operations on a property, borrowed as `&RBusPropertyRef`.
/// [`crate::RBusProperty`] retains and releases ownership of the native property.
/// This type does not release the native property and cannot be cloned or
/// copied out of a borrow.
///
/// ```compile_fail,E0597
/// use rbus_core::{RBusProperty, RBusValue};
/// fn example() -> Result<(), Box<dyn std::error::Error>> {
///     let borrowed: &rbus_core::RBusPropertyRef = {
///         let value = RBusValue::from(&42_i32)?;
///         let owner = RBusProperty::new(c"borrowed-property", &value)?;
///         &owner
///     };
///     borrowed.get_name();
///     Ok(())
/// }
/// ```
///
/// ```compile_fail,E0507
/// use rbus_core::RBusPropertyRef;
/// fn take_property(property: &RBusPropertyRef) -> RBusPropertyRef {
///     *property
/// }
/// ```
pub struct RBusPropertyRef {
    pub(crate) handle: rbusProperty_t,
}

impl RBusProperty {
    ///
    /// Allocate and initialize a property.
    /// Loads the shared library if needed and returns an error if it is unavailable.
    ///
    pub fn new(name: &CStr, value: &RBusValue) -> Result<Self, RBusOpenError> {
        RBusLibrary::load()?;
        let library_raw = RBusLibrary::get();
        let handle = unsafe {
            library_raw.rbusProperty_Init(std::ptr::null_mut(), name.as_ptr(), value.handle)
        };
        Ok(Self {
            inner: RBusPropertyRef { handle },
        })
    }

    pub(crate) fn retain(handle: rbusProperty_t) -> Self {
        unsafe {
            RBusLibrary::get().rbusProperty_Retain(handle);
        }
        Self {
            inner: RBusPropertyRef { handle },
        }
    }
}

impl RBusPropertyRef {
    ///
    /// Get the name of a property.
    ///
    pub fn get_name(&self) -> CString {
        let library = RBusLibrary::get();
        unsafe {
            let ptr = library.rbusProperty_GetName(self.handle);
            if ptr.is_null() {
                return CString::default();
            }
            CStr::from_ptr(ptr).to_owned()
        }
    }

    ///
    /// Set the name of a property.
    ///
    pub fn set_name(&self, name: &CStr) {
        let library = RBusLibrary::get();
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
        self.get_value().get()
    }

    ///
    /// Get the value of a property.
    ///
    pub fn get_value(&self) -> RBusValue {
        let library = RBusLibrary::get();
        unsafe {
            let handle = library.rbusProperty_GetValue(self.handle);
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
        self.set_value(&RBusValue::from_initialized(value));
    }

    ///
    /// Set the value of a property.
    ///
    pub fn set_value(&self, value: &RBusValue) {
        let library = RBusLibrary::get();
        unsafe {
            library.rbusProperty_SetValue(self.handle, value.handle);
        }
    }

    ///
    /// Set the object of a property.
    ///
    pub fn set_object(&self, value: &RBusObject) {
        let library = RBusLibrary::get();
        unsafe {
            library.rbusProperty_SetObject(self.handle, value.handle);
        }
    }

    ///
    /// Set the property of a property.
    ///
    pub fn set_property(&self, value: &RBusPropertyRef) {
        let library = RBusLibrary::get();
        unsafe {
            library.rbusProperty_SetProperty(self.handle, value.handle);
        }
    }

    ///
    /// Append a property to the end of a property list.
    ///
    pub fn append_property(&self, value: &RBusPropertyRef) {
        let library = RBusLibrary::get();
        unsafe {
            library.rbusProperty_Append(self.handle, value.handle);
        }
    }
}

impl Deref for RBusProperty {
    type Target = RBusPropertyRef;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for RBusProperty {
    fn drop(&mut self) {
        let library = RBusLibrary::get();
        unsafe {
            library.rbusProperty_Release(self.inner.handle);
        }
    }
}

impl Clone for RBusProperty {
    fn clone(&self) -> Self {
        let library = RBusLibrary::get();
        unsafe {
            library.rbusProperty_Retain(self.inner.handle);
        }
        Self {
            inner: RBusPropertyRef {
                handle: self.inner.handle,
            },
        }
    }
}

impl Eq for RBusPropertyRef {}

impl PartialEq for RBusPropertyRef {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Ord for RBusPropertyRef {
    fn cmp(&self, other: &Self) -> Ordering {
        let library = RBusLibrary::get();
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

impl PartialOrd for RBusPropertyRef {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
