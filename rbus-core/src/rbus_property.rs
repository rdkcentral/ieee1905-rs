use crate::rbus_library::RBusLibrary;
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
/// Callback-local instances drop their `RBusLibrary` field normally without
/// releasing the native property. This type cannot be cloned or copied out of
/// a borrow.
///
/// ```compile_fail,E0597
/// use rbus_core::{RBusLibrary, RBusProperty, RBusValue};
/// fn example(library: &RBusLibrary) {
///     let borrowed: &rbus_core::RBusPropertyRef = {
///         let value = RBusValue::from(library, &42_i32);
///         let owner = RBusProperty::new(library, c"borrowed-property", &value);
///         &owner
///     };
///     borrowed.get_name();
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
    pub(crate) library: RBusLibrary,
}

impl RBusProperty {
    ///
    /// Allocate and initialize a property.
    ///
    pub fn new(library: &RBusLibrary, name: &CStr, value: &RBusValue) -> Self {
        let library_raw = library.as_raw();
        let handle = unsafe {
            library_raw.rbusProperty_Init(std::ptr::null_mut(), name.as_ptr(), value.handle)
        };
        Self {
            inner: RBusPropertyRef {
                handle,
                library: library.clone(),
            },
        }
    }

    pub(crate) fn retain(library: &RBusLibrary, handle: rbusProperty_t) -> Self {
        unsafe {
            library.as_raw().rbusProperty_Retain(handle);
        }
        Self {
            inner: RBusPropertyRef {
                handle,
                library: library.clone(),
            },
        }
    }
}

impl RBusPropertyRef {
    ///
    /// Wrap a callback property without retaining its native ownership.
    ///
    /// # Safety
    /// The property must remain valid while this wrapper or any reference to it is used.
    ///
    pub(crate) unsafe fn from_raw(library: &RBusLibrary, handle: rbusProperty_t) -> Self {
        Self {
            handle,
            library: library.clone(),
        }
    }

    ///
    /// Get the name of a property.
    ///
    pub fn get_name(&self) -> CString {
        let library = self.library.as_raw();
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
        self.get_value().get()
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
    pub fn set_property(&self, value: &RBusPropertyRef) {
        let library = self.library.as_raw();
        unsafe {
            library.rbusProperty_SetProperty(self.handle, value.handle);
        }
    }

    ///
    /// Append a property to the end of a property list.
    ///
    pub fn append_property(&self, value: &RBusPropertyRef) {
        let library = self.library.as_raw();
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
        let library = self.inner.library.as_raw();
        unsafe {
            library.rbusProperty_Release(self.inner.handle);
        }
    }
}

impl Clone for RBusProperty {
    fn clone(&self) -> Self {
        let library = self.inner.library.as_raw();
        unsafe {
            library.rbusProperty_Retain(self.inner.handle);
        }
        Self {
            inner: RBusPropertyRef {
                handle: self.inner.handle,
                library: self.inner.library.clone(),
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
        let library = self.library.as_raw();
        let result = unsafe { library.rbusProperty_Compare(self.handle, other.handle) };
        result.cmp(&0)
    }
}

impl PartialOrd for RBusPropertyRef {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
