use crate::rbus_library::RBusLibrary;
use crate::rbus_property::RBusProperty;
use crate::{RBusError, RBusProperties, RBusValue};
use rbus_sys::*;
use std::ffi::{CStr, CString};
use std::ops::Deref;

/// An owning reference to a native object.
/// Dereferences to [`RBusObjectRef`] for object operations.
pub struct RBusObject {
    inner: RBusObjectRef,
}

/// Operations on an object, borrowed as `&RBusObjectRef`.
/// This type does not release the native object and cannot be cloned or copied
/// out of a borrow.
///
/// ```compile_fail,E0597
/// use rbus_core::{RBusLibrary, RBusObject, RBusObjectRef};
/// fn example(library: &RBusLibrary) {
///     let borrowed: &RBusObjectRef = {
///         let owner = RBusObject::new(library, c"borrowed-object");
///         &owner
///     };
///     borrowed.get_name();
/// }
/// ```
///
/// ```compile_fail,E0507
/// use rbus_core::RBusObjectRef;
/// fn take_object(object: &RBusObjectRef) -> RBusObjectRef {
///     *object
/// }
/// ```
pub struct RBusObjectRef {
    pub(crate) handle: rbusObject_t,
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
            inner: RBusObjectRef {
                handle,
                library: library.clone(),
            },
        }
    }
}

impl RBusObjectRef {
    /// Wrap a borrowed object without retaining its native ownership.
    /// Returns `RBusError::InvalidHandle` if the pointer is null.
    /// Returns `RBusError::GeneralError` if the library cannot be loaded.
    ///
    /// # Safety
    /// A non-null native object must remain valid while this wrapper or any reference to it is used.
    pub(crate) unsafe fn try_from_raw(handle: rbusObject_t) -> Result<Self, RBusError> {
        if handle.is_null() {
            return Err(RBusError::InvalidHandle);
        }
        let library = RBusLibrary::load().map_err(|_| RBusError::GeneralError)?;
        Ok(Self { handle, library })
    }

    ///
    /// Get the name of the object.
    ///
    pub fn get_name(&self) -> CString {
        let library = self.library.as_raw();
        unsafe {
            let ptr = library.rbusObject_GetName(self.handle);
            if ptr.is_null() {
                return CString::default();
            }
            CStr::from_ptr(ptr).to_owned()
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
    /// Returns an empty collection if the object has no properties.
    /// The collection retains ownership of the list independently of the object.
    ///
    pub fn get_properties(&self) -> RBusProperties {
        let library = self.library.as_raw();
        unsafe {
            let handle = library.rbusObject_GetProperties(self.handle);
            RBusProperties::retain(&self.library, handle)
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

impl Deref for RBusObject {
    type Target = RBusObjectRef;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for RBusObject {
    fn drop(&mut self) {
        unsafe {
            self.library.as_raw().rbusObject_Release(self.inner.handle);
        }
    }
}

impl Clone for RBusObject {
    fn clone(&self) -> Self {
        let library = self.library.as_raw();
        unsafe {
            library.rbusObject_Retain(self.inner.handle);
        }
        Self {
            inner: RBusObjectRef {
                handle: self.inner.handle,
                library: self.inner.library.clone(),
            },
        }
    }
}
