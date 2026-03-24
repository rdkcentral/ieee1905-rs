mod errors;
mod readable;
mod writable;

use crate::rbus_library::RBusLibrary;
use crate::rbus_utils::write_c_char_ptr_lossy_and_free;
use rbus_sys::*;
use std::cmp::Ordering;
use std::fmt::{Debug, Display, Formatter};
use std::os::raw::{c_char, c_uchar};

pub use errors::*;
pub use readable::*;
pub use writable::*;

///
/// A handle to an rbus value.
///
pub struct RBusValue {
    pub(super) handle: rbusValue_t,
    pub(crate) library: RBusLibrary,
}

impl RBusValue {
    ///
    /// Allocate and initialize a value to an empty state with its type set to RBUS_NONE
    /// and data set to NULL. This automatically retains ownership of the value.
    /// It's the caller's responsibility to release ownership by calling rbusValue_Release once it's done with it.
    ///
    pub fn new(library: &RBusLibrary) -> Self {
        let handle = unsafe { library.as_raw().rbusValue_Init(std::ptr::null_mut()) };
        Self {
            handle,
            library: library.clone(),
        }
    }

    ///
    /// Allocate and initialize a value to a state
    ///
    pub fn from<T>(library: &RBusLibrary, value: &T) -> Self
    where
        T: RBusValueWritable + ?Sized,
    {
        let this = Self::new(library);
        this.set(value);
        this
    }

    ///
    /// Take shared ownership of the value.
    /// This allows a value to have multiple owners.
    /// The first owner obtains ownership with rbusValue_Init.
    /// Additional owners can be assigned afterward with rbusValue_Retain.
    /// Each owner must call rbusValue_Release once done using the value.
    ///
    pub(crate) fn retain(library: &RBusLibrary, handle: rbusValue_t) -> Self {
        unsafe {
            library.as_raw().rbusValue_Retain(handle);
        }
        Self {
            handle,
            library: library.clone(),
        }
    }

    ///
    /// Get the type of the value
    ///
    pub fn kind(&self) -> rbusValueType_t {
        let library = self.library.as_raw();
        unsafe { library.rbusValue_GetType(self.handle) }
    }

    ///
    /// Copy data from source to dest
    ///
    pub fn copy_from(&self, source: &Self) {
        let library = self.library.as_raw();
        unsafe {
            library.rbusValue_Copy(self.handle, source.handle);
        }
    }

    ///
    /// Copy data from source to dest
    ///
    pub fn swap(&mut self, other: &mut Self) {
        let library = self.library.as_raw();
        unsafe {
            library.rbusValue_Swap(&mut self.handle, &mut other.handle);
        }
    }

    ///
    /// Get primitive value
    ///
    pub fn get<T>(&self) -> Result<T, RBusValueGetError>
    where
        T: RBusValueReadable,
    {
        let mut value = T::default();
        self.get_into(&mut value)?;
        Ok(value)
    }

    ///
    /// Get primitive value
    ///
    pub fn get_into<T>(&self, target: &mut T) -> Result<(), RBusValueGetError>
    where
        T: RBusValueReadable,
    {
        let result = T::get(target, self);
        RBusValueGetError::map(result, ())
    }

    ///
    /// Get char value
    ///
    pub fn get_char(&self) -> Result<c_char, RBusValueGetError> {
        let mut value = 0;
        let library = self.library.as_raw();
        let result = unsafe { library.rbusValue_GetCharEx(self.handle, &mut value) };
        RBusValueGetError::map(result, value)
    }

    ///
    /// Get byte value
    ///
    pub fn get_byte(&self) -> Result<c_uchar, RBusValueGetError> {
        let mut value = 0;
        let library = self.library.as_raw();
        let result = unsafe { library.rbusValue_GetByteEx(self.handle, &mut value) };
        RBusValueGetError::map(result, value)
    }

    ///
    /// Set primitive value
    ///
    pub fn set<T>(&self, value: &T)
    where
        T: RBusValueWritable + ?Sized,
    {
        T::set(value, self);
    }

    ///
    /// Set char value
    ///
    pub fn set_char(&self, value: c_char) {
        let library = self.library.as_raw();
        unsafe { library.rbusValue_SetChar(self.handle, value) };
    }

    ///
    /// Set byte value
    ///
    pub fn set_byte(&self, value: c_uchar) {
        let library = self.library.as_raw();
        unsafe { library.rbusValue_SetByte(self.handle, value) };
    }
}

impl Drop for RBusValue {
    fn drop(&mut self) {
        let library = self.library.as_raw();
        unsafe {
            library.rbusValue_Release(self.handle);
        }
    }
}

impl Clone for RBusValue {
    fn clone(&self) -> Self {
        let library = self.library.as_raw();
        unsafe {
            library.rbusValue_Retain(self.handle);
        }
        Self {
            handle: self.handle,
            library: self.library.clone(),
        }
    }
}

impl Eq for RBusValue {}

impl PartialEq for RBusValue {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Ord for RBusValue {
    fn cmp(&self, other: &Self) -> Ordering {
        let library = self.library.as_raw();
        let result = unsafe { library.rbusValue_Compare(self.handle, other.handle) };
        if result < 0 {
            return Ordering::Less;
        }
        if result > 0 {
            return Ordering::Greater;
        }
        Ordering::Equal
    }
}

impl PartialOrd for RBusValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for RBusValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let library = self.library.as_raw();
            let ptr = library.rbusValue_ToString(self.handle, std::ptr::null_mut(), 0);
            write_c_char_ptr_lossy_and_free(f, ptr)?;
        }
        Ok(())
    }
}

impl Debug for RBusValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let library = self.library.as_raw();
            let ptr = library.rbusValue_ToDebugString(self.handle, std::ptr::null_mut(), 0);
            write_c_char_ptr_lossy_and_free(f, ptr)?;
        }
        Ok(())
    }
}
