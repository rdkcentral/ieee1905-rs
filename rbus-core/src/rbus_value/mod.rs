mod errors;
mod readable;
mod writable;

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
#[repr(transparent)]
pub struct RBusValue(pub(super) rbusValue_t);

impl RBusValue {
    ///
    /// Allocate and initialize a value to an empty state with its type set to RBUS_NONE
    /// and data set to NULL. This automatically retains ownership of the value.
    /// It's the caller's responsibility to release ownership by calling rbusValue_Release once it's done with it.
    ///
    pub fn new() -> Self {
        unsafe {
            let handle = rbusValue_Init(std::ptr::null_mut());
            Self(handle)
        }
    }

    ///
    /// Take shared ownership of the value.
    /// This allows a value to have multiple owners.
    /// The first owner obtains ownership with rbusValue_Init.
    /// Additional owners can be assigned afterward with rbusValue_Retain.
    /// Each owner must call rbusValue_Release once done using the value.
    ///
    pub(crate) fn retain(handle: rbusValue_t) -> Self {
        unsafe {
            rbusValue_Retain(handle);
        }
        Self(handle)
    }

    ///
    /// Get the type of the value
    ///
    pub fn kind(&self) -> rbusValueType_t {
        unsafe { rbusValue_GetType(self.0) }
    }

    ///
    /// Copy data from source to dest
    ///
    pub fn copy_from(&self, source: &Self) {
        unsafe {
            rbusValue_Copy(self.0, source.0);
        }
    }

    ///
    /// Copy data from source to dest
    ///
    pub fn swap(&mut self, other: &mut Self) {
        unsafe {
            rbusValue_Swap(&mut self.0, &mut other.0);
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
        let result = unsafe { rbusValue_GetCharEx(self.0, &mut value) };
        RBusValueGetError::map(result, value)
    }

    ///
    /// Get byte value
    ///
    pub fn get_byte(&self) -> Result<c_uchar, RBusValueGetError> {
        let mut value = 0;
        let result = unsafe { rbusValue_GetByteEx(self.0, &mut value) };
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
        unsafe { rbusValue_SetChar(self.0, value) };
    }

    ///
    /// Set byte value
    ///
    pub fn set_byte(&self, value: c_uchar) {
        unsafe { rbusValue_SetByte(self.0, value) };
    }
}

impl Drop for RBusValue {
    fn drop(&mut self) {
        unsafe {
            rbusValue_Release(self.0);
        }
    }
}

impl Clone for RBusValue {
    fn clone(&self) -> Self {
        unsafe {
            rbusValue_Retain(self.0);
        }
        Self(self.0)
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
        let result = unsafe { rbusValue_Compare(self.0, other.0) };
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
            let ptr = rbusValue_ToString(self.0, std::ptr::null_mut(), 0);
            write_c_char_ptr_lossy_and_free(f, ptr)?;
        }
        Ok(())
    }
}

impl Debug for RBusValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        unsafe {
            let ptr = rbusValue_ToDebugString(self.0, std::ptr::null_mut(), 0);
            write_c_char_ptr_lossy_and_free(f, ptr)?;
        }
        Ok(())
    }
}

impl<T: RBusValueWritable + ?Sized> From<&T> for RBusValue {
    fn from(value: &T) -> Self {
        let this = Self::new();
        this.set(value);
        this
    }
}
