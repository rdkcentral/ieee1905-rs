use crate::RBusValue;
use rbus_sys::*;
use std::borrow::Cow;

pub trait RBusValueReadable: Default {
    fn get(this: &mut Self, value: &RBusValue) -> rbusValueError_t;
}

///
/// `String`
///
impl RBusValueReadable for String {
    fn get(this: &mut Self, value: &RBusValue) -> rbusValueError_t {
        let mut len = 0;
        let mut ptr = std::ptr::null();
        unsafe {
            let result = rbusValue_GetStringEx(value.0, &mut ptr, &mut len);
            if result != rbusValueError_t::RBUS_VALUE_ERROR_SUCCESS {
                return result;
            }

            if ptr.is_null() {
                return rbusValueError_t::RBUS_VALUE_ERROR_SUCCESS;
            }

            let slice = std::slice::from_raw_parts(ptr.cast(), len as usize);
            match String::from_utf8_lossy(slice) {
                Cow::Owned(e) => *this = e,
                Cow::Borrowed(e) => this.push_str(e),
            }
        }
        rbusValueError_t::RBUS_VALUE_ERROR_SUCCESS
    }
}

///
/// `Vec<u8>`
///
impl RBusValueReadable for Vec<u8> {
    fn get(this: &mut Self, value: &RBusValue) -> rbusValueError_t {
        let mut len = 0;
        let mut ptr = std::ptr::null();
        unsafe {
            let result = rbusValue_GetBytesEx(value.0, &mut ptr, &mut len);
            if result != rbusValueError_t::RBUS_VALUE_ERROR_SUCCESS {
                return result;
            }
            if !ptr.is_null() {
                this.extend(std::slice::from_raw_parts(ptr.cast(), len as usize));
            }
        }
        rbusValueError_t::RBUS_VALUE_ERROR_SUCCESS
    }
}

///
/// Primitives
///
macro_rules! define {
    ($kind:ty, $get_func:ident) => {
        impl RBusValueReadable for $kind {
            fn get(this: &mut Self, value: &RBusValue) -> rbusValueError_t {
                unsafe { $get_func(value.0, this) }
            }
        }
    };
}

define!(bool, rbusValue_GetBooleanEx);
define!(i8, rbusValue_GetInt8Ex);
define!(i16, rbusValue_GetInt16Ex);
define!(i32, rbusValue_GetInt32Ex);
define!(i64, rbusValue_GetInt64Ex);
define!(u8, rbusValue_GetUInt8Ex);
define!(u16, rbusValue_GetUInt16Ex);
define!(u32, rbusValue_GetUInt32Ex);
define!(u64, rbusValue_GetUInt64Ex);
define!(f32, rbusValue_GetSingleEx);
define!(f64, rbusValue_GetDoubleEx);
