use crate::RBusValue;
use rbus_sys::*;
use std::os::raw::c_int;

pub trait RBusValueWritable {
    fn set(this: &Self, value: &RBusValue);
}

///
/// `str`
///
impl RBusValueWritable for str {
    fn set(this: &Self, value: &RBusValue) {
        let string = format!("{this}\0");
        unsafe { rbusValue_SetString(value.0, string.as_ptr().cast()) }
    }
}

///
/// `String`
///
impl RBusValueWritable for String {
    fn set(this: &Self, value: &RBusValue) {
        RBusValueWritable::set(this.as_str(), value);
    }
}

///
/// `[u8]`
///
impl RBusValueWritable for [u8] {
    fn set(this: &Self, value: &RBusValue) {
        unsafe { rbusValue_SetBytes(value.0, this.as_ptr(), this.len() as c_int) }
    }
}

///
/// `Vec<u8>`
///
impl RBusValueWritable for Vec<u8> {
    fn set(this: &Self, value: &RBusValue) {
        RBusValueWritable::set(this.as_slice(), value);
    }
}

///
/// Primitives
///
macro_rules! define {
    ($kind:ty, $set_func:ident) => {
        impl RBusValueWritable for $kind {
            fn set(this: &Self, value: &RBusValue) {
                unsafe { $set_func(value.0, *this) };
            }
        }
    };
}

define!(bool, rbusValue_SetBoolean);
define!(i8, rbusValue_SetInt8);
define!(i16, rbusValue_SetInt16);
define!(i32, rbusValue_SetInt32);
define!(i64, rbusValue_SetInt64);
define!(u8, rbusValue_SetUInt8);
define!(u16, rbusValue_SetUInt16);
define!(u32, rbusValue_SetUInt32);
define!(u64, rbusValue_SetUInt64);
define!(f32, rbusValue_SetSingle);
define!(f64, rbusValue_SetDouble);
