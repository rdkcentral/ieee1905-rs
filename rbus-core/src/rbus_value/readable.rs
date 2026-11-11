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
            let library = value.library.as_raw();
            let result = library.rbusValue_GetStringEx(value.handle, &mut ptr, &mut len);
            if result != rbusValueError_t::RBUS_VALUE_ERROR_SUCCESS {
                return result;
            }

            this.clear();

            if !ptr.is_null() {
                let slice = std::slice::from_raw_parts(ptr.cast(), len as usize);
                match String::from_utf8_lossy(slice) {
                    Cow::Owned(e) => *this = e,
                    Cow::Borrowed(e) => this.push_str(e),
                }
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
            let library = value.library.as_raw();
            let result = library.rbusValue_GetBytesEx(value.handle, &mut ptr, &mut len);
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
                let library = value.library.as_raw();
                unsafe { library.$get_func(value.handle, this) }
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

#[cfg(test)]
mod tests {
    use crate::{RBusLibrary, RBusOpenError, RBusValue, RBusValueGetError};

    // Requires librbus, but no running broker.
    fn load_library() -> anyhow::Result<Option<RBusLibrary>> {
        match RBusLibrary::load() {
            Ok(library) => Ok(Some(library)),
            Err(RBusOpenError::NotAvailable) => {
                eprintln!("library is not available, test ignored");
                Ok(None)
            }
            Err(error) => Err(error.into()),
        }
    }

    #[test]
    fn string_reads_replace_destination() -> anyhow::Result<()> {
        let Some(library) = load_library()? else {
            return Ok(());
        };

        let null_string = RBusValue::new(&library);
        // Native RBus allows a string value with a null buffer.
        unsafe {
            library
                .as_raw()
                .rbusValue_SetString(null_string.handle, std::ptr::null());
        }
        for (value, expected) in [
            (RBusValue::from(&library, "new"), "new"),
            (RBusValue::from(&library, "été"), "été"),
            (RBusValue::from(&library, ""), ""),
            (RBusValue::from(&library, b"\xff".as_slice()), "�"),
            (null_string, ""),
        ] {
            let mut target = String::from("old");
            for _ in 0..2 {
                value.get_into(&mut target)?;
                assert_eq!(target, expected);
            }
        }
        Ok(())
    }

    #[test]
    fn string_read_error_preserves_destination() -> anyhow::Result<()> {
        let Some(library) = load_library()? else {
            return Ok(());
        };

        let value = RBusValue::from(&library, &42_i32);
        let mut target = String::from("old");
        assert_eq!(value.get_into(&mut target), Err(RBusValueGetError::BadType));
        assert_eq!(target, "old");
        Ok(())
    }
}
