use bstr::BStr;
use std::ffi::CStr;
use std::fmt::Formatter;
use std::os::raw::c_char;

pub(super) fn write_c_char_ptr_lossy_and_free(
    f: &mut Formatter,
    ptr: *mut c_char,
) -> std::fmt::Result {
    if ptr.is_null() {
        return Ok(());
    }

    let ptr = scopeguard::guard(ptr, |e| unsafe { libc::free(e.cast()) });

    let c_str = unsafe { CStr::from_ptr(*ptr) };
    let b_str = BStr::new(c_str.to_bytes());
    write!(f, "{b_str}")
}
