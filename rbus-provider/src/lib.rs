use bstr::{BStr, BString, ByteVec};
use std::borrow::Cow;
use std::ffi::CString;

pub mod element;
pub mod provider;
pub mod registry;

///
/// Helper to join path chunks into c string
///
fn join_path(chunks: &[&BStr]) -> CString {
    let mut result = BString::default();
    for chunk in chunks {
        if chunk.is_empty() {
            continue;
        }
        if !result.is_empty() {
            result.push_str(".");
        }
        result.push_str(chunk);
    }
    result.push_str("\0");

    unsafe { CString::from_vec_with_nul_unchecked(result.into()) }
}

pub trait IntoCowBStr {
    fn into_cow_b_str(self) -> Cow<'static, BStr>;
}

impl IntoCowBStr for &'static str {
    fn into_cow_b_str(self) -> Cow<'static, BStr> {
        Cow::Borrowed(self.as_bytes().into())
    }
}

impl IntoCowBStr for String {
    fn into_cow_b_str(self) -> Cow<'static, BStr> {
        Cow::Owned(BString::from(self))
    }
}
