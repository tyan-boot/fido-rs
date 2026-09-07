use crate::error::FidoError;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub(crate) const fn check(code: i32) -> Result<(), FidoError> {
    match code {
        0 => Ok(()),
        _ => Err(FidoError::new(code)),
    }
}

pub(crate) const fn allocation_error() -> FidoError {
    FidoError::new(ffi::FIDO_ERR_INTERNAL)
}

pub(crate) unsafe fn slice_or_empty<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        &[]
    } else {
        assert!(
            !ptr.is_null(),
            "libfido2 returned NULL for a non-empty slice"
        );
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
}

pub(crate) unsafe fn cstring_from_ptr_or_empty(ptr: *const c_char) -> CString {
    if ptr.is_null() {
        CString::new("").expect("empty strings cannot contain NUL bytes")
    } else {
        unsafe { CStr::from_ptr(ptr) }.to_owned()
    }
}

macro_rules! str_or_none {
    ($ptr:ident) => {
        if $ptr.is_null() {
            None
        } else {
            let $ptr = unsafe {
                std::ffi::CStr::from_ptr($ptr)
                    .to_str()
                    .expect("invalid utf8")
            };

            Some($ptr)
        }
    };
}
