use std::collections::HashMap;
use std::ffi::CStr;
use std::ptr::NonNull;

use crate::error::Result;
use crate::utils::{allocation_error, slice_or_empty};

pub struct CBORInfo {
    pub(crate) ptr: NonNull<ffi::fido_cbor_info_t>,
}

impl CBORInfo {
    pub(crate) fn new() -> Result<CBORInfo> {
        unsafe {
            let ptr = ffi::fido_cbor_info_new();
            let ptr = NonNull::new(ptr).ok_or_else(allocation_error)?;
            Ok(CBORInfo { ptr })
        }
    }

    pub fn aaguid(&self) -> &[u8] {
        unsafe {
            let len = ffi::fido_cbor_info_aaguid_len(self.ptr.as_ptr());
            let ptr = ffi::fido_cbor_info_aaguid_ptr(self.ptr.as_ptr());

            slice_or_empty(ptr, len)
        }
    }

    pub fn extensions(&self) -> Vec<&str> {
        unsafe {
            let len = ffi::fido_cbor_info_extensions_len(self.ptr.as_ptr());
            let ptr = ffi::fido_cbor_info_extensions_ptr(self.ptr.as_ptr());

            let exts = slice_or_empty(ptr, len);

            exts.iter()
                .map(|it| CStr::from_ptr(*it))
                .map(|it| it.to_str().expect("invalid utf8"))
                .collect()
        }
    }

    pub fn protocols(&self) -> &[u8] {
        unsafe {
            let len = ffi::fido_cbor_info_protocols_len(self.ptr.as_ptr());
            let ptr = ffi::fido_cbor_info_protocols_ptr(self.ptr.as_ptr());

            slice_or_empty(ptr, len)
        }
    }

    pub fn transports(&self) -> Vec<&str> {
        unsafe {
            let len = ffi::fido_cbor_info_transports_len(self.ptr.as_ptr());
            let ptr = ffi::fido_cbor_info_transports_ptr(self.ptr.as_ptr());

            let txs = slice_or_empty(ptr, len);

            txs.iter()
                .map(|it| CStr::from_ptr(*it))
                .map(|it| it.to_str().expect("invalid utf8"))
                .collect()
        }
    }

    pub fn versions(&self) -> Vec<&str> {
        unsafe {
            let len = ffi::fido_cbor_info_versions_len(self.ptr.as_ptr());
            let ptr = ffi::fido_cbor_info_versions_ptr(self.ptr.as_ptr());

            let versions = slice_or_empty(ptr, len);

            versions
                .iter()
                .map(|it| CStr::from_ptr(*it))
                .map(|it| it.to_str().expect("invalid utf8"))
                .collect()
        }
    }

    pub fn options(&self) -> HashMap<&str, bool> {
        unsafe {
            let len = ffi::fido_cbor_info_options_len(self.ptr.as_ptr());
            let names = ffi::fido_cbor_info_options_name_ptr(self.ptr.as_ptr());
            let values = ffi::fido_cbor_info_options_value_ptr(self.ptr.as_ptr());

            let names = slice_or_empty(names, len);
            let values = slice_or_empty(values, len);

            names
                .iter()
                .map(|it| CStr::from_ptr(*it))
                .map(|it| it.to_str().expect("invalid utf8"))
                .zip(values)
                .map(|(k, v)| (k, *v))
                .collect()
        }
    }

    pub fn algorithms(&self) -> Vec<(&str, i32)> {
        unsafe {
            let count = ffi::fido_cbor_info_algorithm_count(self.ptr.as_ptr());

            let mut rets = Vec::with_capacity(count);

            for idx in 0..count {
                let algo_type = ffi::fido_cbor_info_algorithm_type(self.ptr.as_ptr(), idx);
                let algo_cose = ffi::fido_cbor_info_algorithm_cose(self.ptr.as_ptr(), idx);

                let algo_type = CStr::from_ptr(algo_type).to_str().expect("invalid utf8");

                rets.push((algo_type, algo_cose))
            }

            rets
        }
    }

    pub fn certs(&self) -> HashMap<&str, u64> {
        unsafe {
            let len = ffi::fido_cbor_info_certs_len(self.ptr.as_ptr());

            let names = ffi::fido_cbor_info_certs_name_ptr(self.ptr.as_ptr());
            let values = ffi::fido_cbor_info_certs_value_ptr(self.ptr.as_ptr());

            let names = slice_or_empty(names, len);
            let values = slice_or_empty(values, len);

            names
                .iter()
                .map(|it| CStr::from_ptr(*it))
                .map(|it| it.to_str().expect("invalid utf8"))
                .zip(values)
                .map(|(k, v)| (k, *v))
                .collect()
        }
    }

    pub fn max_msg_size(&self) -> u64 {
        unsafe { ffi::fido_cbor_info_maxmsgsiz(self.ptr.as_ptr()) }
    }

    pub fn max_cred_blob_len(&self) -> u64 {
        unsafe { ffi::fido_cbor_info_maxcredbloblen(self.ptr.as_ptr()) }
    }

    pub fn max_cred_count_list(&self) -> u64 {
        unsafe { ffi::fido_cbor_info_maxcredcntlst(self.ptr.as_ptr()) }
    }

    pub fn max_cred_id_len(&self) -> u64 {
        unsafe { ffi::fido_cbor_info_maxcredidlen(self.ptr.as_ptr()) }
    }

    pub fn max_large_blob(&self) -> u64 {
        unsafe { ffi::fido_cbor_info_maxlargeblob(self.ptr.as_ptr()) }
    }

    pub fn max_rp_id_minpinlen(&self) -> u64 {
        unsafe { ffi::fido_cbor_info_maxrpid_minpinlen(self.ptr.as_ptr()) }
    }

    pub fn min_pin_len(&self) -> u64 {
        unsafe { ffi::fido_cbor_info_minpinlen(self.ptr.as_ptr()) }
    }

    pub fn fw_version(&self) -> u64 {
        unsafe { ffi::fido_cbor_info_fwversion(self.ptr.as_ptr()) }
    }

    pub fn uv_attempts(&self) -> u64 {
        unsafe { ffi::fido_cbor_info_uv_attempts(self.ptr.as_ptr()) }
    }

    pub fn uv_modality(&self) -> u64 {
        unsafe { ffi::fido_cbor_info_uv_modality(self.ptr.as_ptr()) }
    }

    pub fn rk_remaining(&self) -> i64 {
        unsafe { ffi::fido_cbor_info_rk_remaining(self.ptr.as_ptr()) }
    }

    pub fn new_pin_required(&self) -> bool {
        unsafe { ffi::fido_cbor_info_new_pin_required(self.ptr.as_ptr()) }
    }
}

impl Drop for CBORInfo {
    fn drop(&mut self) {
        unsafe {
            let mut ptr = self.ptr.as_ptr();
            ffi::fido_cbor_info_free(&mut ptr);

            let _ = std::mem::replace(&mut self.ptr, NonNull::dangling());
        }
    }
}
