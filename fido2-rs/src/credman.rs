use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::ops::Index;
use std::ptr::NonNull;

use foreign_types::{ForeignType, ForeignTypeRef};
use zeroize::Zeroizing;

use crate::credentials::{Credential, CredentialRef};
use crate::device::Device;
use crate::error::Result;
use crate::utils::{allocation_error, check};

/// FIDO2 credential management.
pub struct CredentialManagement<'a> {
    pub(crate) ptr: NonNull<ffi::fido_credman_metadata_t>,

    dev: &'a Device,

    pin: Option<Zeroizing<CString>>,
}

impl<'a> CredentialManagement<'a> {
    pub(crate) fn new(
        ptr: NonNull<ffi::fido_credman_metadata_t>,
        device: &'a Device,
        pin: Option<Zeroizing<CString>>,
    ) -> CredentialManagement<'a> {
        CredentialManagement {
            ptr,
            dev: device,
            pin,
        }
    }

    /// Returns the number of resident credentials on the authenticator.
    pub fn count(&self) -> usize {
        unsafe { ffi::fido_credman_rk_existing(self.ptr.as_ptr()) as usize }
    }

    /// Returns the estimated number of resident credentials that can be created on the authenticator.
    pub fn remaining(&self) -> usize {
        unsafe { ffi::fido_credman_rk_remaining(self.ptr.as_ptr()) as usize }
    }

    /// Get information about relying parties with resident credentials in dev.
    pub fn get_rp(&self) -> Result<CredManRP> {
        let pin_ptr = match &self.pin {
            Some(p) => p.as_ptr(),
            None => std::ptr::null(),
        };

        unsafe {
            let p = ffi::fido_credman_rp_new();
            let p = NonNull::new(p).ok_or_else(allocation_error)?;

            if let Err(err) = check(ffi::fido_credman_get_dev_rp(
                self.dev.ptr.as_ptr(),
                p.as_ptr(),
                pin_ptr,
            )) {
                let mut raw = p.as_ptr();
                ffi::fido_credman_rp_free(&mut raw);
                return Err(err.into());
            }

            Ok(CredManRP {
                ptr: p,
                _phantom: Default::default(),
            })
        }
    }

    /// Get resident credentials belonging to rp (relying parties) in dev.
    pub fn get_rk<'i, I: Into<Cow<'i, CStr>>>(&self, rp: I) -> Result<CredManRK> {
        let rp = rp.into();
        let pin_ptr = match &self.pin {
            Some(p) => p.as_ptr(),
            None => std::ptr::null(),
        };

        unsafe {
            let rk = ffi::fido_credman_rk_new();
            let rk = NonNull::new(rk).ok_or_else(allocation_error)?;

            if let Err(err) = check(ffi::fido_credman_get_dev_rk(
                self.dev.ptr.as_ptr(),
                rp.as_ptr(),
                rk.as_ptr(),
                pin_ptr,
            )) {
                let mut raw = rk.as_ptr();
                ffi::fido_credman_rk_free(&mut raw);
                return Err(err.into());
            }

            Ok(CredManRK {
                ptr: rk,
                _phantom: PhantomData,
            })
        }
    }

    /// Deletes the resident credential identified by cred_id from dev.
    ///
    /// A valid pin must be provided.
    ///
    /// # Arguments
    /// * `cred_id` - credential id
    pub fn delete_rk(&self, cred_id: &[u8]) -> Result<()> {
        let pin_ptr = match &self.pin {
            Some(p) => p.as_ptr(),
            None => std::ptr::null(),
        };

        unsafe {
            check(ffi::fido_credman_del_dev_rk(
                self.dev.ptr.as_ptr(),
                cred_id.as_ptr(),
                cred_id.len(),
                pin_ptr,
            ))?;

            Ok(())
        }
    }

    /// Updates the credential pointed to by cred in dev.
    ///
    /// The credential id and user id attributes of cred must be set.
    ///
    /// See [Credential::set_id] and [Credential::set_user] for details.
    ///
    /// Only a credential's user attributes (name, display name) may be updated at this time.
    pub fn set_rk(&self, cred: &Credential) -> Result<()> {
        let pin_ptr = match &self.pin {
            Some(p) => p.as_ptr(),
            None => std::ptr::null(),
        };

        unsafe {
            check(ffi::fido_credman_set_dev_rk(
                self.dev.ptr.as_ptr(),
                cred.as_ptr(),
                pin_ptr,
            ))?;

            Ok(())
        }
    }
}

impl<'a> Drop for CredentialManagement<'a> {
    fn drop(&mut self) {
        unsafe {
            let mut ptr = self.ptr.as_ptr();
            ffi::fido_credman_metadata_free(&mut ptr);
        }
    }
}

/// Abstracts the set of resident credentials belonging to a given relying party.
pub struct CredManRK {
    ptr: NonNull<ffi::fido_credman_rk_t>,
    _phantom: PhantomData<ffi::fido_credman_rk_t>,
}

impl CredManRK {
    /// Returns the number of resident credentials in rk
    pub fn count(&self) -> usize {
        unsafe { ffi::fido_credman_rk_count(self.ptr.as_ptr()) }
    }

    /// Return an iterator over the resident credentials
    pub fn iter(&self) -> IterRK<'_> {
        let total = self.count();

        IterRK {
            idx: 0,
            total,
            rk: self.ptr,
            _phantom: Default::default(),
        }
    }
}

impl Drop for CredManRK {
    fn drop(&mut self) {
        unsafe {
            let mut ptr = self.ptr.as_ptr();
            ffi::fido_credman_rk_free(&mut ptr);
        }
    }
}

impl Index<usize> for CredManRK {
    type Output = CredentialRef;

    fn index(&self, index: usize) -> &Self::Output {
        assert!(index < self.count(), "credential index out of bounds");

        unsafe {
            let ptr = ffi::fido_credman_rk(self.ptr.as_ptr(), index);
            assert!(!ptr.is_null(), "libfido2 returned NULL for credential");

            // todo: how to prevent mut
            CredentialRef::from_ptr(ptr as *mut ffi::fido_cred_t)
        }
    }
}

/// Iterator over resident credentials.
pub struct IterRK<'a> {
    idx: usize,
    total: usize,
    rk: NonNull<ffi::fido_credman_rk_t>,
    _phantom: PhantomData<&'a CredManRK>,
}

impl<'a> Iterator for IterRK<'a> {
    type Item = &'a CredentialRef;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.total {
            return None;
        }

        let ptr = unsafe { ffi::fido_credman_rk(self.rk.as_ptr(), self.idx) };
        assert!(!ptr.is_null(), "libfido2 returned NULL for credential");

        self.idx += 1;

        let credential_ref = unsafe { CredentialRef::from_ptr(ptr as *mut ffi::fido_cred_t) };
        Some(credential_ref)
    }
}

impl ExactSizeIterator for IterRK<'_> {
    fn len(&self) -> usize {
        self.total - self.idx
    }
}

/// Information about a relying party.
#[derive(Copy, Clone, Debug)]
pub struct RelyingParty<'a> {
    pub id: &'a CStr,
    pub name: Option<&'a CStr>,
}

/// Abstracts information about a relying party.
pub struct CredManRP {
    ptr: NonNull<ffi::fido_credman_rp_t>,
    _phantom: PhantomData<ffi::fido_credman_rp_t>,
}

impl CredManRP {
    /// Returns the number of relying parties in rp
    pub fn count(&self) -> usize {
        unsafe { ffi::fido_credman_rp_count(self.ptr.as_ptr()) }
    }

    /// Return an iterator over the relying parties
    pub fn iter(&self) -> IterRP<'_> {
        let total = self.count();

        IterRP {
            idx: 0,
            total,
            rp: self.ptr,
            _phantom: Default::default(),
        }
    }
}

impl Drop for CredManRP {
    fn drop(&mut self) {
        unsafe {
            let mut ptr = self.ptr.as_ptr();
            ffi::fido_credman_rp_free(&mut ptr);
        }
    }
}

/// Iterator over relying parties.
pub struct IterRP<'a> {
    idx: usize,
    total: usize,
    rp: NonNull<ffi::fido_credman_rp_t>,
    _phantom: PhantomData<&'a CredManRP>,
}

impl<'a> Iterator for IterRP<'a> {
    type Item = RelyingParty<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.total {
            return None;
        }

        let id = unsafe {
            let id = ffi::fido_credman_rp_id(self.rp.as_ptr(), self.idx);
            assert!(!id.is_null(), "libfido2 returned NULL for relying party id");

            CStr::from_ptr(id)
        };

        let name = unsafe {
            let name = ffi::fido_credman_rp_name(self.rp.as_ptr(), self.idx);

            if !name.is_null() {
                Some(CStr::from_ptr(name))
            } else {
                None
            }
        };

        self.idx += 1;

        Some(RelyingParty { id, name })
    }
}

impl ExactSizeIterator for IterRP<'_> {
    fn len(&self) -> usize {
        self.total - self.idx
    }
}
