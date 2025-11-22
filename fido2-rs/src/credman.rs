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
use crate::utils::check;

/// FIDO2 credential management.
pub struct CredentialManagement<'a> {
    pub(crate) ptr: NonNull<ffi::fido_credman_metadata_t>,

    dev: &'a Device,

    pin: Zeroizing<CString>,
}

impl<'a> CredentialManagement<'a> {
    pub(crate) fn new(
        ptr: NonNull<ffi::fido_credman_metadata_t>,
        device: &'a Device,
        pin: Zeroizing<CString>,
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
    pub fn get_rp(&self) -> Result<IterRP<'a>> {
        let pin_ptr = self.pin.as_ptr();

        unsafe {
            let p = ffi::fido_credman_rp_new();

            check(ffi::fido_credman_get_dev_rp(
                self.dev.ptr.as_ptr(),
                p,
                pin_ptr,
            ))?;

            let total = ffi::fido_credman_rp_count(p);

            Ok(IterRP {
                idx: 0,
                total,
                rp: NonNull::new_unchecked(p),
                _phantom: Default::default(),
            })
        }
    }

    /// Get resident credentials belonging to rp (relying parties) in dev.
    pub fn get_rk<'i, I: Into<Cow<'i, CStr>>>(&self, rp: I) -> Result<CredManRK<'a>> {
        let rp = rp.into();
        let pin_ptr = self.pin.as_ptr();

        unsafe {
            let rk = ffi::fido_credman_rk_new();
            check(ffi::fido_credman_get_dev_rk(
                self.dev.ptr.as_ptr(),
                rp.as_ptr(),
                rk,
                pin_ptr,
            ))?;

            Ok(CredManRK {
                ptr: NonNull::new_unchecked(rk),
                _phantom: PhantomData::default(),
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
        let pin_ptr = self.pin.as_ptr();

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
        let pin_ptr = self.pin.as_ptr();

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
            ffi::fido_credman_metadata_free(&mut self.ptr.as_ptr());
        }
    }
}

/// Abstracts the set of resident credentials belonging to a given relying party.
pub struct CredManRK<'a> {
    ptr: NonNull<ffi::fido_credman_rk_t>,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> CredManRK<'a> {
    /// Returns the number of resident credentials in rk
    pub fn count(&self) -> usize {
        unsafe { ffi::fido_credman_rk_count(self.ptr.as_ptr()) }
    }

    /// Return an iterator over the resident credentials
    pub fn iter(&self) -> IterRK<'a> {
        let total = self.count();

        IterRK {
            idx: 0,
            total,
            rk: self.ptr,
            _phantom: Default::default(),
        }
    }
}

impl<'a> Index<usize> for CredManRK<'a> {
    type Output = CredentialRef;

    fn index(&self, index: usize) -> &'a Self::Output {
        unsafe {
            let ptr = ffi::fido_credman_rk(self.ptr.as_ptr(), index);

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
    _phantom: PhantomData<&'a ()>,
}

impl<'a> Iterator for IterRK<'a> {
    type Item = &'a CredentialRef;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.total {
            return None;
        }

        let ptr = unsafe { ffi::fido_credman_rk(self.rk.as_ptr(), self.idx) };

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
pub struct CredManRP<'a> {
    ptr: NonNull<ffi::fido_credman_rp_t>,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> CredManRP<'a> {
    /// Returns the number of relying parties in rp
    pub fn count(&self) -> usize {
        unsafe { ffi::fido_credman_rp_count(self.ptr.as_ptr()) }
    }

    /// Return an iterator over the relying parties
    pub fn iter(&self) -> IterRP<'a> {
        let total = self.count();

        IterRP {
            idx: 0,
            total,
            rp: self.ptr,
            _phantom: Default::default(),
        }
    }
}

/// Iterator over relying parties.
pub struct IterRP<'a> {
    idx: usize,
    total: usize,
    rp: NonNull<ffi::fido_credman_rp_t>,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> Iterator for IterRP<'a> {
    type Item = RelyingParty<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.total {
            return None;
        }

        let id = unsafe {
            let id = ffi::fido_credman_rp_id(self.rp.as_ptr(), self.idx);

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
