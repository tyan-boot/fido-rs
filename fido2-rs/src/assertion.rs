use crate::credentials::{CoseType, Opt};
use crate::error::{FidoError, Result};
use crate::key::{Eddsa, Rsa, ES256, ES384};
use crate::utils::check;
use ffi::FIDO_ERR_INVALID_ARGUMENT;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Public};
use std::ffi::CString;
use std::marker::PhantomData;
use std::ptr::NonNull;

macro_rules! impl_assertion_set {
    ($ty:ty, $($f:tt).*) => {
        impl $ty {
            /// Set the client data hash of assert by specifying the assertion's unhashed client data.
            ///
            /// This is required by Windows Hello, which calculates the client data hash internally.
            ///
            /// For compatibility with Windows Hello, applications should use [AssertRequestBuilder::client_data]
            /// instead of [AssertRequestBuilder::client_data_hash].
            pub fn set_client_data(&mut self, data: impl AsRef<[u8]>) -> Result<()> {
                let data = data.as_ref();
                unsafe {
                    check(ffi::fido_assert_set_clientdata(
                        self.$($f).*.as_ptr(),
                        data.as_ptr(),
                        data.len(),
                    ))?;
                }

                Ok(())
            }

            /// See [AssertRequestBuilder::client_data]
            pub fn set_client_data_hash(&mut self, data: impl AsRef<[u8]>) -> Result<()> {
                let data = data.as_ref();
                unsafe {
                    check(ffi::fido_assert_set_clientdata_hash(
                        self.$($f).*.as_ptr(),
                        data.as_ptr(),
                        data.len(),
                    ))?;
                }

                Ok(())
            }

            /// Set the relying party id of assert.
            pub fn set_rp(&mut self, id: impl AsRef<str>) -> Result<()> {
                let id = CString::new(id.as_ref())?;

                unsafe {
                    check(ffi::fido_assert_set_rp(self.$($f).*.as_ptr(), id.as_ptr()))?;
                }

                Ok(())
            }

            /// Set the up (user presence) attribute of assert.
            ///
            /// **Default to [Opt::Omit]**
            pub fn set_up(&mut self, up: Opt) -> Result<()> {
                unsafe {
                    check(ffi::fido_assert_set_up(self.$($f).*.as_ptr(), up as _))?;
                }

                Ok(())
            }

            /// Set the uv (user verification) attribute of assert.
            ///
            /// **Default to [Opt::Omit]**
            pub fn set_uv(&mut self, uv: Opt) -> Result<()> {
                unsafe {
                    check(ffi::fido_assert_set_uv(self.$($f).*.as_ptr(), uv as _))?;
                }

                Ok(())
            }

            /// Set the extensions of assert to the bitmask flags.
            ///
            /// At the moment, only the FIDO_EXT_CRED_BLOB, FIDO_EXT_HMAC_SECRET, and FIDO_EXT_LARGEBLOB_KEY extensions are supported.
            pub fn set_extensions(&mut self, flags: crate::credentials::Extensions) -> Result<()> {
                unsafe {
                    check(ffi::fido_assert_set_extensions(
                        self.$($f).*.as_ptr(),
                        flags.bits(),
                    ))?;
                }

                Ok(())
            }

            /// Allow a credential in a FIDO2 assertion.
            ///
            /// Add id to the list of credentials allowed in assert.
            ///
            /// If fails, the existing list of allowed credentials is preserved.
            pub fn set_allow_credential(&mut self, id: impl AsRef<[u8]>) -> Result<()> {
                let id = id.as_ref();

                unsafe {
                    check(ffi::fido_assert_allow_cred(
                        self.$($f).*.as_ptr(),
                        id.as_ptr(),
                        id.len(),
                    ))?;
                }

                Ok(())
            }
        }
    };
}

/// FIDO assertions from device, contains one or more assertion.
pub struct Assertions {
    pub(crate) ptr: NonNull<ffi::fido_assert_t>,
}

/// A single FIDO assertion.
pub struct Assertion<'a> {
    ptr: NonNull<ffi::fido_assert_t>,
    idx: usize,
    _p: PhantomData<&'a ()>,
}

/// Request to get a assertion.
pub struct AssertRequest(pub(crate) Assertions);

impl_assertion_set!(AssertRequest, 0.ptr);

impl AssertRequest {
    /// Return a [AssertRequest]
    #[allow(clippy::new_without_default)]
    pub fn new() -> AssertRequest {
        unsafe {
            let assert = ffi::fido_assert_new();

            AssertRequest(Assertions {
                ptr: NonNull::new_unchecked(assert),
            })
        }
    }

    pub fn set_hmac_salt(&mut self, salt: &[u8]) -> Result<()> {
        unsafe {
            check(ffi::fido_assert_set_hmac_salt(
                self.0.ptr.as_ptr(),
                salt.as_ptr(),
                salt.len(),
            ))?;
        }

        Ok(())
    }
}

/// helper for verify an exist single assertion
pub struct AssertVerifier(Assertions);

impl_assertion_set!(AssertVerifier, 0.ptr);

impl AssertVerifier {
    /// Return a [AssertVerifier] for verify.
    #[allow(clippy::new_without_default)]
    pub fn new() -> AssertVerifier {
        unsafe {
            let assert = ffi::fido_assert_new();
            ffi::fido_assert_set_count(assert, 1);

            AssertVerifier(Assertions {
                ptr: NonNull::new_unchecked(assert),
            })
        }
    }

    /// Set the authenticator data part of the statement.
    ///
    /// A copy of data is made, and no references to the passed data are kept.
    ///
    /// The authenticator data passed to [AssertVerifier::set_auth_data] must be a CBOR-encoded byte string,
    /// as obtained from [Assertion::auth_data].
    ///
    /// Alternatively, a raw binary blob may be passed to [AssertVerifier::set_auth_data_raw]
    pub fn set_auth_data(&mut self, data: impl AsRef<[u8]>) -> Result<()> {
        let data = data.as_ref();

        unsafe {
            check(ffi::fido_assert_set_authdata(
                self.0.ptr.as_ptr(),
                0,
                data.as_ptr(),
                data.len(),
            ))?;
        }

        Ok(())
    }

    /// Set the raw binary authenticator data part of the statement.
    pub fn set_auth_data_raw(&mut self, data: impl AsRef<[u8]>) -> Result<()> {
        let data = data.as_ref();

        unsafe {
            check(ffi::fido_assert_set_authdata_raw(
                self.0.ptr.as_ptr(),
                0,
                data.as_ptr(),
                data.len(),
            ))?;
        }

        Ok(())
    }

    /// Set the signature part of the statement.
    pub fn set_signature(&mut self, signature: impl AsRef<[u8]>) -> Result<()> {
        let signature = signature.as_ref();

        unsafe {
            check(ffi::fido_assert_set_sig(
                self.0.ptr.as_ptr(),
                0,
                signature.as_ptr(),
                signature.len(),
            ))?;
        }

        Ok(())
    }

    /// Verify whether the signature contained in statement of assert matches the parameters of the assertion.
    ///
    /// And verify whether the client data hash, relying party ID, user presence and user verification
    /// attributes of assert have been attested by the holder of the private counterpart of the public key.
    ///
    /// The `public_key` is a public key of type COSE_ES256, COSE_ES384, COSE_RS256, or COSE_EDDSA.
    ///
    /// # Return
    /// On verify success, this method return Ok(()), otherwise return Err.
    pub fn verify(&self, public_key: PKey<Public>) -> Result<()> {
        match public_key.id() {
            Id::ED25519 => {
                let pk = Eddsa::try_from(public_key)?;

                unsafe {
                    check(ffi::fido_assert_verify(
                        self.0.ptr.as_ptr(),
                        0,
                        CoseType::EDDSA as i32,
                        pk.as_ptr().cast(),
                    ))?;
                }
            }
            Id::RSA => {
                let pk = Rsa::try_from(public_key)?;

                unsafe {
                    check(ffi::fido_assert_verify(
                        self.0.ptr.as_ptr(),
                        0,
                        CoseType::EDDSA as i32,
                        pk.as_ptr().cast(),
                    ))?;
                }
            }
            Id::EC => {
                let ec_key = public_key.ec_key()?;
                let group = ec_key.group();
                let curve = group
                    .curve_name()
                    .ok_or(FidoError::new(FIDO_ERR_INVALID_ARGUMENT))?;
                match curve {
                    Nid::X9_62_PRIME256V1 => {
                        let pk = ES256::try_from(ec_key)?;

                        unsafe {
                            check(ffi::fido_assert_verify(
                                self.0.ptr.as_ptr(),
                                0,
                                CoseType::ES256 as i32,
                                pk.as_ptr().cast(),
                            ))?;
                        }
                    }
                    Nid::SECP384R1 => {
                        let pk = ES384::try_from(ec_key)?;

                        unsafe {
                            check(ffi::fido_assert_verify(
                                self.0.ptr.as_ptr(),
                                0,
                                CoseType::ES384 as i32,
                                pk.as_ptr().cast(),
                            ))?;
                        }
                    }
                    _ => {
                        return Err(FidoError::new(FIDO_ERR_INVALID_ARGUMENT))?;
                    }
                }
            }
            _ => {
                return Err(FidoError::new(FIDO_ERR_INVALID_ARGUMENT))?;
            }
        }

        Ok(())
    }
}

impl Drop for Assertions {
    fn drop(&mut self) {
        let mut ptr = self.ptr.as_ptr();

        unsafe {
            ffi::fido_assert_free(&mut ptr);
        }

        let _ = std::mem::replace(&mut self.ptr, NonNull::dangling());
    }
}

impl Assertion<'_> {
    /// Return relying party ID of assert.
    pub fn rp_id(&self) -> Option<&str> {
        let rp_id = unsafe { ffi::fido_assert_rp_id(self.ptr.as_ptr()) };
        str_or_none!(rp_id)
    }

    /// Return user display name of assert.
    pub fn user_display_name(&self) -> Option<&str> {
        let display_name =
            unsafe { ffi::fido_assert_user_display_name(self.ptr.as_ptr(), self.idx) };

        str_or_none!(display_name)
    }

    /// Return user icon of assert.
    pub fn user_icon(&self) -> Option<&str> {
        let icon = unsafe { ffi::fido_assert_user_icon(self.ptr.as_ptr(), self.idx) };

        str_or_none!(icon)
    }

    /// Return user name of assert.
    pub fn user_name(&self) -> Option<&str> {
        let name = unsafe { ffi::fido_assert_user_name(self.ptr.as_ptr(), self.idx) };

        str_or_none!(name)
    }

    /// Return CBOR-encoded authenticator data
    pub fn auth_data(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_authdata_len(self.ptr.as_ptr(), self.idx) };
        let ptr = unsafe { ffi::fido_assert_authdata_ptr(self.ptr.as_ptr(), self.idx) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return client data hash.
    pub fn client_data_hash(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_clientdata_hash_len(self.ptr.as_ptr()) };
        let ptr = unsafe { ffi::fido_assert_clientdata_hash_ptr(self.ptr.as_ptr()) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return the credBlob attribute.
    pub fn blob(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_blob_len(self.ptr.as_ptr(), self.idx) };
        let ptr = unsafe { ffi::fido_assert_blob_ptr(self.ptr.as_ptr(), self.idx) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return the hmac-secret attribute.
    ///
    /// The HMAC Secret Extension (hmac-secret) is a CTAP 2.0 extension.
    ///
    /// Note that the resulting hmac-secret varies according to whether user verification was performed by the authenticator.
    pub fn hmac_secret(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_hmac_secret_len(self.ptr.as_ptr(), self.idx) };
        let ptr = unsafe { ffi::fido_assert_hmac_secret_ptr(self.ptr.as_ptr(), self.idx) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return largeBlobKey attribute.
    pub fn large_blob_key(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_largeblob_key_len(self.ptr.as_ptr(), self.idx) };
        let ptr = unsafe { ffi::fido_assert_largeblob_key_ptr(self.ptr.as_ptr(), self.idx) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return user ID.
    pub fn user_id(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_user_id_len(self.ptr.as_ptr(), self.idx) };
        let ptr = unsafe { ffi::fido_assert_user_id_ptr(self.ptr.as_ptr(), self.idx) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return signature
    pub fn signature(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_sig_len(self.ptr.as_ptr(), self.idx) };
        let ptr = unsafe { ffi::fido_assert_sig_ptr(self.ptr.as_ptr(), self.idx) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return credential ID
    pub fn id(&self) -> &[u8] {
        let len = unsafe { ffi::fido_assert_id_len(self.ptr.as_ptr(), self.idx) };
        let ptr = unsafe { ffi::fido_assert_id_ptr(self.ptr.as_ptr(), self.idx) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return signature count.
    pub fn counter(&self) -> u32 {
        unsafe { ffi::fido_assert_sigcount(self.ptr.as_ptr(), self.idx) }
    }

    /// Return authenticator data flags.
    pub fn flags(&self) -> u8 {
        unsafe { ffi::fido_assert_flags(self.ptr.as_ptr(), self.idx) }
    }
}

impl Assertions {
    /// Return the number of assertion.
    pub fn count(&self) -> usize {
        unsafe { ffi::fido_assert_count(self.ptr.as_ptr()) }
    }

    /// Return a iterator of contained assertion
    pub fn iter(&self) -> impl Iterator<Item = Assertion<'_>> {
        let count = self.count();

        AssertionIter {
            asserts: self,
            idx: 0,
            count,
        }
    }
}

/// Iterator of assertion
pub struct AssertionIter<'a> {
    asserts: &'a Assertions,
    idx: usize,
    count: usize,
}

impl<'a> Iterator for AssertionIter<'a> {
    type Item = Assertion<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.count {
            None
        } else {
            let item = Assertion {
                ptr: self.asserts.ptr,
                idx: self.idx,
                _p: PhantomData,
            };

            self.idx += 1;

            Some(item)
        }
    }
}
