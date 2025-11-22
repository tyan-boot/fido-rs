use std::ffi::{CStr, CString};
use std::ops::Deref;
use std::ptr::NonNull;

use bitflags::bitflags;
use foreign_types::{ForeignType, ForeignTypeRef, Opaque};

use crate::error::Result;
use crate::utils::check;

/// FIDO credential
pub struct Credential(pub(crate) NonNull<ffi::fido_cred_t>);

impl Drop for Credential {
    fn drop(&mut self) {
        unsafe {
            // `fido_cred_free` set this ptr to `NULL`
            ffi::fido_cred_free(&mut self.0.as_ptr());
        }
    }
}

impl ForeignType for Credential {
    type CType = ffi::fido_cred_t;
    type Ref = CredentialRef;

    unsafe fn from_ptr(ptr: *mut Self::CType) -> Self {
        unsafe { Credential(NonNull::new_unchecked(ptr)) }
    }

    fn as_ptr(&self) -> *mut Self::CType {
        self.0.as_ptr()
    }
}

/// FIDO credential
pub struct CredentialRef(Opaque);

impl ForeignTypeRef for CredentialRef {
    type CType = ffi::fido_cred_t;
}

impl CredentialRef {
    /// If the CTAP 2.1 FIDO_EXT_MINPINLEN extension is enabled on cred, then this function returns
    /// the minimum PIN length of cred.
    ///
    /// Otherwise, returns zero.
    pub fn pin_min_len(&self) -> usize {
        unsafe { ffi::fido_cred_pin_minlen(self.as_ptr()) }
    }

    /// If the CTAP 2.1 FIDO_EXT_CRED_PROTECT extension is enabled on cred, then this function returns
    /// the protection of cred.
    ///
    /// Otherwise, returns [None]
    pub fn protection(&self) -> Option<Protection> {
        unsafe {
            let prot = ffi::fido_cred_prot(self.as_ptr());

            match prot {
                ffi::FIDO_CRED_PROT_UV_OPTIONAL => Some(Protection::UvOptional),
                ffi::FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID => Some(Protection::UvOptionalWithId),
                ffi::FIDO_CRED_PROT_UV_REQUIRED => Some(Protection::UvRequired),
                _ => None,
            }
        }
    }

    /// Return the attestation statement format identifier of cred, or [None] if cred does not have a format set.
    pub fn attestation_format(&self) -> Option<AttestationFormat> {
        let fmt = unsafe { ffi::fido_cred_fmt(self.as_ptr()) };

        if fmt.is_null() {
            None
        } else {
            let fmt = unsafe { CStr::from_ptr(fmt).to_str().expect("invalid utf8") };

            match fmt {
                "packed" => Some(AttestationFormat::Packed),
                "fido-u2f" => Some(AttestationFormat::FidoU2f),
                "tpm" => Some(AttestationFormat::Tpm),
                "none" => Some(AttestationFormat::None),
                _ => None,
            }
        }
    }

    /// Return relying party ID, or [None] if is not set.
    pub fn rp_id(&self) -> Option<&str> {
        let rp_id = unsafe { ffi::fido_cred_rp_id(self.as_ptr()) };
        str_or_none!(rp_id)
    }

    /// Return relying party name, or [None] if is not set.
    pub fn rp_name(&self) -> Option<&str> {
        let rp_name = unsafe { ffi::fido_cred_rp_name(self.as_ptr()) };
        str_or_none!(rp_name)
    }

    /// Return user name, or [None] if is not set.
    pub fn user_name(&self) -> Option<&str> {
        let user_name = unsafe { ffi::fido_cred_user_name(self.as_ptr()) };
        str_or_none!(user_name)
    }

    /// Return user display name, or [None] if is not set.
    pub fn display_name(&self) -> Option<&str> {
        let display_name = unsafe { ffi::fido_cred_display_name(self.as_ptr()) };
        str_or_none!(display_name)
    }

    /// Return CBOR-encoded authenticator data.
    ///
    /// The slice len will be 0 if is not set.
    pub fn auth_data(&self) -> &[u8] {
        let len = unsafe { ffi::fido_cred_authdata_len(self.as_ptr()) };
        let ptr = unsafe { ffi::fido_cred_authdata_ptr(self.as_ptr()) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return raw authenticator data.
    ///
    /// The slice len will be 0 if is not set.
    pub fn auth_data_raw(&self) -> &[u8] {
        let len = unsafe { ffi::fido_cred_authdata_raw_len(self.as_ptr()) };
        let ptr = unsafe { ffi::fido_cred_authdata_raw_ptr(self.as_ptr()) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return client data hash
    ///
    /// The slice len will be 0 if is not set.
    pub fn client_data_hash(&self) -> &[u8] {
        let len = unsafe { ffi::fido_cred_clientdata_hash_len(self.as_ptr()) };
        let ptr = unsafe { ffi::fido_cred_clientdata_hash_ptr(self.as_ptr()) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return credential ID
    ///
    /// The slice len will be 0 if is not set.
    pub fn id(&self) -> &[u8] {
        let len = unsafe { ffi::fido_cred_id_len(self.as_ptr()) };
        let ptr = unsafe { ffi::fido_cred_id_ptr(self.as_ptr()) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return authenticator attestation GUID
    ///
    /// The slice len will be 0 if is not set.
    pub fn attestation_guid(&self) -> &[u8] {
        let len = unsafe { ffi::fido_cred_aaguid_len(self.as_ptr()) };
        let ptr = unsafe { ffi::fido_cred_aaguid_ptr(self.as_ptr()) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return "largeBlobKey".
    ///
    /// The slice len will be 0 if is not set.
    pub fn large_blob_key(&self) -> &[u8] {
        let len = unsafe { ffi::fido_cred_largeblob_key_len(self.as_ptr()) };
        let ptr = unsafe { ffi::fido_cred_largeblob_key_ptr(self.as_ptr()) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return public key.
    ///
    /// The slice len will be 0 if is not set.
    pub fn public_key(&self) -> &[u8] {
        let len = unsafe { ffi::fido_cred_pubkey_len(self.as_ptr()) };
        let ptr = unsafe { ffi::fido_cred_pubkey_ptr(self.as_ptr()) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return signature.
    ///
    /// The slice len will be 0 if is not set.
    pub fn signature(&self) -> &[u8] {
        let len = unsafe { ffi::fido_cred_sig_len(self.as_ptr()) };
        let ptr = unsafe { ffi::fido_cred_sig_ptr(self.as_ptr()) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return user ID.
    ///
    /// The slice len will be 0 if is not set.
    pub fn user_id(&self) -> &[u8] {
        let len = unsafe { ffi::fido_cred_user_id_len(self.as_ptr()) };
        let ptr = unsafe { ffi::fido_cred_user_id_ptr(self.as_ptr()) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return X509 certificate.
    ///
    /// The slice len will be 0 if is not set.
    pub fn certificate(&self) -> &[u8] {
        let len = unsafe { ffi::fido_cred_x5c_len(self.as_ptr()) };
        let ptr = unsafe { ffi::fido_cred_x5c_ptr(self.as_ptr()) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return attestation statement.
    ///
    /// The slice len will be 0 if is not set.
    pub fn attestation(&self) -> &[u8] {
        let len = unsafe { ffi::fido_cred_attstmt_len(self.as_ptr()) };
        let ptr = unsafe { ffi::fido_cred_attstmt_ptr(self.as_ptr()) };

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Return the COSE algorithm of cred.
    pub fn cose_type(&self) -> CoseType {
        unsafe {
            let cred_type = ffi::fido_cred_type(self.as_ptr());

            CoseType::try_from(cred_type).unwrap_or(CoseType::UNSPEC)
        }
    }

    /// Return the authenticator data flags of cred.
    pub fn flags(&self) -> u8 {
        unsafe { ffi::fido_cred_flags(self.as_ptr()) }
    }

    /// Return the authenticator data signature counter of cred.
    pub fn counter(&self) -> u32 {
        unsafe { ffi::fido_cred_sigcount(self.as_ptr()) }
    }

    /// Verifies whether the client data hash, relying party ID, credential ID, type, protection policy,
    /// minimum PIN length, and resident/discoverable key and user verification attributes of cred
    /// have been attested by the holder of the private counterpart of the public key contained in the credential's x509 certificate.
    ///
    /// Please note that the x509 certificate itself is not verified.
    ///
    /// The attestation statement formats supported by [Credential::verify] are packed, fido-u2f, and tpm.
    ///
    /// The attestation type implemented by [Credential::verify] is Basic Attestation.
    pub fn verify(&self) -> Result<()> {
        unsafe {
            check(ffi::fido_cred_verify(self.as_ptr()))?;
        }

        Ok(())
    }

    /// verifies whether the client data hash, relying party ID, credential ID, type, protection policy,
    /// minimum PIN length, and resident/discoverable key and user verification attributes of cred
    /// have been attested by the holder of the credential's private key.
    ///
    /// The attestation statement formats supported by [Credential::verify_self] are packed and fido-u2f.
    ///
    /// The attestation type implemented by [Credential::verify_self] is Self Attestation.
    pub fn verify_self(&self) -> Result<()> {
        unsafe {
            check(ffi::fido_cred_verify_self(self.as_ptr()))?;
        }

        Ok(())
    }
}

impl Credential {
    /// Create a new credential
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        unsafe {
            let cred = ffi::fido_cred_new();

            Credential(NonNull::new_unchecked(cred))
        }
    }

    /// Set the id
    pub fn set_id(&mut self, id: impl AsRef<[u8]>) -> Result<()> {
        let id = id.as_ref();
        unsafe {
            check(ffi::fido_cred_set_id(
                self.0.as_ptr(),
                id.as_ptr(),
                id.len(),
            ))?;
        }

        Ok(())
    }

    /// Set the client data hash of cred by specifying the credential's unhashed client data.
    ///
    /// This is required by Windows Hello, which calculates the client data hash internally.
    ///
    /// For compatibility with Windows Hello, applications should use [Credential::set_client_data] instead of [Credential::set_client_data_hash]
    pub fn set_client_data(&mut self, data: impl AsRef<[u8]>) -> Result<()> {
        let data = data.as_ref();
        unsafe {
            check(ffi::fido_cred_set_clientdata(
                self.0.as_ptr(),
                data.as_ptr(),
                data.len(),
            ))?;
        }

        Ok(())
    }

    /// See [Credential::set_client_data]
    pub fn set_client_data_hash(&mut self, data: impl AsRef<[u8]>) -> Result<()> {
        let data = data.as_ref();
        unsafe {
            check(ffi::fido_cred_set_clientdata_hash(
                self.0.as_ptr(),
                data.as_ptr(),
                data.len(),
            ))?;
        }

        Ok(())
    }

    /// Set the relying party id and name parameters of cred
    pub fn set_rp(&mut self, id: impl AsRef<str>, name: impl AsRef<str>) -> Result<()> {
        let id = CString::new(id.as_ref())?;
        let name = CString::new(name.as_ref())?;

        unsafe {
            check(ffi::fido_cred_set_rp(
                self.0.as_ptr(),
                id.as_ptr(),
                name.as_ptr(),
            ))?;
        }

        Ok(())
    }

    pub fn exclude_cred_id(&mut self, id: impl AsRef<[u8]>) -> Result<()> {
        let id = id.as_ref();
        unsafe {
            check(ffi::fido_cred_exclude(
                self.0.as_ptr(),
                id.as_ptr(),
                id.len(),
            ))?;
        }

        Ok(())
    }

    /// Sets the user attributes of cred.
    ///
    /// Previously set user attributes are flushed
    pub fn set_user(
        &mut self,
        id: impl AsRef<[u8]>,
        name: impl AsRef<str>,
        display_name: Option<&str>,
        icon: Option<&str>,
    ) -> Result<()> {
        let id = id.as_ref();
        let name = CString::new(name.as_ref())?;
        let display_name = display_name.map(CString::new).transpose()?;
        let icon = icon.map(CString::new).transpose()?;

        let display_name_ptr = match &display_name {
            Some(it) => it.as_ptr(),
            None => std::ptr::null(),
        };

        let icon_ptr = match &icon {
            Some(it) => it.as_ptr(),
            None => std::ptr::null(),
        };

        unsafe {
            check(ffi::fido_cred_set_user(
                self.0.as_ptr(),
                id.as_ptr(),
                id.len(),
                name.as_ptr(),
                display_name_ptr,
                icon_ptr,
            ))?;
        }

        Ok(())
    }

    /// Sets the extensions of cred to the bitmask flags.
    ///
    /// Only the FIDO_EXT_CRED_BLOB, FIDO_EXT_CRED_PROTECT, FIDO_EXT_HMAC_SECRET,
    /// FIDO_EXT_MINPINLEN, and FIDO_EXT_LARGEBLOB_KEY extensions are supported.
    ///
    /// See [Extensions]
    pub fn set_extension(&mut self, flags: Extensions) -> Result<()> {
        unsafe {
            check(ffi::fido_cred_set_extensions(self.0.as_ptr(), flags.bits()))?;
        }

        Ok(())
    }

    /// Sets the “credBlob” to be stored with cred.
    pub fn set_blob(&mut self, data: impl AsRef<[u8]>) -> Result<()> {
        let data = data.as_ref();
        unsafe {
            check(ffi::fido_cred_set_blob(
                self.0.as_ptr(),
                data.as_ptr(),
                data.len(),
            ))?;
        }

        Ok(())
    }

    /// Enable the CTAP 2.1 FIDO_EXT_MINPINLEN extension on cred and sets the expected minimum PIN length of cred to len.
    ///
    /// If len is zero, the FIDO_EXT_MINPINLEN extension is disabled on cred.
    pub fn set_pin_min_len(&mut self, len: usize) -> Result<()> {
        unsafe {
            check(ffi::fido_cred_set_pin_minlen(self.0.as_ptr(), len))?;
        }

        Ok(())
    }

    /// Enables the CTAP 2.1 FIDO_EXT_CRED_PROTECT extension on cred and sets the protection of cred to the scalar prot.
    ///
    /// At the moment, only the FIDO_CRED_PROT_UV_OPTIONAL, FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID, and FIDO_CRED_PROT_UV_REQUIRED protections are supported.
    ///
    /// See [Protection]
    pub fn set_protection(&mut self, prot: Protection) -> Result<()> {
        unsafe {
            check(ffi::fido_cred_set_prot(self.0.as_ptr(), prot as i32))?;
        }

        Ok(())
    }

    /// Set the rk (resident/discoverable key) attribute of cred.
    pub fn set_rk(&mut self, rk: Opt) -> Result<()> {
        unsafe {
            check(ffi::fido_cred_set_rk(self.0.as_ptr(), rk as _))?;
        }

        Ok(())
    }

    /// Set the uv (user verification) attribute of cred.
    pub fn set_uv(&mut self, uv: Opt) -> Result<()> {
        unsafe {
            check(ffi::fido_cred_set_uv(self.0.as_ptr(), uv as _))?;
        }

        Ok(())
    }

    /// Sets the attestation statement format identifier of cred.
    ///
    /// Note that not all authenticators support FIDO2 and therefore may only be able to generate fido-u2f attestation statements.
    pub fn set_attestation_format(&mut self, fmt: AttestationFormat) -> Result<()> {
        let fmt = match fmt {
            AttestationFormat::Packed => CString::new("packed"),
            AttestationFormat::FidoU2f => CString::new("fido-u2f"),
            AttestationFormat::Tpm => CString::new("tpm"),
            AttestationFormat::None => CString::new("none"),
        };
        let fmt = fmt.unwrap();

        unsafe {
            check(ffi::fido_cred_set_fmt(self.0.as_ptr(), fmt.as_ptr()))?;
        }

        Ok(())
    }

    /// Sets the type of cred.
    ///
    /// The `type` of a credential may only be set once.
    ///
    /// Note that not all authenticators support COSE_RS256, COSE_ES384, or COSE_EDDSA.
    pub fn set_cose_type(&mut self, ty: CoseType) -> Result<()> {
        unsafe {
            check(ffi::fido_cred_set_type(self.0.as_ptr(), ty as i32))?;
        }

        Ok(())
    }
}

impl AsRef<CredentialRef> for Credential {
    fn as_ref(&self) -> &CredentialRef {
        unsafe { CredentialRef::from_ptr(self.0.as_ptr()) }
    }
}

impl Deref for Credential {
    type Target = CredentialRef;

    fn deref(&self) -> &Self::Target {
        unsafe { CredentialRef::from_ptr(self.0.as_ptr()) }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(i32)]
pub enum Opt {
    Omit = 0,
    False = 1,
    True = 2,
}

#[derive(Copy, Clone, Debug)]
#[repr(i32)]
pub enum Protection {
    UvOptional = ffi::FIDO_CRED_PROT_UV_OPTIONAL,
    UvOptionalWithId = ffi::FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID,
    UvRequired = ffi::FIDO_CRED_PROT_UV_REQUIRED,
}

/// Attestation statement format
#[derive(Copy, Clone, Debug)]
pub enum AttestationFormat {
    Packed,
    FidoU2f,
    Tpm,
    None,
}

/// COSE Algorithms type
#[repr(i32)]
pub enum CoseType {
    ES256 = ffi::COSE_ES256,
    ES384 = ffi::COSE_ES384,
    RS256 = ffi::COSE_RS256,
    EDDSA = ffi::COSE_EDDSA,
    UNSPEC = ffi::COSE_UNSPEC,
}

impl TryFrom<i32> for CoseType {
    type Error = i32;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            ffi::COSE_UNSPEC => Ok(CoseType::UNSPEC),
            ffi::COSE_ES256 => Ok(CoseType::ES256),
            ffi::COSE_ES384 => Ok(CoseType::ES384),
            ffi::COSE_RS256 => Ok(CoseType::RS256),
            ffi::COSE_EDDSA => Ok(CoseType::EDDSA),
            _ => Err(value),
        }
    }
}

bitflags! {
    /// FIDO extensions
    pub struct Extensions: i32 {
        const CRED_BLOB = ffi::FIDO_EXT_CRED_BLOB;
        const CRED_PROTECT = ffi::FIDO_EXT_CRED_PROTECT;
        const HMAC_SECRET = ffi::FIDO_EXT_HMAC_SECRET;
        const MIN_PINLEN = ffi::FIDO_EXT_MINPINLEN;
        const LARGEBLOB_KEY = ffi::FIDO_EXT_LARGEBLOB_KEY;
    }
}
