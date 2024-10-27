use crate::assertion::{AssertRequest, Assertions};
use crate::cbor::CBORInfo;
use crate::credentials::Credential;
use crate::credman::CredentialManagement;
use crate::error::{Error, Result};
use crate::utils::check;
use bitflags::bitflags;
use ffi::fido_dev_t;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::ptr::NonNull;

/// Device list.
///
/// contain fido devices found by the underlying operating system.
///
/// user can call [DeviceList::list_devices] to start enumerate fido devices.
pub struct DeviceList<'a> {
    ptr: NonNull<ffi::fido_dev_info_t>,
    idx: usize,
    found: usize,
    _p: PhantomData<&'a ()>,
}

impl<'a> DeviceList<'a> {
    /// Enumerate up to `max` fido devices found by the underlying operating system.
    ///
    /// Currently only USB HID devices are supported
    pub fn list_devices(max: usize) -> DeviceList<'a> {
        unsafe {
            let mut found = 0;
            let ptr = ffi::fido_dev_info_new(max);

            ffi::fido_dev_info_manifest(ptr, max, &mut found);

            DeviceList {
                ptr: NonNull::new_unchecked(ptr),
                idx: 0,
                found,
                _p: PhantomData,
            }
        }
    }
}

impl<'a> Iterator for DeviceList<'a> {
    type Item = DeviceInfo<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.found {
            return None;
        }

        unsafe {
            let ptr = self.ptr.as_ptr();
            let info = ffi::fido_dev_info_ptr(ptr, self.idx);

            let path = ffi::fido_dev_info_path(info);
            let path = CStr::from_ptr(path);

            let product_id = ffi::fido_dev_info_product(info);
            let vendor_id = ffi::fido_dev_info_vendor(info);

            let manufacturer = ffi::fido_dev_info_manufacturer_string(info);
            let manufacturer = CStr::from_ptr(manufacturer);

            let product = ffi::fido_dev_info_product_string(info);
            let product = CStr::from_ptr(product);
            self.idx += 1;

            Some(DeviceInfo {
                path,
                product_id,
                vendor_id,
                manufacturer,
                product,
            })
        }
    }
}

impl<'a> ExactSizeIterator for DeviceList<'a> {
    fn len(&self) -> usize {
        self.found
    }
}

impl<'a> Drop for DeviceList<'a> {
    fn drop(&mut self) {
        unsafe {
            ffi::fido_dev_info_free(&mut self.ptr.as_ptr(), self.found);
        }
    }
}

/// Device info obtained from [DeviceList]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceInfo<'a> {
    pub path: &'a CStr,
    pub product_id: i16,
    pub vendor_id: i16,
    pub manufacturer: &'a CStr,
    pub product: &'a CStr,
}

impl<'a> DeviceInfo<'a> {
    /// Open the device specified by this [DeviceInfo]
    pub fn open(&self) -> Result<Device> {
        unsafe {
            let ptr = ffi::fido_dev_new();
            check(ffi::fido_dev_open(ptr, self.path.as_ptr()))?;

            let ptr = NonNull::new_unchecked(ptr);

            Ok(Device { ptr })
        }
    }
}

/// A cancel handle to device, used to cancel a pending requests.
///
/// This handle can be copy/clone.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct DeviceCancel(NonNull<fido_dev_t>);

impl DeviceCancel {
    /// Cancel any pending requests on device.
    pub fn cancel(&self) {
        unsafe {
            ffi::fido_dev_cancel(self.0.as_ptr());
        }
    }
}

/// A fido device.
pub struct Device {
    pub(crate) ptr: NonNull<fido_dev_t>,
}

impl Device {
    /// Open the device pointed to by `path`.
    ///
    /// If dev claims to be FIDO2, libfido2 will attempt to speak FIDO2 to dev.
    /// If that fails, libfido2 will fallback to U2F unless the FIDO_DISABLE_U2F_FALLBACK flag
    /// was set in fido_init(3).
    pub fn open(path: impl AsRef<str>) -> Result<Device> {
        let path = CString::new(path.as_ref())?;
        unsafe {
            let dev = ffi::fido_dev_new();
            assert!(!dev.is_null());

            check(ffi::fido_dev_open(dev, path.as_ptr()))?;

            Ok(Device {
                ptr: NonNull::new_unchecked(dev),
            })
        }
    }

    /// Get a handle of this device for cancel.
    pub fn cancel_handle(&self) -> DeviceCancel {
        DeviceCancel(self.ptr)
    }

    /// can be used to force CTAP2 communication with dev
    pub fn force_u2f(&self) {
        unsafe {
            ffi::fido_dev_force_u2f(self.ptr.as_ptr());
        }
    }

    /// Can be used to force CTAP1 (U2F) communication with dev
    pub fn force_fido2(&self) {
        unsafe {
            ffi::fido_dev_force_fido2(self.ptr.as_ptr());
        }
    }

    /// Returns true if dev is a FIDO2 device.
    pub fn is_fido2(&self) -> bool {
        unsafe { ffi::fido_dev_is_fido2(self.ptr.as_ptr()) }
    }

    /// Returns true if dev is a Windows Hello device.
    pub fn is_winhello(&self) -> bool {
        unsafe { ffi::fido_dev_is_winhello(self.ptr.as_ptr()) }
    }

    /// Returns true if dev supports CTAP 2.1 Credential Management.
    pub fn supports_credman(&self) -> bool {
        unsafe { ffi::fido_dev_supports_credman(self.ptr.as_ptr()) }
    }

    /// Returns true if dev supports CTAP 2.1 Credential Protection.
    pub fn supports_cred_prot(&self) -> bool {
        unsafe { ffi::fido_dev_supports_cred_prot(self.ptr.as_ptr()) }
    }

    /// Returns true if dev supports CTAP 2.1 UV token permissions.
    pub fn supports_permission(&self) -> bool {
        unsafe { ffi::fido_dev_supports_permissions(self.ptr.as_ptr()) }
    }

    /// Returns true if dev supports CTAP 2.0 Client PINs.
    pub fn supports_pin(&self) -> bool {
        unsafe { ffi::fido_dev_supports_pin(self.ptr.as_ptr()) }
    }

    /// Returns true if dev supports a built-in user verification method.
    pub fn supports_uv(&self) -> bool {
        unsafe { ffi::fido_dev_supports_uv(self.ptr.as_ptr()) }
    }

    /// Returns true if dev has a CTAP 2.0 Client PIN set.
    pub fn has_pin(&self) -> bool {
        unsafe { ffi::fido_dev_has_pin(self.ptr.as_ptr()) }
    }

    /// Returns true if dev supports built-in user verification and its user verification feature is configured.
    pub fn has_uv(&self) -> bool {
        unsafe { ffi::fido_dev_has_uv(self.ptr.as_ptr()) }
    }

    /// Return CTAPHID protocol info.
    pub fn ctap_protocol(&self) -> CTAPHIDInfo {
        unsafe {
            let protocol = ffi::fido_dev_protocol(self.ptr.as_ptr());
            let build = ffi::fido_dev_build(self.ptr.as_ptr());
            let flags = ffi::fido_dev_flags(self.ptr.as_ptr());
            let flags = CTAPHIDFlags::from_bits_truncate(flags);
            let major = ffi::fido_dev_major(self.ptr.as_ptr());
            let minor = ffi::fido_dev_minor(self.ptr.as_ptr());

            CTAPHIDInfo {
                protocol,
                build,
                flags,
                major,
                minor,
            }
        }
    }

    /// Return device info.
    pub fn info(&self) -> Result<CBORInfo> {
        let info = CBORInfo::new();

        unsafe {
            check(ffi::fido_dev_get_cbor_info(
                self.ptr.as_ptr(),
                info.ptr.as_ptr(),
            ))?;
        }

        Ok(info)
    }

    pub fn get_retry_count(&self) -> Result<i32> {
        let mut res = 0;
        unsafe {
            check(ffi::fido_dev_get_retry_count(
                self.ptr.as_ptr(),
                &mut res as *mut i32,
            ))?;
        }
        Ok(res)
    }

    pub fn get_uv_retry_count(&self) -> Result<i32> {
        let mut res = 0;
        unsafe {
            check(ffi::fido_dev_get_uv_retry_count(
                self.ptr.as_ptr(),
                &mut res as *mut i32,
            ))?;
        }
        Ok(res)
    }

    /// Generates a new credential on a FIDO2 device.
    ///
    /// Ask the FIDO2 device represented by dev to generate a new credential according to the following parameters defined in cred:
    /// * type
    /// * client data hash
    /// * relying party
    /// * user attributes
    /// * list of excluded credential IDs
    /// * resident/discoverable key and user verification attributes
    ///
    /// If a PIN is not needed to authenticate the request against dev, then pin may be [None].
    ///
    /// **Please note that fido_dev_make_cred() is synchronous and will block if necessary.**
    ///
    /// # Example
    /// ```rust,no_run
    /// use fido2_rs::credentials::Credential;
    /// use fido2_rs::device::Device;
    /// use fido2_rs::credentials::CoseType;
    ///
    /// fn main() -> anyhow::Result<()> {
    ///     let dev = Device::open("windows://hello").expect("unable open device");
    ///     let mut cred = Credential::new();
    ///     cred.set_client_data(&[1, 2, 3, 4, 5, 6])?;
    ///     cred.set_rp("fido_rs", "fido example")?;
    ///     cred.set_user(&[1, 2, 3, 4, 5, 6], "alice", Some("alice"), None)?;
    ///     cred.set_cose_type(CoseType::RS256)?;
    ///
    ///     let _ = dev.make_credential(&mut cred, None)?;    // and not require pin..
    ///
    ///     dbg!(cred.id());
    ///     Ok(())
    /// }
    /// ```
    pub fn make_credential(&self, credential: &mut Credential, pin: Option<&str>) -> Result<()> {
        let pin = pin.map(CString::new).transpose()?;
        let pin_ptr = match &pin {
            Some(pin) => pin.as_ptr(),
            None => std::ptr::null(),
        };

        unsafe {
            check(ffi::fido_dev_make_cred(
                self.ptr.as_ptr(),
                credential.0.as_ptr(),
                pin_ptr,
            ))?;
        }

        Ok(())
    }

    /// Obtains an assertion from a FIDO2 device.
    ///
    /// Ask the FIDO2 device represented by dev for an assertion according to the following parameters defined in assert:
    /// * relying party ID
    /// * client data hash
    /// * list of allowed credential IDs
    /// * user presence and user verification attributes
    ///
    /// If a PIN is not needed to authenticate the request against dev, then pin may be NULL.
    ///
    /// **Please note that fido_dev_get_assert() is synchronous and will block if necessary.**
    ///
    /// # Example
    /// ```rust,no_run
    /// use fido2_rs::assertion::AssertRequest;
    /// use fido2_rs::credentials::Opt;
    /// use fido2_rs::device::Device;
    ///
    /// fn main() -> anyhow::Result<()> {
    ///     let dev = Device::open("windows://hello")?;
    ///     let mut request = AssertRequest::new();    ///
    ///
    ///     request.set_rp("fido_rs")?;
    ///     request.set_client_data(&[1, 2, 3, 4, 5, 6])?;
    ///     request.set_uv(Opt::True)?;
    ///
    ///     let _assertions = dev.get_assertion(request, None)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn get_assertion(&self, request: AssertRequest, pin: Option<&str>) -> Result<Assertions> {
        let pin = pin.map(CString::new).transpose()?;
        let pin_ptr = match &pin {
            Some(pin) => pin.as_ptr(),
            None => std::ptr::null(),
        };

        unsafe {
            check(ffi::fido_dev_get_assert(
                self.ptr.as_ptr(),
                request.0.ptr.as_ptr(),
                pin_ptr,
            ))?;
        }

        Ok(request.0)
    }

    /// Obtain a handle to the credential management interface of a FIDO2 device.
    ///
    /// A valid pin must be provided. If the device does not support credential management,
    /// or an error happened, error will be returned.
    pub fn credman(&self, pin: &str) -> Result<CredentialManagement> {
        if !self.supports_credman() {
            return Err(Error::Unsupported);
        }

        let credman = CredentialManagement::new(&self);

        let pin = CString::new(pin)?;
        let pin_ptr = pin.as_ptr();

        unsafe {
            check(ffi::fido_credman_get_dev_metadata(
                self.ptr.as_ptr(),
                credman.ptr.as_ptr(),
                pin_ptr,
            ))?;
        }

        Ok(credman)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            let _ = ffi::fido_dev_close(self.ptr.as_ptr());
            ffi::fido_dev_free(&mut self.ptr.as_ptr());
        }
    }
}

bitflags! {
    /// CTAPHID capabilities
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct CTAPHIDFlags: u8 {
        const WINK = ffi::FIDO_CAP_WINK as u8;
        const CBOR = ffi::FIDO_CAP_CBOR as u8;
        const NMSG = ffi::FIDO_CAP_NMSG as u8;
    }
}

/// For the format and meaning of the CTAPHID parameters,
/// please refer to the FIDO Client to Authenticator Protocol (CTAP) specification.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CTAPHIDInfo {
    /// CTAPHID protocol version identifier of dev
    pub protocol: u8,
    /// CTAPHID build version number of dev.
    pub build: u8,
    /// CTAPHID capabilities flags of dev.
    pub flags: CTAPHIDFlags,
    /// CTAPHID major version number of dev.
    pub major: u8,
    /// CTAPHID minor version number of dev.
    pub minor: u8,
}
