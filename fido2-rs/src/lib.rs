//! Bindings to Yubico libfido2
//!
//! This crate provides a safe interface to the Yubico libfido2 library.
//!
//! # Building
//!
//! There are multiple options available to locate libfido2.
//!
//! ## Pre-build MSVC binary.
//!
//! If the rust toolchain is msvc, the `libfido2-sys` crate will download a pre-build binary dll from
//! Yubico release.
//!
//! ## Build from source.
//!
//! If the target is not msvc(mingw on windows or linux), this crate will build a static library from source.
//!
//! The build process requires a C compiler, cmake, libcbor, zlib, libcrypto.
//!
//! ## Automatic
//!
//! The `libfido2-sys` crate can automatically detect libfido2 installations via vcpkg on Windows and `pkg-config` on Linux.
//!
//! This method can be enabled by set environment variable `FIDO2_USE_PKG_CONFIG` to any non empty value.
//!
//! ## Manual
//!
//! A `FIDO2_LIB_DIR` environment variable can be used to help `libfido2-sys` to find a libfido2 installation.
//!
//! The directory should contains the libfido2 libraries.
//!
//! The other dependency like libcbor, libcrypto, zlib will use system version. Currently there is no way to
//! set these library directory, but you can put them together in `FIDO2_LIB_DIR`.
//!
//! # Example
//!
//! ## Enumerate fido devices on system
//! ```rust,no_run
//! use fido2_rs::device::DeviceList;
//!
//! let list = DeviceList::list_devices(4);
//! for dev in list {
//!     println!("{:?}", dev.path);
//! }
//!
//! ```
//!
//! ## Make a credential
//! ```rust,no_run
//! use fido2_rs::device::Device;
//! use fido2_rs::credentials::Credential;
//! use fido2_rs::credentials::CoseType;
//! use anyhow::Result;
//! fn main() -> Result<()> {
//!     let dev = Device::open("windows://hello").expect("unable open windows hello");
//!  
//!     let mut cred = Credential::new();
//!     cred.set_client_data(&[1, 2, 3, 4, 5, 6])?;
//!     cred.set_rp("fido_rs", "fido example")?;
//!     cred.set_user(&[1, 2, 3, 4, 5, 6], "alice", Some("alice"), None)?;
//!     cred.set_cose_type(CoseType::RS256)?;
//!
//!     let _ = dev.make_credential(&mut cred, None)?;
//!     dbg!(cred.id());
//!
//!     Ok(())
//! }
//! ```
extern crate libfido2_sys as ffi;

#[macro_use]
mod utils;

pub mod assertion;
mod cbor;
pub mod credentials;
pub mod credman;
pub mod device;
pub mod error;
mod key;
