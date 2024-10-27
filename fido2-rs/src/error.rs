use std::ffi::CStr;
use std::fmt::{Debug, Display, Formatter};

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Error type of fido2-rs
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("libfido2: {0}")]
    Fido(#[from] FidoError),

    #[error("{0}")]
    NulError(#[from] std::ffi::NulError),

    #[error("openssl {0}")]
    Openssl(#[from] openssl::error::ErrorStack),

    #[error("unsupported")]
    Unsupported,
}

/// Error from libfido2
pub struct FidoError {
    /// the origin error code
    pub code: i32,
}

impl FidoError {
    pub(crate) const fn new(code: i32) -> FidoError {
        FidoError { code }
    }
}

impl Debug for FidoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <Self as Display>::fmt(self, f)
    }
}

impl Display for FidoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let err = unsafe {
            let err = ffi::fido_strerr(self.code);
            CStr::from_ptr(err)
        };

        f.debug_struct("Error")
            .field("code", &self.code)
            .field("message", &err)
            .finish()
    }
}

impl std::error::Error for FidoError {}
