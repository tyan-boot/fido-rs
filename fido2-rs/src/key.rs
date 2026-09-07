use crate::error::FidoError;
use crate::utils::allocation_error;
use openssl::ec::EcKey;
use openssl::pkey::{PKey, Public};
use std::ptr::NonNull;

macro_rules! impl_key {
    (
        type CType = $ctype:ty;
        fn new = $new:expr;
        $(fn from<$t:ty> = $from:expr;)*
        fn drop = $drop:expr;

        pub struct $ty:ident;
    ) => {
        pub struct $ty(NonNull<$ctype>);

        $(impl TryFrom<$t> for $ty {
            type Error = FidoError;

            fn try_from(value: $t) -> Result<Self, Self::Error> {
                use foreign_types::ForeignType;

                unsafe {
                    let pk = $new();
                    let pk = NonNull::new(pk).ok_or_else(allocation_error)?;

                    if let Err(err) = crate::utils::check($from(pk.as_ptr(), value.as_ptr() as _)) {
                        let mut raw = pk.as_ptr();
                        $drop(&mut raw);
                        return Err(err);
                    }

                    Ok($ty(pk))
                }
            }
        })*

        impl Drop for $ty {
            fn drop(&mut self) {
                let mut ptr = self.0.as_ptr();
                unsafe {
                    $drop(&mut ptr);
                }

                let _ = std::mem::replace(&mut self.0, NonNull::dangling());
            }
        }

        impl $ty {
            pub(crate) fn as_ptr(&self) -> *const $ctype {
                self.0.as_ptr()
            }
        }
    };
}

impl_key! {
    type CType = ffi::eddsa_pk_t;
    fn new = ffi::eddsa_pk_new;
    fn from<PKey<Public>> = ffi::eddsa_pk_from_EVP_PKEY;
    fn drop = ffi::eddsa_pk_free;

    pub struct Eddsa;
}

impl_key! {
    type CType = ffi::rs256_pk_t;
    fn new = ffi::rs256_pk_new;
    fn from<PKey<Public>> = ffi::rs256_pk_from_EVP_PKEY;
    fn drop = ffi::rs256_pk_free;

    pub struct Rsa;
}

impl_key! {
    type CType = ffi::es256_pk_t;
    fn new = ffi::es256_pk_new;
    fn from<EcKey<Public>> = ffi::es256_pk_from_EC_KEY;
    fn drop = ffi::es256_pk_free;

    pub struct ES256;
}

impl_key! {
    type CType = ffi::es384_pk_t;
    fn new = ffi::es384_pk_new;
    fn from<EcKey<Public>> = ffi::es384_pk_from_EC_KEY;
    fn drop = ffi::es384_pk_free;

    pub struct ES384;
}
