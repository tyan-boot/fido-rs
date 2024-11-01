# fido-rs

[libfido2](https://github.com/Yubico/libfido2) bindings for the Rust programming language.

# Example

1. Make a credential
```rust
use fido2_rs::device::Device;
use fido2_rs::credentials::Credential;
use fido2_rs::credentials::CoseType;
use anyhow::Result;
fn main() -> Result<()> {
    let dev = Device::open("windows://hello").expect("unable open windows hello");
 
    let mut cred = Credential::new();
    cred.set_client_data(&[1, 2, 3, 4, 5, 6])?;
    cred.set_rp("fido_rs", "fido example")?;
    cred.set_user(&[1, 2, 3, 4, 5, 6], "alice", Some("alice"), None)?;
    cred.set_cose_type(CoseType::RS256)?;

    let _ = dev.make_credential(&mut cred, None)?;
    dbg!(cred.id());

    Ok(())
}
```

# Support platform
* Windows (MSVC and MinGW)
* Linux

# TODO

* [ ] more doc
* [x] full bindings to `fido_cred_t` and `fido_assert_t`
* [x] credman api
