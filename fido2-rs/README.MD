# fido2-rs

[![crates.io](https://img.shields.io/crates/v/fido2-rs?style=flat-square)](https://crates.io/crates/fido2-rs)
[![MIT](https://img.shields.io/crates/l/libfido2-sys?style=flat-square)](./LICENSE)

[libfido2](https://github.com/Yubico/libfido2) bindings for the Rust programming language.

For more details, see [tyan-boot/fido-rs](https://github.com/tyan-boot/fido-rs)

```rust
use fido2_rs::device::Device;
use fido2_rs::credentials::Credential;
use fido2_rs::credentials::CoseType;
use anyhow::Result;

fn main() -> Result<()> {
    let dev = Device::open("windows://hello").expect("unable open windows hello");

    let mut cred = Credential::new()?;
    cred.set_client_data(&[1, 2, 3, 4, 5, 6])?;
    cred.set_rp("fido_rs", "fido example")?;
    cred.set_user(&[1, 2, 3, 4, 5, 6], "alice", Some("alice"), None)?;
    cred.set_cose_type(CoseType::RS256)?;

    let _ = dev.make_credential(&mut cred, None)?;
    dbg!(cred.id());

    Ok(())
}
```
