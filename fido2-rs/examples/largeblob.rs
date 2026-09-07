//! Example: write and read data via FIDO2 largeBlob
//!
//! Requires a FIDO2 device with largeBlob support (e.g. YubiKey 5).
//! The device must have a PIN set.
//!
//! Usage: cargo run --example largeblob

use fido2_rs::credentials::{CoseType, Credential, Extensions, Opt};
use fido2_rs::device::DeviceList;

fn main() -> anyhow::Result<()> {
    let pin = "0000";
    let payload = b"Hello from fido2-rs largeBlob!";

    // Open first available device.
    let mut devices = DeviceList::list_devices(8)?;
    let dev_info = devices.next().expect("No FIDO2 device found");
    let dev = dev_info.open()?;

    // Check max largeBlob capacity
    let info = dev.info()?;
    println!("maxlargeblob: {} bytes", info.max_large_blob());

    // Create a resident credential with largeBlobKey extension
    let mut cred = Credential::new()?;
    cred.set_client_data([0u8; 32])?;
    cred.set_rp("fido2-rs.example", "largeBlob example")?;
    cred.set_user([1, 2, 3, 4], "test", Some("Test User"), None)?;
    cred.set_cose_type(CoseType::ES256)?;
    cred.set_rk(Opt::True)?;
    cred.set_extension(Extensions::LARGEBLOB_KEY)?;

    println!("Creating credential (touch device)...");
    dev.make_credential(&mut cred, Some(pin))?;

    // Extract and validate the largeBlobKey
    let blob_key = cred.large_blob_key().to_vec();
    if blob_key.is_empty() {
        anyhow::bail!(
            "largeBlobKey missing from credential — \
             device may not support the LARGEBLOB_KEY extension"
        );
    }
    println!("largeBlobKey: {} bytes", blob_key.len());

    // Drop the device handle to release the HID session.
    // libfido2 devices can only maintain one active HID connection at a time.
    // After make_credential completes, we must close and re-open before
    // calling largeblob operations.
    drop(dev);

    println!("Writing {} bytes...", payload.len());
    {
        let mut devices = DeviceList::list_devices(8)?;
        let dev_info = devices.next().expect("No FIDO2 device found");
        let dev = dev_info.open()?;
        dev.largeblob_set(&blob_key, payload, pin)?;
        println!("Write OK");
        drop(dev);
    }

    println!("Reading...");
    let data = {
        let mut devices = DeviceList::list_devices(8)?;
        let dev_info = devices.next().expect("No FIDO2 device found");
        let dev = dev_info.open()?;
        let result = dev.largeblob_get(&blob_key)?;
        println!(
            "Read {} bytes: {:?}",
            result.len(),
            String::from_utf8_lossy(&result)
        );
        result
    };

    assert_eq!(&data, payload);
    println!("Round-trip verified!");

    // Clean up
    println!("Removing blob entry...");
    {
        let mut devices = DeviceList::list_devices(8)?;
        let dev_info = devices.next().expect("No FIDO2 device found");
        let dev = dev_info.open()?;
        dev.largeblob_remove(&blob_key, pin)?;
        println!("Removed blob entry");
    }

    Ok(())
}
