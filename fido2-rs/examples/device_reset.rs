//! Example: reset a FIDO2 device and verify the old PIN no longer works.
//!
//! **WARNING: This example DESTROYS all FIDO2 data on the device — credentials,
//! PIN, and largeBlob entries. Other applets (PIV, OpenPGP) are not affected.**
//!
//! The CTAP2 spec requires the device to have been powered on within ~10
//! seconds for a reset to succeed. If the device has been connected longer,
//! unplug and reinsert it before running.
//!
//! Usage: cargo run --example device_reset

use fido2_rs::device::DeviceList;
use fido2_rs::error::Error;

const PIN: &str = "1234";

fn main() -> anyhow::Result<()> {
    let mut devices = DeviceList::list_devices(8);
    let dev_info = devices.next().expect("No FIDO2 device found");
    let dev = dev_info.open()?;

    println!("Factory reset (touch device)...");
    dev.reset()?;
    println!("  Reset OK");

    println!("Setting initial PIN to \"{PIN}\"...");
    dev.set_pin(PIN, None)?;
    println!("  PIN set");

    assert!(dev.has_pin(), "has_pin() should be true after set_pin");
    println!("  has_pin() = true");

    println!("Factory reset again (touch device)...");
    dev.reset()?;
    println!("  Reset OK — PIN and all credentials wiped");

    assert!(!dev.has_pin(), "has_pin() should be false after reset");
    println!("  has_pin() = false");

    println!("Trying to change PIN using the old PIN (should fail)...");
    match dev.set_pin("5678", Some(PIN)) {
        Err(Error::Fido(e)) => println!("  Failed as expected: {e}"),
        Ok(()) => panic!("set_pin with old PIN should have failed after reset"),
        Err(e) => panic!("Unexpected error type: {e:?}"),
    }

    println!("\nAll checks passed — old PIN is invalid after reset.");
    Ok(())
}
