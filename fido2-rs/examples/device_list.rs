use fido2_rs::device::DeviceList;

fn main() -> anyhow::Result<()> {
    let devices = DeviceList::list_devices(16);
    for dev_info in devices {
        let dev = dev_info.open()?;

        let info = dev.info()?;
        for ver in info.versions() {
            println!("Version: {}", ver);
        }
    }

    Ok(())
}
