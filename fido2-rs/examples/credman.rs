use fido2_rs::device::DeviceList;

use anyhow::Result;

const PIN: &str = "123456";

fn main() -> Result<()> {
    let dev_list = DeviceList::list_devices(16);
    for dev_info in dev_list {
        println!("device path: {}", dev_info.path.to_str()?);
        println!("manufacturer: {}", dev_info.manufacturer.to_str()?);

        let dev = dev_info.open()?;
        let support = dev.supports_credman();
        println!("  credman: {}", support);
        if !support {
            continue;
        }

        let credman = dev.credman(PIN)?;
        println!("  cred count: {}", credman.count());

        for rp in credman.get_rp()? {
            println!("  rp: {:?}", rp);
            let rk = credman.get_rk(rp.id)?;

            for idx in 0..rk.count() {
                let rk = &rk[idx];
                println!("    {:?} {:?}", rk.user_name(), rk.display_name());
            }
        }
    }

    Ok(())
}
