const VERSION: &str = "1.15.0";
const BASE_URL: &str = "https://developers.yubico.com/libfido2/Releases";

#[cfg(all(windows, target_env = "msvc"))]
const SHA256: &str = "30f58bff7767983be40084bea5c75a8ef008a42794721ca75d1b73cc5685698c";

#[cfg(not(all(windows, target_env = "msvc")))]
const SHA256: &str = "abaab1318d21d262ece416fb8a7132fa9374bda89f6fa52b86a98a2f5712b61e";

#[cfg(target_env = "msvc")]
extern crate ureq;

#[cfg(not(target_env = "msvc"))]
extern crate pkg_config;

use anyhow::{bail, Context, Result};
use cfg_if::cfg_if;
use sha2::{Digest, Sha256};
use std::env;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    println!("cargo:rerun-if-env-changed=FIDO2_LIB_DIR");
    println!("cargo:rerun-if-env-changed=FIDO2_USE_PKG_CONFIG");

    if let Ok(dir) = env::var("FIDO2_LIB_DIR") {
        println!("cargo:rustc-link-search={}", dir);
        println!("cargo:rustc-link-lib=static=fido2");

        if cfg!(windows) {
            println!("cargo:rustc-link-lib=hid");
            println!("cargo:rustc-link-lib=user32");
            println!("cargo:rustc-link-lib=setupapi");
            println!("cargo:rustc-link-lib=crypt32");
        }

        cfg_if! {
            if #[cfg(all(windows, target_env = "msvc"))] {
                // link to pre-build cbor,zlib,crypto
                println!("cargo:rustc-link-lib=cbor");
                println!("cargo:rustc-link-lib=zlib1");
                println!("cargo:rustc-link-lib=crypto-49");
            } else {
                println!("cargo:rustc-link-lib=cbor");
                println!("cargo:rustc-link-lib=z");
                println!("cargo:rustc-link-lib=crypto");
            }
        }

        return Ok(());
    }

    if env::var("FIDO2_USE_PKG_CONFIG").is_ok() {
        find_pkg()?;

        return Ok(());
    }

    download_src()?;

    let lib_dir = build_lib()?;

    println!("cargo:rustc-link-search={}", lib_dir.display());

    if cfg!(windows) {
        println!("cargo:rustc-link-lib=hid");
        println!("cargo:rustc-link-lib=user32");
        println!("cargo:rustc-link-lib=setupapi");
        println!("cargo:rustc-link-lib=crypt32");
    }

    cfg_if! {
        if #[cfg(all(windows, target_env = "msvc"))] {
            // link to pre-build cbor,zlib,crypto
            println!("cargo:rustc-link-lib=cbor");
            println!("cargo:rustc-link-lib=zlib1");
            println!("cargo:rustc-link-lib=crypto-49");
        } else {
            // mingw, linux, and other.
            println!("cargo:rustc-link-lib=cbor");
            println!("cargo:rustc-link-lib=udev");
            println!("cargo:rustc-link-lib=pcsclite");
            println!("cargo:rustc-link-lib=z");
            println!("cargo:rustc-link-lib=crypto");
        }
    }

    println!("cargo:rustc-link-lib=static=fido2");

    Ok(())
}

fn verify_sha256(content: &[u8]) -> bool {
    let sha256 = Sha256::digest(content);

    *sha256 == hex::decode(SHA256).unwrap()
}

/// for windows and msvc, use pre-build
#[cfg(all(windows, target_env = "msvc"))]
fn download_src() -> Result<()> {
    fn extract_zip(content: &[u8], dst: impl AsRef<Path>) -> Result<()> {
        use zip::ZipArchive;

        let mut zip = ZipArchive::new(Cursor::new(content))?;
        zip.extract(dst)?;

        Ok(())
    }

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);
    let filename = format!("libfido2-{VERSION}-win.zip");
    let out_path = out_dir.join(&filename);

    let mut archive_bin = Vec::new();

    if out_path.exists() {
        let archive = std::fs::read(&out_path).context("read exist archive failed")?;

        if verify_sha256(&archive) {
            extract_zip(&archive, out_dir.join("libfido2"))?;
            return Ok(());
        } else {
            std::fs::remove_file(&out_path).context("unable delete old file")?;
        }
    }

    let response = ureq::get(&format!("{}/{}", BASE_URL, filename))
        .call()
        .context("unable download fido2 release")?;
    response
        .into_reader()
        .read_to_end(&mut archive_bin)
        .context("read stream failed")?;
    std::fs::write(out_path, &archive_bin).context("write file failed")?;

    if !verify_sha256(&archive_bin) {
        bail!("verify down  load {} failed", filename);
    }

    extract_zip(&archive_bin, out_dir.join("libfido2"))?;

    Ok(())
}

/// for windows and msvc, build nothing
#[cfg(all(windows, target_env = "msvc"))]
fn build_lib() -> Result<PathBuf> {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir).join("libfido2");

    let dir = out_dir.join(format!("libfido2-{VERSION}-win"));
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    let arch_dir = match &*arch {
        "x86" => "Win32",
        "x86_64" => "Win64",
        "arm" => "ARM",
        "aarch64" => "ARM64",
        _ => panic!("unsupported arch"),
    };

    let lib_dir = dir.join(arch_dir).join("Release");
    let vc_dir = std::fs::read_dir(&lib_dir)?
        .next()
        .context("no vc dir found")??;
    let lib_dir = lib_dir.join(vc_dir.path()).join("static");

    Ok(lib_dir)
}

/// for other, mingw or linux, download source.
#[cfg(not(target_env = "msvc"))]
fn download_src() -> Result<()> {
    fn extract_tar(content: &[u8], dst: impl AsRef<Path>) -> Result<()> {
        let gz = flate2::read::GzDecoder::new(Cursor::new(content));
        let mut tar = tar::Archive::new(gz);

        tar.unpack(dst)?;

        Ok(())
    }

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);
    let filename = format!("libfido2-{VERSION}.tar.gz");
    let out_path = out_dir.join(&filename);

    if out_path.exists() {
        let archive = std::fs::read(&out_path).context("read exist archive failed")?;

        if verify_sha256(&archive) {
            extract_tar(&archive, out_dir.join("libfido2"))?;

            return Ok(());
        } else {
            std::fs::remove_file(&out_path).context("unable delete old file")?;
        }
    }

    let mut archive_bin = Vec::new();

    let response = ureq::get(&format!("{}/{}", BASE_URL, filename))
        .call()
        .context("unable download fido2 release")?;
    response
        .into_reader()
        .read_to_end(&mut archive_bin)
        .context("read stream failed")?;

    std::fs::write(out_path, &archive_bin).context("write file failed")?;

    if !verify_sha256(&archive_bin) {
        bail!("verify download {} failed", filename);
    }

    extract_tar(&archive_bin, out_dir.join("libfido2"))?;

    Ok(())
}

/// for other, mingw or linux, use cmake to build
#[cfg(not(target_env = "msvc"))]
fn build_lib() -> Result<PathBuf> {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);

    let path = cmake::Config::new(
        out_dir
            .join("libfido2")
            .join(format!("libfido2-{}", VERSION)),
    )
    .define("BUILD_MANPAGES", "off")
    .define("BUILD_EXAMPLES", "off")
    .define("BUILD_TOOLS", "off")
    .define("NFC_LINUX", "on")
    .define("USE_PCSC", "on")
    .build();

    Ok(path.join("lib"))
}

#[cfg(not(target_env = "msvc"))]
fn find_pkg() -> Result<()> {
    let _lib = pkg_config::probe_library("libfido2")?;

    Ok(())
}

#[cfg(all(windows, target_env = "msvc"))]
fn find_pkg() -> Result<()> {
    let _lib = vcpkg::find_package("libfido2")?;

    println!("cargo:rustc-link-lib=hid");
    println!("cargo:rustc-link-lib=user32");
    println!("cargo:rustc-link-lib=setupapi");
    println!("cargo:rustc-link-lib=crypt32");

    Ok(())
}
