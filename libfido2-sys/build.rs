const VERSION: &str = "1.15.0";
const BASE_URL: &str = "https://developers.yubico.com/libfido2/Releases";

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
            println!("cargo:rustc-link-lib=bcrypt");
        }

        cfg_if! {
            if #[cfg(all(windows, target_env = "msvc"))] {
                // link to pre-build cbor,zlib,crypto
                println!("cargo:rustc-link-lib=cbor");
                println!("cargo:rustc-link-lib=zlib1");
                println!("cargo:rustc-link-lib=crypto");
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
            println!("cargo:rustc-link-lib=zlib");
            println!("cargo:rustc-link-lib=bcrypt");
        } else {
            // mingw, linux, and other.
            println!("cargo:rustc-link-lib=cbor");
            println!("cargo:rustc-link-lib=udev");
            println!("cargo:rustc-link-lib=pcsclite");
            println!("cargo:rustc-link-lib=z");
            println!("cargo:rustc-link-lib=crypto");
        }
    }

    Ok(())
}

fn verify_sha256(content: &[u8]) -> bool {
    let sha256 = Sha256::digest(content);

    *sha256 == hex::decode(SHA256).unwrap()
}

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

/// for windows and msvc, use vcpkg to find cbor,zlib,crypto
#[cfg(all(windows, target_env = "msvc"))]
fn build_lib() -> Result<PathBuf> {
    let cbor = vcpkg::find_package("libcbor")?;
    let zlib = vcpkg::find_package("zlib")?;
    let crypto = vcpkg::find_package("openssl")?;
    let crypto_name = crypto
        .found_names
        .iter()
        .find(|it| it.contains("crypto"))
        .context("crypto not found")?;

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir);

    let build_type = if cfg!(debug_assertions) {
        "Debug"
    } else {
        "Release"
    };

    let path = cmake::Config::new(
        out_dir
            .join("libfido2")
            .join(format!("libfido2-{}", VERSION)),
    )
    .define("CMAKE_BUILD_TYPE", build_type)
    .define("BUILD_SHARED_LIBS", "off")
    .define("BUILD_MANPAGES", "off")
    .define("BUILD_EXAMPLES", "off")
    .define("BUILD_TOOLS", "off")
    .define("BUILD_TESTS", "off")
    .define("CBOR_INCLUDE_DIRS", cbor.include_paths.first().unwrap())
    .define("CBOR_LIBRARY_DIRS", cbor.link_paths.first().unwrap())
    .define("ZLIB_INCLUDE_DIRS", zlib.include_paths.first().unwrap())
    .define("ZLIB_LIBRARY_DIRS", zlib.link_paths.first().unwrap())
    .define("CRYPTO_INCLUDE_DIRS", crypto.include_paths.first().unwrap())
    .define("CRYPTO_LIBRARY_DIRS", crypto.link_paths.first().unwrap())
    .define("CRYPTO_LIBRARIES", crypto_name)
    .build();

    println!("cargo:rustc-link-lib=fido2_static");

    Ok(path.join("lib"))
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

    println!("cargo:rustc-link-lib=static=fido2");

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
    println!("cargo:rustc-link-lib=bcrypt");

    Ok(())
}
