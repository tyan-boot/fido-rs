use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use cfg_if::cfg_if;

pub fn source_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("libfido2")
}

fn main() -> Result<()> {
    println!("cargo:rerun-if-env-changed=FIDO2_LIB_DIR");

    // Warn if features that only work with vendored are enabled without it
    #[cfg(not(feature = "vendored"))]
    {
        #[cfg(feature = "nfc")]
        println!("cargo:warning=Feature 'nfc' has no effect without 'vendored' feature");
        #[cfg(feature = "pcsc")]
        println!("cargo:warning=Feature 'pcsc' has no effect without 'vendored' feature");
        #[cfg(feature = "hidapi")]
        println!("cargo:warning=Feature 'hidapi' has no effect without 'vendored' feature");
        #[cfg(feature = "win-hello")]
        println!("cargo:warning=Feature 'win-hello' has no effect without 'vendored' feature");
    }

    // Priority 1: Use pre-built library if FIDO2_LIB_DIR is set
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

    // Priority 2: Build from source if vendored feature is enabled
    #[cfg(feature = "vendored")]
    {
        if env::var("FIDO2_NO_VENDOR").map_or(true, |s| s == "0") {
            return build();
        }
    }

    // Priority 3: Find and link system-installed libfido2
    find_pkg()?;

    Ok(())
}

#[cfg(feature = "vendored")]
fn configure_cbor(config: &mut cmake::Config) -> Result<()> {
    if let (Ok(include_dir), Ok(library_dir)) =
        (env::var("CBOR_INCLUDE_DIR"), env::var("CBOR_LIBRARY_DIR"))
    {
        let include_path = PathBuf::from(include_dir);
        let link_path = PathBuf::from(library_dir);

        config
            .define("CBOR_INCLUDE_DIRS", &include_path)
            .define("CBOR_LIBRARY_DIRS", &link_path);
        println!("cargo:rustc-link-search={}", link_path.display());

        return Ok(());
    }

    cfg_if! {
        if #[cfg(windows)] {
            let pkg = vcpkg::find_package("libcbor")
                .context("Failed to locate libcbor via vcpkg. Consider installing it with vcpkg or setting CBOR_INCLUDE_DIR/CBOR_LIBRARY_DIR")?;

            let include_path = pkg
                .include_paths
                .first()
                .context("No include paths found for libcbor")?
                .clone();
            let link_path = pkg
                .link_paths
                .first()
                .context("No link paths found for libcbor")?
                .clone();

            config
                .define("CBOR_INCLUDE_DIRS", &include_path)
                .define("CBOR_LIBRARY_DIRS", &link_path);
            println!("cargo:rustc-link-search={}", link_path.display());
            Ok(())
        } else if #[cfg(any(target_os = "linux", target_os = "macos"))] {
            let lib = pkg_config::Config::new()
                .probe("libcbor")
                .context("Failed to locate libcbor via pkg-config. Consider installing it or setting CBOR_INCLUDE_DIR/CBOR_LIBRARY_DIR")?;

            let include_path = lib
                .include_paths
                .first()
                .context("No include paths found for libcbor")?
                .clone();
            let link_path = lib
                .link_paths
                .first()
                .context("No link paths found for libcbor")?
                .clone();

            config
                .define("CBOR_INCLUDE_DIRS", &include_path)
                .define("CBOR_LIBRARY_DIRS", &link_path);
            println!("cargo:rustc-link-search={}", link_path.display());
            Ok(())
        } else {
            anyhow::bail!("Unsupported target for libcbor discovery");
        }
    }
}

#[cfg(feature = "vendored")]
fn configure_zlib(config: &mut cmake::Config) -> Result<()> {
    if let Ok(z_root) = env::var("DEP_Z_ROOT") {
        let include_path = env::var("DEP_Z_INCLUDE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(&z_root).join("include"));
        let link_path = PathBuf::from(&z_root).join("lib");

        config
            .define("ZLIB_INCLUDE_DIRS", include_path)
            .define("ZLIB_LIBRARY_DIRS", link_path);
        return Ok(());
    }

    cfg_if! {
        if #[cfg(windows)] {
            let pkg = vcpkg::Config::new()
                .cargo_metadata(false)
                .copy_dlls(false)
                .find_package("zlib")
                .context("Failed to locate zlib via vcpkg. Set DEP_Z_ROOT or install zlib")?;

            let include_path = pkg
                .include_paths
                .first()
                .context("No include paths found for zlib")?
                .clone();
            let link_path = pkg
                .link_paths
                .first()
                .context("No link paths found for zlib")?
                .clone();

            config
                .define("ZLIB_INCLUDE_DIRS", include_path)
                .define("ZLIB_LIBRARY_DIRS", link_path);
            Ok(())
        } else if #[cfg(any(target_os = "linux", target_os = "macos"))] {
            let lib = pkg_config::Config::new()
                .cargo_metadata(false)
                .probe("zlib")
                .context("Failed to locate zlib via pkg-config. Set DEP_Z_ROOT or install zlib")?;

            let include_path = lib
                .include_paths
                .first()
                .context("No include paths found for zlib")?
                .clone();
            let link_path = lib
                .link_paths
                .first()
                .context("No link paths found for zlib")?
                .clone();

            config
                .define("ZLIB_INCLUDE_DIRS", include_path)
                .define("ZLIB_LIBRARY_DIRS", link_path);
            Ok(())
        } else {
            anyhow::bail!("Unsupported target for zlib discovery");
        }
    }
}

#[cfg(feature = "vendored")]
fn configure_crypto(config: &mut cmake::Config) -> Result<()> {
    if let (Ok(include_dir), Ok(library_dir)) = (
        env::var("CRYPTO_INCLUDE_DIRS"),
        env::var("CRYPTO_LIBRARY_DIRS"),
    ) {
        println!("cargo:rerun-if-env-changed=CRYPTO_INCLUDE_DIRS");
        println!("cargo:rerun-if-env-changed=CRYPTO_LIBRARY_DIRS");
        println!("cargo:rerun-if-env-changed=CRYPTO_LIBRARIES");

        let include_path = PathBuf::from(include_dir);
        let link_path = PathBuf::from(library_dir);
        config
            .define("CRYPTO_INCLUDE_DIRS", &include_path)
            .define("CRYPTO_LIBRARY_DIRS", &link_path);
        if let Ok(libs) = env::var("CRYPTO_LIBRARIES") {
            config.define("CRYPTO_LIBRARIES", libs);
        } else {
            config.define("CRYPTO_LIBRARIES", "crypto");
        }
        println!("cargo:rustc-link-search={}", link_path.display());
        return Ok(());
    }

    if let Ok(root) = env::var("DEP_OPENSSL_ROOT") {
        println!("cargo:rerun-if-env-changed=DEP_OPENSSL_ROOT");
        println!("cargo:rerun-if-env-changed=DEP_OPENSSL_INCLUDE");
        println!("cargo:rerun-if-env-changed=DEP_OPENSSL_LIB");
        println!("cargo:rerun-if-env-changed=DEP_OPENSSL_LIBDIR");

        let root = PathBuf::from(root);
        let include_path = env::var("DEP_OPENSSL_INCLUDE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| root.join("include"));

        let link_path = env::var("DEP_OPENSSL_LIB")
            .or_else(|_| env::var("DEP_OPENSSL_LIBDIR"))
            .map(PathBuf::from)
            .ok()
            .or_else(|| {
                [root.join("lib64"), root.join("lib")]
                    .into_iter()
                    .find(|p| p.exists())
            })
            .unwrap_or_else(|| root.join("lib"));

        config
            .define("CRYPTO_INCLUDE_DIRS", &include_path)
            .define("CRYPTO_LIBRARY_DIRS", &link_path)
            .define("CRYPTO_LIBRARIES", "crypto");
        println!("cargo:rustc-link-search={}", link_path.display());

        return Ok(());
    }

    cfg_if! {
        if #[cfg(windows)] {
            let pkg = vcpkg::find_package("openssl")
                .context("Failed to locate OpenSSL via vcpkg. Set CRYPTO_INCLUDE_DIRS/CRYPTO_LIBRARY_DIRS or DEP_OPENSSL_ROOT")?;

            let include_path = pkg
                .include_paths
                .first()
                .context("No include paths found for openssl")?
                .clone();
            let link_path = pkg
                .link_paths
                .first()
                .context("No link paths found for openssl")?
                .clone();

            config
                .define("CRYPTO_INCLUDE_DIRS", &include_path)
                .define("CRYPTO_LIBRARY_DIRS", &link_path);

            if let Some(crypto_lib) = pkg.found_names.iter().find(|it| it.contains("crypto")) {
                config.define("CRYPTO_LIBRARIES", crypto_lib);
            } else {
                config.define("CRYPTO_LIBRARIES", "crypto");
            }
            println!("cargo:rustc-link-search={}", link_path.display());
            Ok(())
        } else if #[cfg(any(target_os = "linux", target_os = "macos"))] {
            let lib = pkg_config::Config::new()
                .cargo_metadata(false)
                .probe("libcrypto")
                .context("Failed to locate OpenSSL (libcrypto) via pkg-config. Set CRYPTO_INCLUDE_DIRS/CRYPTO_LIBRARY_DIRS or DEP_OPENSSL_ROOT")?;

            let include_path = lib
                .include_paths
                .first()
                .context("No include paths found for libcrypto")?
                .clone();
            let link_path = lib
                .link_paths
                .first()
                .context("No library paths found for libcrypto")?
                .clone();

            config
                .define("CRYPTO_INCLUDE_DIRS", include_path)
                .define("CRYPTO_LIBRARY_DIRS", &link_path)
                .define("CRYPTO_LIBRARIES", lib.libs.join(";"));
            println!("cargo:rustc-link-search={}", link_path.display());
            Ok(())
        } else {
            anyhow::bail!("Unsupported target for OpenSSL discovery");
        }
    }
}

#[cfg(feature = "vendored")]
fn build() -> Result<()> {
    let build_type = if cfg!(debug_assertions) {
        "Debug"
    } else {
        "Release"
    };

    let mut config = cmake::Config::new(source_dir());
    config
        .define("CMAKE_BUILD_TYPE", build_type)
        .define("BUILD_SHARED_LIBS", "off")
        .define("BUILD_STATIC_LIBS", "on")
        .define("BUILD_MANPAGES", "off")
        .define("BUILD_EXAMPLES", "off")
        .define("BUILD_TOOLS", "off")
        .define("BUILD_TESTS", "off")
        .define("FUZZ", "off");

    configure_cbor(&mut config)?;
    configure_zlib(&mut config)?;
    configure_crypto(&mut config)?;

    if cfg!(feature = "nfc") && cfg!(target_os = "linux") {
        config.define("NFC_LINUX", "on");
    } else {
        config.define("NFC_LINUX", "off");
    }

    if cfg!(feature = "pcsc") {
        config.define("USE_PCSC", "on");
    } else {
        config.define("USE_PCSC", "off");
    }

    if cfg!(feature = "hidapi") {
        config.define("USE_HIDAPI", "on");
    } else {
        config.define("USE_HIDAPI", "off");
    }

    if cfg!(feature = "win-hello") && cfg!(windows) {
        config.define("USE_WINHELLO", "on");
    } else {
        config.define("USE_WINHELLO", "off");
    }

    let out = config.build();
    println!("cargo:rustc-link-search={}", out.join("lib").display());
    println!("cargo:rustc-link-search={}", out.join("lib64").display());

    if cfg!(windows) {
        println!("cargo:rustc-link-lib=fido2_static");

        println!("cargo:rustc-link-lib=hid");
        println!("cargo:rustc-link-lib=user32");
        println!("cargo:rustc-link-lib=setupapi");
    } else {
        println!("cargo:rustc-link-lib=static=fido2");
    }

    cfg_if! {
        if #[cfg(all(windows, target_env = "msvc"))] {
            // link to pre-build cbor,zlib,crypto
            println!("cargo:rustc-link-lib=cbor");
            println!("cargo:rustc-link-lib=bcrypt");
        } else {
            // mingw, linux, and other.
            println!("cargo:rustc-link-lib=cbor");
            #[cfg(target_os = "linux")]
            {
                println!("cargo:rustc-link-lib=udev");
            }
            if cfg!(feature = "pcsc") {
                println!("cargo:rustc-link-lib=pcsclite");
            }
        }
    }

    Ok(())
}

#[cfg(not(target_env = "msvc"))]
fn find_pkg() -> Result<()> {
    let _lib = pkg_config::probe_library("libfido2").context("Could not find libfido2 package")?;

    Ok(())
}

#[cfg(all(windows, target_env = "msvc"))]
fn find_pkg() -> Result<()> {
    let _lib = vcpkg::find_package("libfido2").context("Could not find libfido2 package")?;

    println!("cargo:rustc-link-lib=hid");
    println!("cargo:rustc-link-lib=user32");
    println!("cargo:rustc-link-lib=setupapi");
    println!("cargo:rustc-link-lib=bcrypt");

    Ok(())
}
