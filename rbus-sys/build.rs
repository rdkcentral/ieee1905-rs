use anyhow::anyhow;
use bindgen::EnumVariation;
use std::path::{Path, PathBuf};

const RBUS_DIR: &str = "./c_src";

///
/// Cross-compilation toolchains for macOS:
/// https://github.com/messense/homebrew-macos-cross-toolchains
///
fn main() -> anyhow::Result<()> {
    let bundled = std::env::var("CARGO_FEATURE_BUNDLED").is_ok();
    let host_triple = std::env::var("HOST")?;
    let target_os = std::env::var("CARGO_CFG_TARGET_OS")?;
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH")?;
    let target = format!("{target_os}-{target_arch}");

    let base_dir = Path::new(RBUS_DIR).canonicalize();
    let base_dir = base_dir.map_err(|e| anyhow!("path {RBUS_DIR} not found: {e:?}"))?;

    let lib_dir = PathBuf::from(format!("{}/lib/{target}", base_dir.display()));
    let lib_dir = lib_dir.to_string_lossy();

    let include_dir = PathBuf::from(format!("{}/include", base_dir.display()));
    let include_dir = include_dir.to_string_lossy();

    println!("cargo:rustc-link-lib=dylib=rbus");
    if bundled {
        println!("cargo:rustc-link-search=native={lib_dir}");
    }

    let bindings = bindgen::Builder::default()
        .clang_arg(format!("--target={host_triple}"))
        .headers([
            format!("{include_dir}/rbus.h"),
            format!("{include_dir}/rbus_buffer.h"),
            format!("{include_dir}/rbus_filter.h"),
            format!("{include_dir}/rbus_object.h"),
            format!("{include_dir}/rbus_property.h"),
            format!("{include_dir}/rbus_value.h"),
        ])
        .allowlist_function("rbus.*")
        .default_enum_style(EnumVariation::NewType {
            is_bitfield: false,
            is_global: false,
        })
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()?;

    let out_path = PathBuf::from(std::env::var("OUT_DIR")?);
    bindings.write_to_file(out_path.join("bindings.rs"))?;

    Ok(())
}
