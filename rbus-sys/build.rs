use anyhow::anyhow;
use bindgen::EnumVariation;
use std::path::{Path, PathBuf};

const RBUS_DIR: &str = "./c_src";

///
/// Cross-compilation toolchains for macOS:
/// https://github.com/messense/homebrew-macos-cross-toolchains
///
fn main() -> anyhow::Result<()> {
    let host_triple = std::env::var("HOST")?;

    let base_dir = Path::new(RBUS_DIR).canonicalize();
    let base_dir = base_dir.map_err(|e| anyhow!("path {RBUS_DIR} not found: {e:?}"))?;

    let include_dir = PathBuf::from(format!("{}/include", base_dir.display()));
    let include_dir = include_dir.to_string_lossy();

    let bindings = bindgen::Builder::default()
        .clang_arg(format!("--target={host_triple}"))
        .dynamic_library_name("RBusLibraryRaw")
        .dynamic_link_require_all(true)
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
