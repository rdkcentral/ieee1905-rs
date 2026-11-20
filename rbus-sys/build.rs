use anyhow::{Context, bail, ensure};
use bindgen::EnumVariation;
use quote::quote;
use std::env;
use std::path::{Path, PathBuf};

const HEADERS: &[&str] = &[
    "rbus.h",
    "rbus_buffer.h",
    "rbus_filter.h",
    "rbus_object.h",
    "rbus_property.h",
    "rbus_value.h",
];

fn main() -> anyhow::Result<()> {
    for variable in ["RBUS_DIR", "RBUS_INCLUDE_DIR", "RBUS_LIB_DIR"] {
        println!("cargo::rerun-if-env-changed={variable}");
    }

    let target_triple = env::var("TARGET")?;
    let linked = env::var_os("CARGO_FEATURE_LINKED").is_some();
    let prefix = env_path("RBUS_DIR")?;
    let include_dir = env_path("RBUS_INCLUDE_DIR")?
        .or_else(|| prefix.as_ref().map(|dir| dir.join("include/rbus")))
        .or_else(|| {
            (!linked).then(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("c_src/include"))
        });

    let mut builder = bindgen::Builder::default()
        .clang_arg(format!("--target={target_triple}"))
        .allowlist_function("rbus.*")
        .default_enum_style(EnumVariation::NewType {
            is_bitfield: false,
            is_global: false,
        })
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    if let Some(dir) = include_dir {
        let dir = checked_dir(&dir, "RBus include directory")?;
        builder = builder.clang_arg(format!("-I{}", dir.display()));
        for header in HEADERS {
            let path = dir.join(header);
            ensure!(path.is_file(), "RBus header not found: {}", path.display());
            builder = builder.header(path.to_string_lossy());
        }
    } else {
        // Without an explicit prefix, use the toolchain's include search paths.
        // In linked mode we must not fall back to the bundled headers.
        let includes = HEADERS
            .iter()
            .map(|header| format!("#include <rbus/{header}>\n"))
            .collect::<String>();
        builder = builder.header_contents("rbus-wrapper.h", &includes);
    }

    if linked {
        let lib_dir =
            env_path("RBUS_LIB_DIR")?.or_else(|| prefix.as_ref().map(|dir| dir.join("lib")));
        if let Some(dir) = lib_dir {
            let dir = checked_dir(&dir, "RBus library directory")?;
            ensure!(
                dir.join("librbus.so").is_file(),
                "RBus shared library not found: {}",
                dir.join("librbus.so").display()
            );
            println!("cargo::rustc-link-search=native={}", dir.display());
        }
        println!("cargo::rustc-link-lib=dylib=rbus");
    } else {
        builder = builder
            .dynamic_library_name("RBusLibraryRaw")
            .dynamic_link_require_all(true);
    }

    let bindings = builder.generate()?;
    let mut source = bindings.to_string();
    if linked {
        source.push_str(&linked_api(&source)?);
    }
    let out_path = PathBuf::from(env::var("OUT_DIR")?);
    std::fs::write(out_path.join("bindings.rs"), source)?;
    Ok(())
}

fn env_path(name: &str) -> anyhow::Result<Option<PathBuf>> {
    env::var_os(name)
        .map(|value| {
            ensure!(!value.is_empty(), "{name} must not be empty");
            Ok(PathBuf::from(value))
        })
        .transpose()
}

fn checked_dir(path: &Path, description: &str) -> anyhow::Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("{description} not found: {}", path.display()))?;
    ensure!(
        path.is_dir(),
        "{description} is not a directory: {}",
        path.display()
    );
    Ok(path)
}

/// Preserve the method API used by rbus-core without duplicating C signatures.
fn linked_api(bindings: &str) -> anyhow::Result<String> {
    let bindings = syn::parse_file(bindings)?;
    let mut methods = Vec::new();
    for item in bindings.items {
        let syn::Item::ForeignMod(block) = item else {
            continue;
        };
        for item in block.items {
            let syn::ForeignItem::Fn(function) = item else {
                continue;
            };
            // Like bindgen's dlopen backend, do not generate methods for variadic
            // functions: stable Rust cannot forward arbitrary C varargs.
            if function.sig.variadic.is_some() {
                continue;
            }
            let name = &function.sig.ident;
            let inputs = &function.sig.inputs;
            let output = &function.sig.output;
            let mut arguments = Vec::new();
            for input in inputs {
                let syn::FnArg::Typed(argument) = input else {
                    bail!("unexpected receiver in RBus function {name}");
                };
                let syn::Pat::Ident(argument) = argument.pat.as_ref() else {
                    bail!("unexpected argument pattern in RBus function {name}");
                };
                arguments.push(&argument.ident);
            }
            let docs = function
                .attrs
                .iter()
                .filter(|attr| attr.path().is_ident("doc"));
            methods.push(quote! {
                #(#docs)*
                #[inline]
                pub unsafe fn #name(&self, #inputs) #output {
                    unsafe { #name(#(#arguments),*) }
                }
            });
        }
    }
    Ok(quote! {
        pub struct RBusLibraryRaw;
        impl RBusLibraryRaw {
            #(#methods)*
        }
    }
    .to_string())
}
