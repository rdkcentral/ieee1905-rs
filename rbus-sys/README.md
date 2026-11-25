# RBus bindings

`rbus-sys` generates low-level Rust bindings to the RBus C API using bindgen.
Building requires libclang. The headers and the library used at runtime must have
compatible ABIs.

## Link modes

By default, `RBusLibraryRaw::load()` loads `librbus.so.0`, falling back to
`librbus.so` if the first library cannot be opened. Bindings are generated from
the bundled headers unless an explicit include path is configured. This mode
does not require RBus to be installed during compilation.

The `linked` feature selects classic linking against the SDK or system shared
library instead. From this crate's directory:

```shell
RBUS_DIR=/path/to/sdk/sysroot/usr cargo build --features linked
```

This mode requires the linker file `librbus.so` during compilation and a
compatible shared library when the consuming executable starts.

`rbus-core` and `rbus-provider` forward their `linked` feature to `rbus-sys`.
Cargo features are additive: enabling `linked` through any dependency selects
classic linking for the shared `rbus-sys` dependency.

## Build-time paths

Paths are configured independently of the link mode:

| Variable | Meaning | Default |
| --- | --- | --- |
| `RBUS_DIR` | Installation prefix containing `include/rbus/` and `lib/` | Unset |
| `RBUS_INCLUDE_DIR` | Directory directly containing `rbus.h` and the other RBus headers | `$RBUS_DIR/include/rbus` when a prefix is set |
| `RBUS_LIB_DIR` | Directory containing the linker file `librbus.so` | `$RBUS_DIR/lib` when a prefix is set |

`RBUS_INCLUDE_DIR` and `RBUS_LIB_DIR` override the corresponding prefix paths.
For example, an SDK with libraries in `lib64` can use:

```shell
RBUS_DIR=/path/to/sdk/sysroot/usr \
RBUS_LIB_DIR=/path/to/sdk/sysroot/usr/lib64 \
    cargo build --features linked
```

Explicit include paths apply to both modes and must contain all required headers;
invalid paths fail the build rather than falling back to the bundled headers.
Without an include path, linked mode looks for `rbus/rbus.h` and the other
`rbus/` headers in the toolchain's header search paths, such as `/usr/include`.
For headers installed directly in `include/`, set `RBUS_INCLUDE_DIR` to that
directory instead.
Without a library path, it uses the toolchain's library search paths.
`RBUS_LIB_DIR` is ignored in runtime-loading mode.

SDK paths are not embedded as runtime search paths. Runtime loading uses the
library names on the target and never searches the SDK's build-machine directory.

## Cross-compilation

Bindgen interprets headers for Cargo's `TARGET` architecture. Configure the SDK
linker through Cargo and supply the SDK sysroot and any additional C preprocessor
flags to bindgen via `BINDGEN_EXTRA_CLANG_ARGS`.

`RBUS_DIR` is an RBus installation prefix, not a replacement for the toolchain's
sysroot configuration.
