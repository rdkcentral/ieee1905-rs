#!/usr/bin/env python3
"""Exercise the real build script and both loaders using a temporary C library.

Run on Linux with Python 3, Cargo, libclang, cc and readelf installed:
    python3 rbus-sys/tests/link_modes.py
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


class LinkModes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="rbus link tests ")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.prefix = cls.root / "sdk"
        cls.include = cls.prefix / "include/rbus"
        cls.lib = cls.prefix / "lib"
        cls.include.mkdir(parents=True)
        cls.lib.mkdir()
        (cls.include / "rbus.h").write_text(
            "#pragma once\n"
            "typedef enum { RBUS_DISABLED, RBUS_ENABLED } rbusStatus_t;\n"
            "rbusStatus_t rbus_checkStatus(void);\n"
            "int rbusTest_Add(int left, int right);\n"
            "int rbusTest_Apply(int (*callback)(int), int value);\n"
            "void rbusTest_Variadic(int count, ...);\n"
        )
        for name in ["buffer", "filter", "object", "property", "value"]:
            (cls.include / f"rbus_{name}.h").write_text('#include "rbus.h"\n')
        source = cls.root / "rbus.c"
        source.write_text(
            '#include "rbus.h"\n'
            "rbusStatus_t rbus_checkStatus(void) { return RBUS_ENABLED; }\n"
            "int rbusTest_Add(int left, int right) { return left + right; }\n"
            "int rbusTest_Apply(int (*callback)(int), int value) { return callback(value); }\n"
            "void rbusTest_Variadic(int count, ...) { (void)count; }\n"
        )
        subprocess.run(
            ["cc", "-shared", "-fPIC", "-Wl,-soname,librbus.so.0",
             "-I", str(cls.include), str(source), "-o", str(cls.lib / "librbus.so")],
            check=True, capture_output=True, text=True,
        )
        (cls.lib / "librbus.so.0").symlink_to("librbus.so")

        crate = Path(__file__).resolve().parents[1]
        cls.project = cls.root / "probe"
        (cls.project / "src").mkdir(parents=True)
        (cls.project / "Cargo.toml").write_text(
            '[package]\nname = "rbus-link-probe"\nversion = "0.0.0"\nedition = "2024"\n'
            '[workspace]\n[features]\nlinked = ["rbus-sys/linked"]\n'
            f'[dependencies]\nrbus-sys = {{ path = "{crate}" }}\n'
        )
        (cls.project / "src/main.rs").write_text(
            'unsafe extern "C" fn double(value: i32) -> i32 { value * 2 }\n'
            "fn main() {\n"
            "    let library = unsafe { rbus_sys::RBusLibraryRaw::load() }.unwrap();\n"
            "    unsafe {\n"
            "        assert_eq!(library.rbus_checkStatus(), rbus_sys::rbusStatus_t::RBUS_ENABLED);\n"
            "        assert_eq!(library.rbusTest_Add(19, 23), 42);\n"
            "        assert_eq!(library.rbusTest_Apply(Some(double), 21), 42);\n"
            "    }\n"
            "}\n"
        )

    def build(self, *, linked=False, expected_error=None, **variables):
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("RBUS_", "BINDGEN_EXTRA_CLANG_ARGS", "CARGO_TARGET_"))
            and key not in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET")
        }
        environment.update(variables)
        command = ["cargo", "build", "--offline", "--manifest-path",
                   str(self.project / "Cargo.toml"), "--target-dir", str(self.root / "target")]
        if linked:
            command.extend(["--features", "linked"])
        result = subprocess.run(command, env=environment, capture_output=True, text=True)
        if expected_error:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(expected_error, result.stderr)
            return
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        executable = self.root / "target/debug/rbus-link-probe"
        environment["LD_LIBRARY_PATH"] = str(self.lib)
        subprocess.run([str(executable)], env=environment, check=True, capture_output=True)
        dynamic = subprocess.run(
            ["readelf", "-d", str(executable)], check=True, capture_output=True, text=True,
        ).stdout
        self.assertEqual("Shared library: [librbus.so.0]" in dynamic, linked)
        self.assertNotIn(str(self.prefix), dynamic)

    def test_runtime_loading_ignores_library_directory(self):
        self.build(RBUS_DIR=str(self.prefix), RBUS_LIB_DIR=str(self.root / "missing"))

    def test_linked_prefix(self):
        self.build(linked=True, RBUS_DIR=str(self.prefix))

    def test_specific_paths_override_prefix_in_both_modes(self):
        for linked in (False, True):
            with self.subTest(linked=linked):
                self.build(
                    linked=linked, RBUS_DIR=str(self.root / "missing"),
                    RBUS_INCLUDE_DIR=str(self.include), RBUS_LIB_DIR=str(self.lib),
                )

    def test_linked_toolchain_search_paths(self):
        self.build(
            linked=True,
            BINDGEN_EXTRA_CLANG_ARGS=shlex.quote(f"-I{self.include.parent}"),
            LIBRARY_PATH=str(self.lib),
        )

    def test_invalid_include_does_not_fall_back(self):
        for linked in (False, True):
            with self.subTest(linked=linked):
                self.build(
                    linked=linked, RBUS_DIR=str(self.prefix),
                    RBUS_INCLUDE_DIR=str(self.root / "missing"),
                    expected_error="RBus include directory not found",
                )

    def test_missing_header_does_not_fall_back(self):
        empty = self.root / "empty-include"
        empty.mkdir(exist_ok=True)
        self.build(RBUS_INCLUDE_DIR=str(empty), expected_error="RBus header not found")

    def test_invalid_library_directory(self):
        self.build(
            linked=True, RBUS_DIR=str(self.prefix),
            RBUS_LIB_DIR=str(self.root / "missing"),
            expected_error="RBus library directory not found",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
