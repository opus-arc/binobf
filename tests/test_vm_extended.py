"""Fixed machine-word corpus: host execution of generated native VM runtime.

These are newly authored u32 functions compiled once with LLVM 19.1 for
AArch64 Mach-O. Tests consume their machine words and require no LLVM install.
They do not claim that host execution replaces the macOS native CI gate.
"""
import ctypes
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from binobf.vm import FunctionSpec, generate_c, native_remap


FIXTURES = {
    "mix32": "0900014a28378f52291d8913e8c6b3722901000b2001084ac0035fd6",
    "pick32": "08440011295c00511f00016b0801014a2901004a0031891ac0035fd6",
    "step32": "a8c18c52e96b9e522803a072c98da7720804081b0801090b0041484ac0035fd6",
    "add_over": "1f00012b0020811ac0035fd6",
    "sub_signed_over": "1f00016b0060811ac0035fd6",
    "var_asr": "0028c11ac0035fd6",
    "var_ror": "002cc11ac0035fd6",
    "bitinsert": "201c1033c0035fd6",
    "signextract": "20380713c0035fd6",
    "logicmask": "089c001229f001520001092ac0035fd6",
    "multiplysub": "a8c18c522803a0720084081bc0035fd6",
}
MASK = (1 << 32) - 1


def signed(x):
    return x if x < (1 << 31) else x - (1 << 32)


def reference(name, x, y):
    if name == "mix32":
        z = x ^ y
        return ((((z >> 7) | ((z & 127) << 25)) + x) & MASK) ^ 2654435769
    if name == "pick32":
        return (((x + 17) & MASK) ^ y) if x < y else (((y - 23) & MASK) ^ x)
    if name == "step32":
        z = (1664525 * x + y + 1013904223) & MASK
        return z ^ (z >> 16)
    if name == "add_over":
        return x if x + y > MASK else y
    if name == "sub_signed_over":
        return x if not -(1 << 31) <= signed(x) - signed(y) < (1 << 31) else y
    if name == "var_asr":
        return (signed(x) >> (y & 31)) & MASK
    if name == "var_ror":
        n = y & 31
        return ((x >> n) | (x << ((32 - n) & 31))) & MASK
    if name == "bitinsert":
        return (x & ~0xFF0000) | ((y & 255) << 16)
    if name == "signextract":
        return (signed((y << 17) & MASK) >> 24) & MASK
    if name == "logicmask":
        return (x & 0xFF00FF) | (y ^ 0xAAAAAAAA)
    if name == "multiplysub":
        return (y - x * 1664525) & MASK
    raise AssertionError(name)


@unittest.skipUnless(shutil.which("cc"), "host C compiler required")
class ExtendedNativeVmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="binobf-vm-extended-")
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        specs = []
        for name, code_hex in FIXTURES.items():
            spec = FunctionSpec(name, bytes.fromhex(code_hex))
            changed, _ = native_remap(spec, seed=7331)
            specs.extend((spec, FunctionSpec(name + "_remapped", changed)))
        # A public symbol containing the generator's old placeholder must retain
        # its exact name; rewriting it silently would break the linker ABI.
        specs.append(FunctionSpec("exampleBNO_symbol", bytes.fromhex("c0035fd6")))
        generated = generate_c(specs, seed=77)
        cls.source = generated.source
        path = root / "runtime.c"
        path.write_text(generated.source, encoding="utf-8")
        library = root / ("runtime.dylib" if sys.platform == "darwin" else "runtime.so")
        shared = "-dynamiclib" if sys.platform == "darwin" else "-shared"
        subprocess.run([shutil.which("cc"), "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-fPIC", shared, str(path), "-o", str(library)], check=True,
                       capture_output=True, text=True)
        cls.library = ctypes.CDLL(str(library))

    def test_original_and_remapped_instruction_semantics(self):
        edge = [0, 1, 2, 31, 32, 127, 128, 255, 256, 65535, 65536,
                0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, MASK]
        rng = random.Random(6001)
        cases = [(x, y) for x in edge for y in edge]
        cases += [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(2000)]
        for name in FIXTURES:
            for suffix in ("", "_remapped"):
                fn = getattr(self.library, name + suffix)
                fn.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
                fn.restype = ctypes.c_uint32
                with self.subTest(function=name + suffix):
                    for x, y in cases:
                        self.assertEqual(fn(x, y), reference(name, x, y), (name, x, y))
        self.assertEqual(len(FIXTURES) * 2 * len(cases), 48950)

    def test_public_symbol_and_runtime_notice(self):
        fn = self.library.exampleBNO_symbol
        fn.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        fn.restype = ctypes.c_uint32
        self.assertEqual(fn(0xFFFFFFFF, 0), 0xFFFFFFFF)
        self.assertIn("SPDX-License-Identifier: MIT", self.source)
        self.assertIn("Copyright (c) 2026 Opus Arc", self.source)
        self.assertIn("does not change", self.source)


if __name__ == "__main__":
    unittest.main()
