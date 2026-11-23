"""Independent architectural checks of the generated C runtime.

This is host execution, not an AArch64 hardware test. Bitfield expectations use
the architecture's rotate/write-mask/top-mask formulation, independently of
the generator's extract/insert formulation. NZCV uses widened integer math.
"""
import ctypes
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from binobf import vm


MASK = (1 << 32) - 1
CC = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")


def rotate_right(value, count):
    return ((value >> count) | (value << (32 - count))) & MASK if count else value


def architectural_bitfield(old, value, rotate, size, kind):
    write_mask = rotate_right((1 << (size + 1)) - 1, rotate)
    top_mask = (1 << (((size - rotate) & 31) + 1)) - 1
    rotated = rotate_right(value, rotate)
    if kind == 1:
        bottom = (old & ~write_mask) | (rotated & write_mask)
        return ((old & ~top_mask) | (bottom & top_mask)) & MASK
    bottom = rotated & write_mask
    top = MASK if kind == 0 and value & (1 << size) else 0
    return ((top & ~top_mask) | (bottom & top_mask)) & MASK


@unittest.skipUnless(CC and sys.platform != "win32", "a POSIX C compiler is required")
class RuntimeArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        source = vm._C_HELPERS + r'''
uint32_t audit_field(uint32_t old,uint32_t x,uint32_t r,uint32_t s,uint32_t kind) {
    return BNO_field(old,x,r,s,kind);
}
uint32_t audit_cond(uint32_t cond,uint32_t flags) {
    return BNO_cond(cond,(flags>>3)&1,(flags>>2)&1,(flags>>1)&1,flags&1);
}
'''
        source += '\nuint32_t audit_flags(uint32_t X,uint32_t Y,uint32_t S) {'
        source += 'uint32_t r[32]={X},a[5]={0,0,Y,S,1};'
        source += 'uint32_t d,value,x,y,sub,setf,nf=0,zf=0,cf=0,vf=0;'
        source += vm._case_bodies()["ARITH_I"]
        source += 'return (nf<<3)|(zf<<2)|(cf<<1)|vf;}\n'
        path = root / "audit.c"
        output = root / "audit.so"
        path.write_text(source)
        mode = "-dynamiclib" if sys.platform == "darwin" else "-shared"
        subprocess.run([CC, "-std=c99", "-O2", mode, "-fPIC", str(path), "-o", str(output)],
                       check=True, capture_output=True, text=True)
        cls.library = ctypes.CDLL(str(output))
        for name, count in (("audit_field", 5), ("audit_cond", 2), ("audit_flags", 3)):
            function = getattr(cls.library, name)
            function.argtypes = [ctypes.c_uint32] * count
            function.restype = ctypes.c_uint32

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_all_bitfield_encodings_against_rotate_mask_semantics(self):
        random_source = random.Random(20261123)
        values = [0, 1, 2, 0x7fffffff, 0x80000000, MASK, 0xaaaaaaaa, 0x55555555]
        values += [random_source.getrandbits(32) for _ in range(16)]
        for kind in range(3):
            for rotate in range(32):
                for size in range(32):
                    for index, value in enumerate(values):
                        old = values[(index + 5) % len(values)]
                        expected = architectural_bitfield(old, value, rotate, size, kind)
                        actual = self.library.audit_field(old, value, rotate, size, kind)
                        self.assertEqual(actual, expected,
                                         (old, value, rotate, size, kind))

    def test_all_nzcv_and_condition_combinations(self):
        for flags in range(16):
            n, z, c, v = (flags >> 3) & 1, (flags >> 2) & 1, (flags >> 1) & 1, flags & 1
            expected = (z, not z, c, not c, n, not n, v, not v,
                        c and not z, not c or z, n == v, n != v,
                        not z and n == v, z or n != v, True, True)
            for condition, value in enumerate(expected):
                self.assertEqual(self.library.audit_cond(condition, flags), int(value),
                                 (condition, flags))

    def test_arithmetic_flags_against_widened_integer_reference(self):
        random_source = random.Random(20261123)
        edges = [0, 1, 2, 0x7fffffff, 0x80000000, MASK, 0xaaaaaaaa, 0x55555555]
        pairs = [(x, y) for x in edges for y in edges]
        pairs += [(random_source.getrandbits(32), random_source.getrandbits(32))
                  for _ in range(50000)]
        signed = lambda value: value - (1 << 32) if value & (1 << 31) else value
        for subtract in (0, 1):
            for x, y in pairs:
                exact = x - y if subtract else x + y
                result = exact & MASK
                signed_exact = signed(x) - signed(y) if subtract else signed(x) + signed(y)
                carry = int(x >= y) if subtract else int(exact > MASK)
                overflow = int(signed_exact < -(1 << 31) or signed_exact >= (1 << 31))
                expected = ((result >> 31) << 3) | (int(result == 0) << 2) | (carry << 1) | overflow
                self.assertEqual(self.library.audit_flags(x, y, subtract), expected,
                                 (x, y, subtract))


class NativePermutationEncodingTests(unittest.TestCase):
    def test_all_source_fields_follow_the_same_permutation(self):
        # MOV, ADD, MADD, and EOR exercise Rd/Rn/Rm/Ra, including read/write reuse.
        original = (0x2A0003E8, 0x2A0103E9, 0x0B09010A,
                    0x1B09294B, 0x4A080160, 0xD65F03C0)
        expected = (0x2A0003EF, 0x2A0103EE, 0x0B0E01ED,
                    0x1B0E35AC, 0x4A0F0180, 0xD65F03C0)
        pack = lambda words: struct.pack("<" + "I" * len(words), *words)
        spec = vm.FunctionSpec("permutation_fixture", pack(original))
        mapping = dict(zip(range(8, 16), reversed(range(8, 16))))
        self.assertEqual(vm.remap_registers(spec, mapping), pack(expected))


if __name__ == "__main__":
    unittest.main()
