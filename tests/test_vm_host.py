from __future__ import annotations

import ctypes
from pathlib import Path
import platform
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

from fixtures import MIX_WORDS, SELECT_WORDS, mix_reference, select_reference, words

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from binobf.vm import FunctionSpec, generate_c


class VMHostTests(unittest.TestCase):
    def test_generated_vm_against_independent_unsigned_reference(self):
        compiler = shutil.which('cc')
        if compiler is None:
            self.skipTest('host C compiler unavailable')
        specs = [FunctionSpec('mix32', words(*MIX_WORDS)), FunctionSpec('select32', words(*SELECT_WORDS))]
        generated = generate_c(specs, seed=20261123)
        self.assertEqual(generated.source, generate_c(specs, seed=20261123).source)
        with tempfile.TemporaryDirectory(prefix='binobf-vm-host-') as folder:
            work = Path(folder)
            source = work / 'generated.c'
            source.write_text(generated.source, encoding='utf-8')
            output = work / ('vm.dylib' if platform.system() == 'Darwin' else 'vm.so')
            link_mode = '-dynamiclib' if platform.system() == 'Darwin' else '-shared'
            subprocess.run([compiler, '-std=c11', '-O2', '-fPIC', link_mode, str(source), '-o', str(output)],
                           check=True, capture_output=True)
            library = ctypes.CDLL(str(output))
            functions = [(library.mix32, mix_reference), (library.select32, select_reference)]
            for fn, _ in functions:
                fn.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
                fn.restype = ctypes.c_uint32
            edges = [0, 1, 31, 32, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]
            cases = [(x, y) for x in edges for y in edges]
            randoms = random.Random(20261123)
            cases += [(randoms.getrandbits(32), randoms.getrandbits(32)) for _ in range(2048)]
            for x, y in cases:
                for function, reference in functions:
                    self.assertEqual(function(x, y), reference(x, y), (x, y))
