"""Execute generated model kernels against independent finite-f32 references."""
import ctypes
import math
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from binobf.model import compile_model


def f32(bits):
    return struct.unpack('<f', struct.pack('<I', bits))[0]


def f32_round(value):
    return struct.unpack('<f', struct.pack('<f', value))[0]


def run_compiler(command):
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise AssertionError(f'compiler failed ({result.returncode}): {command!r}\n'
                             f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
    return result


class ModelNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = shutil.which('cc')
        if cls.compiler is None:
            raise AssertionError('C compiler required for model correctness validation')
        cls.folder = tempfile.TemporaryDirectory(prefix='binobf-model-test-')
        cls.root = Path(cls.folder.name)
        cls.models = []
        sources, wrappers = [], []
        for channels in (2, 3, 4, 8, 16):
            rng = random.Random(921 + channels)
            rows = [[f32_round(rng.uniform(-10.0, 10.0)) for _ in range(channels)] for _ in range(24)]
            if channels == 4:
                rows += [[f32(bits) for bits in (1, 0x007fffff, 0x00800000, 0x00800001)]]
            # The four-column case exercises nonzero exact dyadic scales.
            # Others also span the complete finite f32 range, constraining
            # scales when needed rather than dropping tiny stored values.
            if channels != 4:
                rows += [[f32(1) * (-1 if c % 2 else 1) for c in range(channels)],
                         [f32(0x7f7fffff) * (-1 if c % 2 else 1) for c in range(channels)],
                         [f32((0x007fffff, 0x00800000, 0x80000000, 0)[c % 4]) for c in range(channels)]]
                rows += [[f32(rng.randrange(0x7f800000) | (rng.randrange(2) << 31))
                          for _ in range(channels)] for _ in range(8)]
            name = f'model{channels}'
            raw = b''.join(struct.pack('<f', v) for row in rows for v in row)
            generated = compile_model(raw, name, channels, seed=channels * 19)
            source, header = cls.root / f'{name}.c', cls.root / f'{name}.h'
            source.write_text(generated.source); header.write_text(generated.header)
            sources.append(source)
            wrappers.append(f'#include "{name}.h"\n'
                            f'int wrap{channels}(const float *w, size_t n, {name}_prepared *p) '
                            f'{{ return {name}_prepare(w,n,p); }}\n')
            context = type(f'Prepared{channels}', (ctypes.Structure,), {
                '_fields_': [('opaque_tag', ctypes.c_uint64), ('opaque_state', ctypes.c_double * channels)]})
            cls.models.append((name, channels, rows, context, generated))
        wrapper = cls.root / 'wrapper.c'
        wrapper.write_text('\n'.join(wrappers))
        library = cls.root / ('models.dylib' if sys.platform == 'darwin' else 'models.so')
        run_compiler([cls.compiler, '-std=c99', '-O2', '-Wall', '-Wextra', '-Werror',
                      '-fno-fast-math', '-fPIC', '-shared', *map(str, sources), str(wrapper),
                      '-o', str(library)])
        cls.native = ctypes.CDLL(str(library))
        for name, channels, rows, context, generated in cls.models:
            prepare = getattr(cls.native, f'wrap{channels}')
            prepare.argtypes = [ctypes.POINTER(ctypes.c_float), ctypes.c_size_t, ctypes.POINTER(context)]
            prepare.restype = ctypes.c_int
            evaluate = getattr(cls.native, name + '_evaluate')
            evaluate.argtypes = [ctypes.c_size_t, ctypes.POINTER(context), ctypes.POINTER(ctypes.c_double)]
            evaluate.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def test_native_dot_errors_and_complete_basis_oracle_limit(self):
        for name, channels, rows, context, generated in self.models:
            with self.subTest(channels=channels):
                prepare = getattr(self.native, f'wrap{channels}')
                evaluate = getattr(self.native, name + '_evaluate')
                prepared, output = context(), ctypes.c_double()
                self.assertEqual(ctypes.sizeof(context), generated.statistics['prepared_bytes'])
                # Explicit negative security evidence: basis inputs recover
                # numeric elements through the legitimate computation API.
                # This is not a claim about locating hidden entry points.
                for column in range(channels):
                    weights = (ctypes.c_float * channels)(*[float(c == column) for c in range(channels)])
                    self.assertEqual(prepare(weights, channels, ctypes.byref(prepared)), 0)
                    for row, values in enumerate(rows):
                        self.assertEqual(evaluate(row, ctypes.byref(prepared), ctypes.byref(output)), 0)
                        self.assertEqual(output.value, values[column])
                rng = random.Random(channels + 431)
                weights_cases = [[f32(1)] * channels, [f32(0x7f7fffff)] * channels,
                                 [(-1.0 if c % 2 else 1.0) for c in range(channels)]]
                weights_cases += [[f32(rng.randrange(0x7f800000) | (rng.randrange(2) << 31))
                                   for _ in range(channels)] for _ in range(64)]
                for values in weights_cases:
                    weights = (ctypes.c_float * channels)(*values)
                    self.assertEqual(prepare(weights, channels, ctypes.byref(prepared)), 0)
                    for row, coefficients in enumerate(rows):
                        products = [a * b for a, b in zip(coefficients, values)]
                        expected = math.fsum(products)
                        scale = math.fsum(abs(p) for p in products)
                        budget = 4 * channels * sys.float_info.epsilon * scale
                        self.assertEqual(evaluate(row, ctypes.byref(prepared), ctypes.byref(output)), 0)
                        self.assertTrue(math.isfinite(output.value))
                        self.assertLessEqual(abs(output.value - expected), budget)

    def test_bounds_invalid_weights_and_context_leave_outputs_unchanged(self):
        for name, channels, rows, context, generated in self.models:
            prepare = getattr(self.native, f'wrap{channels}')
            evaluate = getattr(self.native, name + '_evaluate')
            weights = (ctypes.c_float * channels)(*[1.0] * channels)
            prepared, output = context(), ctypes.c_double(12.5)
            self.assertEqual(evaluate(0, ctypes.byref(prepared), ctypes.byref(output)), -1)
            self.assertEqual(output.value, 12.5)
            self.assertEqual(prepare(weights, channels, ctypes.byref(prepared)), 0)
            saved = bytes(prepared)
            for count in (0, channels - 1, channels + 1, ctypes.c_size_t(-1).value):
                self.assertEqual(prepare(weights, count, ctypes.byref(prepared)), -1)
                self.assertEqual(bytes(prepared), saved)
            for value in (float('nan'), float('inf'), -float('inf')):
                weights[channels - 1] = value
                self.assertEqual(prepare(weights, channels, ctypes.byref(prepared)), -1)
                self.assertEqual(bytes(prepared), saved)
            self.assertEqual(prepare(None, channels, ctypes.byref(prepared)), -1)
            self.assertEqual(prepare(weights, channels, None), -1)
            for row in (len(rows), ctypes.c_size_t(-1).value):
                self.assertEqual(evaluate(row, ctypes.byref(prepared), ctypes.byref(output)), -1)
                self.assertEqual(output.value, 12.5)
            self.assertEqual(evaluate(0, None, ctypes.byref(output)), -1)
            self.assertEqual(evaluate(0, ctypes.byref(prepared), None), -1)

    def test_fast_math_build_is_rejected(self):
        result = subprocess.run([self.compiler, '-std=c99', '-O2', '-ffast-math', '-c',
                                 str(self.root / 'model4.c'), '-o', str(self.root / 'bad.o')],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('requires non-fast-math', result.stderr)

    def test_private_prepare_header_compiles_as_cpp(self):
        compiler = shutil.which('c++')
        self.assertIsNotNone(compiler, 'C++ compiler required to validate the integration header')
        wrapper = self.root / 'cpp.cpp'
        wrapper.write_text('#include "model4.h"\n'
                           'int integrate(const float *w, double *out) {\n'
                           '  model4_prepared p;\n'
                           '  if (model4_prepare(w, model4_channels, &p)) return -1;\n'
                           '  return model4_evaluate(0, &p, out);\n}\n')
        run_compiler([compiler, '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
                      '-c', str(wrapper), '-o', str(self.root / 'cpp.o')])


class ModelGeneratorTests(unittest.TestCase):
    def test_determinism_seed_bounds_and_no_decoding_manifest(self):
        data = struct.pack('<8f', 1.0, -2.0, 3.5, 4.0, 2.5, 0.0, -0.0, -8.25)
        first = compile_model(data, 'example', 4, seed=0)
        self.assertEqual(first, compile_model(data, 'example', 4, seed=0))
        self.assertNotEqual(first.source, compile_model(data, 'example', 4, seed=(1 << 256) - 1).source)
        self.assertFalse(first.statistics['encryption'])
        self.assertFalse(first.statistics['raw_read_api'])
        self.assertNotIn('permutation', first.statistics)
        self.assertNotIn('seed', first.statistics)
        self.assertIn('static inline int example_prepare', first.header)
        self.assertNotIn('example_read(', first.header)
        self.assertIn('SPDX-License-Identifier: MIT', first.header)

    def test_invalid_input_is_rejected_before_generation(self):
        data = struct.pack('<2f', 1.0, 2.0)
        for channels in (0, 1, 17, 3, True, 4.0):
            with self.subTest(channels=channels), self.assertRaises(ValueError):
                compile_model(data, 'sample', channels, seed=1)
        for seed in (-1, 1 << 256, True, 1.0, '1'):
            with self.subTest(seed=seed), self.assertRaises(ValueError):
                compile_model(data, 'sample', 2, seed=seed)
        for symbol in ('', '_reserved', 'has space', 'x;bad', 'binobf_reserved'):
            with self.subTest(symbol=symbol), self.assertRaises(ValueError):
                compile_model(data, symbol, 2, seed=1)
        for raw in (b'', b'1234', b'123456789', bytes(64 * 1024 * 1024 + 8),
                    struct.pack('<II', 0x7f800000, 0), struct.pack('<II', 0xff800000, 0),
                    struct.pack('<II', 0x7fc00001, 0), struct.pack('<II', 0x7f800001, 0)):
            with self.assertRaises(ValueError):
                compile_model(raw, 'sample', 2, seed=1)


if __name__ == '__main__':
    unittest.main()
