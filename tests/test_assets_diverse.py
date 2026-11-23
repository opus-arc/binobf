import ctypes
import json
from pathlib import Path
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from binobf.assets import JAPANESE_NOTICE, PackedData
from binobf.assets_diverse import pack_diverse


class DiverseAssetTests(unittest.TestCase):
    def compile_sources(self, directory, sources):
        compiler = shutil.which('cc')
        self.assertIsNotNone(compiler, 'C compiler required for release validation')
        paths = []
        for name, source in sources:
            path = directory / (name + '.c')
            path.write_text(source)
            paths.append(str(path))
        library = directory / ('readers.dylib' if sys.platform == 'darwin' else 'readers.so')
        command = [compiler, '-std=c99', '-O2', '-Wall', '-Wextra', '-Werror',
                   '-fno-lto', '-shared', '-fPIC', *paths, '-o', str(library)]
        compiled = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)
        return ctypes.CDLL(str(library)), library

    def check_reader(self, native, symbol, data, block_size, seed):
        size = getattr(native, symbol + '_size')
        size.restype = ctypes.c_size_t
        reader = getattr(native, symbol + '_read')
        reader.argtypes = [ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
        reader.restype = ctypes.c_int
        self.assertEqual(size(), len(data))
        rng = random.Random(seed)
        cases = [(0, len(data)), (len(data), 0), (0, 0), (len(data) - 1, 1)]
        for boundary in (1, 3, 4, block_size - 1, block_size, block_size * 8 - 1):
            if boundary < len(data):
                cases.append((boundary, min(13, len(data) - boundary)))
        cases += [(offset := rng.randrange(len(data) + 1), rng.randrange(len(data) - offset + 1))
                  for _ in range(80)]
        for offset, count in cases:
            output = ctypes.create_string_buffer(b'\xa5' * (count + 16), count + 16)
            self.assertEqual(reader(offset, ctypes.byref(output, 7), count), 0,
                             (symbol, offset, count))
            self.assertEqual(output.raw[:7], b'\xa5' * 7)
            self.assertEqual(output.raw[7:7 + count], data[offset:offset + count])
            self.assertEqual(output.raw[7 + count:], b'\xa5' * 9)
        maximum = ctypes.c_size_t(-1).value
        marker = ctypes.create_string_buffer(b'unchanged guard bytes')
        initial = marker.raw
        for offset, count in ((len(data) + 1, 0), (len(data), 1), (1, maximum),
                              (maximum, 0), (maximum - 1, 8), (0, maximum)):
            self.assertEqual(reader(offset, marker, count), -1)
            self.assertEqual(marker.raw, initial)
        self.assertEqual(reader(0, None, 1), -1)
        self.assertEqual(reader(len(data), None, 0), 0)
        self.assertEqual(reader(0, None, 0), 0)

    def test_compiled_differential_ranges_and_guards(self):
        # Tail words/pages, unequal bucket sizes, all active buckets, min/max pages.
        matrix = [(1, 64, 1), (3, 128, 2), (67, 64, 3), (1027, 64, 11),
                  (8197, 256, 16), (65539, 65536, 42), (20493, 4096, 93)]
        sources, cases = [], []
        for i, (length, block, seed) in enumerate(matrix):
            rng = random.Random(1000 + i)
            data = bytes(rng.randrange(256) for _ in range(length))
            symbol = 'asset_' + str(i)
            generated = pack_diverse(data, symbol, seed=seed, block_size=block,
                                     notice=JAPANESE_NOTICE if i == 3 else None)
            self.assertIsInstance(generated, PackedData)
            self.assertNotIn('_pages[', generated.source)
            self.assertNotIn('_keys[', generated.source)
            self.assertIn('_bytes[] =\n    "\\', generated.source)
            self.assertNotIn('_bytes[] = {', generated.source)
            self.assertFalse(generated.statistics['encryption'])
            self.assertIn(generated.statistics['bucket_count'], (8, 16))
            self.assertEqual(generated.statistics['stored_bytes'],
                             ((length + block - 1) // block) * block)
            sources.append((symbol, generated.source))
            cases.append((symbol, data, block, seed))
        with tempfile.TemporaryDirectory() as folder:
            native, path = self.compile_sources(Path(folder), sources)
            for case in cases:
                with self.subTest(symbol=case[0]):
                    self.check_reader(native, *case)
            self.assertIn(JAPANESE_NOTICE.encode(), path.read_bytes())

    def test_long_literal_roundtrip_without_byte_initializer(self):
        # The compiler must accept an actually long concatenated literal, not
        # merely a short demonstration of the new representation.
        data = bytes(range(256)) * 2048 + b'odd-tail-ends!'
        generated = pack_diverse(data, 'large_asset', seed=781, block_size=4096, notice='')
        with tempfile.TemporaryDirectory() as folder:
            native, _ = self.compile_sources(Path(folder), [('large', generated.source)])
            self.check_reader(native, 'large_asset', data, 4096, 781)

    def test_reproducibility_seed_diversity_and_public_metadata(self):
        data = bytes(range(256)) * 9 + b'end'
        a = pack_diverse(data, 'sample', seed=1, block_size=64)
        self.assertEqual(a, pack_diverse(data, 'sample', seed=1, block_size=64))
        b = pack_diverse(data, 'sample', seed=2, block_size=64)
        self.assertNotEqual(a.source, b.source)
        # Reports carry no seed, per-page map, per-bucket program or constants.
        self.assertEqual(set(a.statistics), {
            'input_bytes', 'stored_bytes', 'pages', 'block_size', 'bucket_count',
            'active_buckets', 'program_operations_per_bucket',
            'literal_terminator_bytes', 'encoding', 'encryption'})
        self.assertNotIn('seed', json.dumps(a.statistics))

    def test_invalid_sizes_symbols_and_limit(self):
        for block in (-1, 0, 16, 65, 131072):
            with self.assertRaises(ValueError):
                pack_diverse(b'data', 'asset', seed=1, block_size=block)
        for symbol in ('bad;name', '_private', '1asset', 'binobf_reserved'):
            with self.assertRaises(ValueError):
                pack_diverse(b'data', symbol, seed=1)
        with self.assertRaises(ValueError):
            pack_diverse(b'', 'asset', seed=1)

        class OverLimit:
            def __len__(self):
                return 64 * 1024 * 1024 + 1

        with self.assertRaisesRegex(ValueError, '64 MiB'):
            pack_diverse(OverLimit(), 'asset', seed=1)


if __name__ == '__main__':
    unittest.main()
