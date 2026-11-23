import json
from pathlib import Path
import struct
import tempfile
import unittest

from test_cli import cli


class DataProfileCLITests(unittest.TestCase):
    def test_diverse_profile_generates_usable_interface_and_size_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.bin'
            data = bytes(range(256)) * 3 + b'last'
            source.write_bytes(data)
            result = cli('pack-data', source, '-o', root / 'asset.c', '--symbol', 'asset',
                         '--profile', 'diverse', '--seed', '11', '--report', root / 'summary.json')
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((root / 'summary.json').read_text())
            self.assertEqual(report['profile'], 'diverse')
            self.assertEqual(report['input_bytes'], len(data))
            self.assertFalse(report['encryption'])
            self.assertNotIn('seed', report)
            self.assertNotIn('plans', report)
            self.assertIn('int asset_read(', (root / 'asset.h').read_text())
            self.assertEqual(source.read_bytes(), data)

    def test_compiled_model_cli_and_rejected_inputs_do_not_leave_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'matrix.f32'
            data = struct.pack('<6f', 1.0, 2.0, -3.0, 0.0, 0.25, -0.5)
            source.write_bytes(data)
            command = ['compile-model', source, '-o', root / 'model.c', '--symbol', 'model',
                       '--channels', '3', '--seed', '7']
            result = cli(*command, '--report', root / 'model.json')
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((root / 'model.json').read_text())
            self.assertEqual((report['rows'], report['channels']), (2, 3))
            self.assertFalse(report['raw_read_api'])
            self.assertTrue(report['basis_queries_recover_numeric_matrix'])
            self.assertIn('static inline int model_prepare(', (root / 'model.h').read_text())
            self.assertEqual(source.read_bytes(), data)
            for path in (root / 'model.c', root / 'model.h', root / 'model.json'):
                path.unlink()

            collision = cli(*command, '--report', root / 'model.h', '--force')
            self.assertEqual(collision.returncode, 2)
            self.assertFalse((root / 'model.c').exists())
            self.assertFalse((root / 'model.h').exists())
            for invalid in (struct.pack('<6f', float('nan'), 0, 0, 0, 0, 0), data[:-1]):
                source.write_bytes(invalid)
                rejected = cli(*command, '--report', root / 'model.json')
                self.assertEqual(rejected.returncode, 2, rejected.stderr)
                self.assertNotIn('Traceback', rejected.stderr)
                for name in ('model.c', 'model.h', 'model.json'):
                    self.assertFalse((root / name).exists())

    def test_oversized_data_is_rejected_before_creating_any_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'large.bin'
            with source.open('wb') as file:
                file.truncate(64 * 1024 * 1024 + 1)
            for command, options in [('pack-data', ['--profile', 'diverse']),
                                     ('compile-model', ['--channels', '2'])]:
                result = cli(command, source, '-o', root / 'large.c', '--symbol', 'large', *options)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('64 MiB', result.stderr)
                self.assertFalse((root / 'large.c').exists())
                self.assertFalse((root / 'large.h').exists())


if __name__ == '__main__':
    unittest.main()
