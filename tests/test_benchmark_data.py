"""Prevent a benchmark report from replacing its input before any compilation."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('binobf_benchmark_data', ROOT / 'tools/benchmark_data.py')
benchmark_data = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark_data)


class BenchmarkDataOutputTests(unittest.TestCase):
    def test_input_aliases_and_existing_outputs_are_protected_before_compilation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'asset.bin'
            original = b'original asset bytes\0\xff'
            source.write_bytes(original)
            symlink = root / 'alias-symlink'
            symlink.symlink_to(source)
            hardlink = root / 'alias-hardlink'
            hardlink.hardlink_to(source)
            existing = root / 'report.json'
            existing.write_text('previous result')
            directory = root / 'directory'
            directory.mkdir()
            with mock.patch.object(benchmark_data.shutil, 'which',
                                   side_effect=AssertionError('compiler discovery must not run')):
                for alias in (source, symlink, hardlink):
                    for force in (False, True):
                        args = SimpleNamespace(input=str(source), output=str(alias), force=force)
                        with self.subTest(alias=alias.name, force=force), self.assertRaises(ValueError):
                            benchmark_data.benchmark(args)
                for output in (existing, directory):
                    args = SimpleNamespace(input=str(source), output=str(output), force=False)
                    with self.assertRaises(ValueError):
                        benchmark_data.benchmark(args)
                with self.assertRaises(ValueError):
                    benchmark_data.benchmark(SimpleNamespace(input=str(source), output=str(directory), force=True))
            self.assertEqual(existing.read_text(), 'previous result')
            benchmark_data._atomic_output(existing, 'new result\n', source, force=True)
            self.assertEqual(existing.read_text(), 'new result\n')
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(symlink.read_bytes(), original)
            self.assertEqual(hardlink.read_bytes(), original)
            self.assertFalse(list(root.glob('.binobf-benchmark-*')))


if __name__ == '__main__':
    unittest.main()
