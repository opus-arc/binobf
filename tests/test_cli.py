from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from fixtures import elf_object, words

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from binobf.binary import BinaryImage


def cli(*args):
    return subprocess.run([sys.executable, str(ROOT / 'bin/binobf'), *map(str, args)],
                          cwd=ROOT, capture_output=True, text=True)


class CLITests(unittest.TestCase):
    def test_inspect_and_native_object_rewrite(self):
        with tempfile.TemporaryDirectory(prefix='binobf-test-') as folder:
            work = Path(folder)
            original = work / 'input.o'
            original.write_bytes(elf_object())
            before = hashlib.sha256(original.read_bytes()).hexdigest()
            inspected = cli('inspect', original, '--json')
            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            self.assertIsInstance(json.loads(inspected.stdout), dict)
            for name in ['first.o', 'second.o']:
                result = cli('protect', original, '-o', work / name, '--function', 'mix32', '--seed', 173,
                             '--sign', 'none')
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(before, hashlib.sha256(original.read_bytes()).hexdigest())
            self.assertEqual((work / 'first.o').read_bytes(), (work / 'second.o').read_bytes())
            self.assertNotEqual(original.read_bytes(), (work / 'first.o').read_bytes())
            self.assertEqual(len(original.read_bytes()), len((work / 'first.o').read_bytes()))
            before_image, after_image = BinaryImage.read(original), BinaryImage.read(work / 'first.o')
            self.assertEqual(before_image.select(['select32'])[0].code, after_image.select(['select32'])[0].code)

    def test_unsupported_function_does_not_write_output(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            source, output = work / 'load.o', work / 'output.o'
            source.write_bytes(elf_object([('load32', words(0xB9400000, 0xD65F03C0))]))
            for operation, options in [('protect', ['--function', 'load32', '--sign', 'none']),
                                       ('virtualize', ['--abi', 'u32x2'])]:
                result = cli(operation, source, '-o', output, *options)
                self.assertNotEqual(result.returncode, 0, operation)
                self.assertFalse(output.exists(), operation)

    def test_missing_function_does_not_create_output(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            source, output = work / 'input.o', work / 'output.o'
            source.write_bytes(elf_object())
            result = cli('protect', source, '-o', output, '--function', 'missing', '--sign', 'none')
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())

    def test_truncated_input_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'invalid.o'
            source.write_bytes(elf_object()[:80])
            result = cli('inspect', source, '--json')
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('Traceback', result.stderr)
