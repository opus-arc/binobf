from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/fixtures'
NATIVE_MAC = platform.system() == 'Darwin' and platform.machine() == 'arm64'


def run(*args):
    command = [str(x) for x in args]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode:
        raise AssertionError(f'command failed ({result.returncode}): {command!r}\n'
                             f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}')
    return result


def cli(*args):
    return run(sys.executable, ROOT / 'bin/binobf', *args)


class NativeGateTests(unittest.TestCase):
    def test_required_native_platform_is_present(self):
        if os.environ.get('BINOBF_REQUIRE_NATIVE') == '1':
            self.assertTrue(NATIVE_MAC, 'macos-arm64 release cannot pass by skipping native tests')
            self.assertIsNotNone(shutil.which('cc'), 'native C compiler is required')


@unittest.skipUnless(NATIVE_MAC, 'native macOS arm64 integration; exercised by release CI')
class NativeIntegrationTests(unittest.TestCase):
    def test_native_object_and_executable_keep_behavior(self):
        with tempfile.TemporaryDirectory(prefix='binobf-native-') as folder:
            work = Path(folder)
            original = work / 'original.o'
            run('cc', '-arch', 'arm64', '-c', FIXTURES / 'leaf_u32.S', '-o', original)
            baseline = work / 'baseline'
            run('cc', '-arch', 'arm64', '-std=c11', '-O2', FIXTURES / 'native_harness.c', original, '-o', baseline)
            expected = run(baseline).stdout
            original_hash = hashlib.sha256(original.read_bytes()).hexdigest()
            changed = work / 'protected.o'
            cli('protect', original, '-o', changed, '--function', 'mix32', '--function', 'select32',
                '--seed', 181, '--sign', 'none')
            rebuilt = work / 'rebuilt'
            run('cc', '-arch', 'arm64', '-std=c11', '-O2', FIXTURES / 'native_harness.c', changed, '-o', rebuilt)
            self.assertEqual(run(rebuilt).stdout, expected)
            self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), original_hash)
            self.assertNotEqual(original.read_bytes(), changed.read_bytes())
            protected_executable = work / 'protected-cli'
            cli('protect', baseline, '-o', protected_executable, '--function', 'mix32', '--function', 'select32',
                '--seed', 193, '--sign', 'ad-hoc')
            run('codesign', '--verify', '--strict', protected_executable)
            self.assertEqual(run(protected_executable).stdout, expected)

    def test_virtualized_object_links_and_executes(self):
        with tempfile.TemporaryDirectory(prefix='binobf-vm-native-') as folder:
            work = Path(folder)
            original = work / 'original.o'
            run('cc', '-arch', 'arm64', '-c', FIXTURES / 'leaf_u32.S', '-o', original)
            baseline = work / 'baseline'
            run('cc', '-arch', 'arm64', '-std=c11', '-O2', FIXTURES / 'native_harness.c', original, '-o', baseline)
            expected = run(baseline).stdout
            for seed in [0, 73, 4294967295]:
                with self.subTest(seed=seed):
                    virtualized = work / f'virtualized-{seed}.o'
                    source = work / f'vm-{seed}.c'
                    cli('virtualize', original, '-o', virtualized, '--abi', 'u32x2', '--seed', seed,
                        '--target', 'arm64-apple-macos', '--emit-c', source)
                    generated = work / f'vm-test-{seed}'
                    run('cc', '-arch', 'arm64', '-std=c11', '-O2', FIXTURES / 'native_harness.c', virtualized, '-o', generated)
                    self.assertEqual(run(generated).stdout, expected)
                    self.assertTrue(source.is_file())

    def test_unsupported_object_rejected_before_compilation(self):
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            original, output = work / 'unsupported.o', work / 'output.o'
            run('cc', '-arch', 'arm64', '-c', FIXTURES / 'unsupported.S', '-o', original)
            result = subprocess.run([sys.executable, str(ROOT / 'bin/binobf'), 'virtualize', str(original),
                                     '-o', str(output), '--abi', 'u32x2'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
