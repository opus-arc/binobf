from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


package = module('binobf_package_test', 'package_release.py')
verify = module('binobf_verify_test', 'verify_release.py')


class PackagingTests(unittest.TestCase):
    def test_archives_repeat_and_round_trip(self):
        # Exercise the actual distribution without recursively invoking its tests.
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            version = package.source_version(ROOT)
            first = package.build(ROOT, work / 'a', version, 'source')
            second = package.build(ROOT, work / 'b', version, 'source')
            for a, b in zip(first, second):
                self.assertEqual(a.read_bytes(), b.read_bytes(), a.name)
            for index, archive in enumerate(first[:2]):
                verify.check_checksum(archive)
                extracted = verify.extract_checked(archive, work / f'extract-{index}', version)
                self.assertEqual((extracted / 'bin/binobf').read_bytes(), (ROOT / 'bin/binobf').read_bytes())
                self.assertTrue((extracted / 'bin/binobf').stat().st_mode & 0o111)

    def test_wrong_version_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, 'version'):
                package.build(ROOT, Path(folder), '999.0.0', 'source')

    def test_modified_archive_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            archive = package.build(ROOT, Path(folder), package.source_version(ROOT), 'source')[0]
            archive.write_bytes(archive.read_bytes() + b'changed')
            with self.assertRaisesRegex(ValueError, 'SHA256SUMS'):
                verify.check_checksum(archive)
