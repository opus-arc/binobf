#!/usr/bin/env python3
"""Validate and exercise the exact extracted release archive."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile


def members(path: Path):
    if path.name.endswith('.tar.gz'):
        with tarfile.open(path, 'r:gz') as archive:
            for item in archive:
                if not item.isfile():
                    raise ValueError('release archive may contain regular files only')
                data = archive.extractfile(item)
                if data is None:
                    raise ValueError('unreadable archive member')
                yield item.name, item.mode, data.read()
    elif path.suffix == '.zip':
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                mode = item.external_attr >> 16
                if not stat.S_ISREG(mode):
                    raise ValueError('release archive may contain regular files only')
                yield item.filename, stat.S_IMODE(mode), archive.read(item)
    else:
        raise ValueError('expected .tar.gz or .zip')


def extract_checked(path: Path, destination: Path, version: str) -> Path:
    prefix = f'binobf-v{version}'
    seen = set()
    total = 0
    for name, mode, data in members(path):
        parts = PurePosixPath(name)
        if parts.is_absolute() or '..' in parts.parts or len(parts.parts) < 2 or parts.parts[0] != prefix or '\\' in name:
            raise ValueError(f'unsafe or unexpected archive path: {name}')
        if name in seen:
            raise ValueError(f'duplicate archive member: {name}')
        seen.add(name)
        total += len(data)
        if total > 100 * 1024 * 1024:
            raise ValueError('release archive exceeds expected source-distribution size')
        target = destination.joinpath(*parts.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(mode & 0o777)
    root = destination / prefix
    manifest = json.loads((root / 'RELEASE_MANIFEST.json').read_text(encoding='utf-8'))
    if manifest.get('version') != version or manifest.get('product') != 'binobf' or manifest.get('schema') != 1:
        raise ValueError('release manifest identity mismatch')
    expected = {f'{prefix}/{name}' for name in manifest['files']} | {f'{prefix}/RELEASE_MANIFEST.json'}
    if seen != expected:
        raise ValueError('archive members do not match release manifest')
    for name, record in manifest['files'].items():
        target = root / name
        data = target.read_bytes()
        if len(data) != record['size'] or hashlib.sha256(data).hexdigest() != record['sha256']:
            raise ValueError(f'content checksum mismatch: {name}')
        if stat.S_IMODE(target.stat().st_mode) != int(record['mode'], 8):
            raise ValueError(f'permission mismatch: {name}')
    return root


def check_checksum(path: Path) -> None:
    lines = (path.parent / 'SHA256SUMS').read_text(encoding='ascii').splitlines()
    expected = {}
    for line in lines:
        digest, filename = line.split('  ', 1)
        if filename in expected:
            raise ValueError('duplicate checksum entry')
        expected[filename] = digest
    if expected.get(path.name) != hashlib.sha256(path.read_bytes()).hexdigest():
        raise ValueError('archive SHA256SUMS verification failed')


def verify(path: Path, version: str, require_native: bool = False) -> None:
    check_checksum(path)
    if require_native and (platform.system() != 'Darwin' or platform.machine() != 'arm64'):
        raise ValueError('native release verification requires macOS arm64')
    with tempfile.TemporaryDirectory(prefix='binobf-release-') as folder:
        root = extract_checked(path, Path(folder), version)
        env = os.environ.copy()
        env['PYTHONPATH'] = str(root / 'src')
        env['PYTHONDONTWRITEBYTECODE'] = '1'
        env['BINOBF_REQUIRE_NATIVE'] = '1' if require_native else '0'
        result = subprocess.run([sys.executable, str(root / 'bin/binobf'), '--version'],
                                cwd=root, env=env, check=True, capture_output=True, text=True)
        if version not in result.stdout:
            raise ValueError('packaged CLI reports wrong version')
        # The same files shipped to users are exercised, not the original checkout.
        subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
                       cwd=root, env=env, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--native', action='store_true')
    args = parser.parse_args()
    try:
        verify(args.archive.resolve(), args.version, args.native)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.exit(2, f'verify_release: {exc}\n')
    print(f'Verified exact archive: {args.archive.name}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
