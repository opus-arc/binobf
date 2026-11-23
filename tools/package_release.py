#!/usr/bin/env python3
"""Create deterministic source-inclusive binobf release archives."""
from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FIXED_EPOCH = 946684800  # 2000-01-01; archive metadata, not a claimed build time.
TREES = ('bin', 'src', 'tests', 'tools', 'examples', 'docs', '.github')
ROOT_FILES = ('README.md', 'README.zh-CN.md', 'LICENSE', 'CHANGELOG.md', 'THIRD_PARTY_NOTICES.md', 'build.sh', '.gitignore')


def source_version(root: Path) -> str:
    tree = ast.parse((root / 'src/binobf/__init__.py').read_text(encoding='utf-8'))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id == '__version__' for x in node.targets):
            value = ast.literal_eval(node.value)
            if isinstance(value, str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', value):
                return value
    raise ValueError('missing literal semantic __version__ in src/binobf/__init__.py')


def selected_files(root: Path) -> list[Path]:
    found = []
    for name in ROOT_FILES:
        path = root / name
        if path.exists():
            found.append(path)
    for name in TREES:
        base = root / name
        if base.is_symlink():
            raise ValueError(f'release input directory cannot be a symlink: {base}')
        if base.exists():
            for path in base.rglob('*'):
                if '__pycache__' in path.parts or path.suffix in {'.pyc', '.pyo'}:
                    continue
                if path.is_symlink():
                    raise ValueError(f'release input cannot be a symlink: {path}')
                if path.is_file():
                    found.append(path)
    for required in ['README.md', 'LICENSE', 'bin/binobf', 'src/binobf/__init__.py', 'src/binobf/__main__.py']:
        if root / required not in found:
            raise ValueError(f'missing release input: {required}')
    if any(p.is_symlink() for p in found):
        raise ValueError('release input cannot be a symlink')
    return sorted(found, key=lambda p: p.relative_to(root).as_posix())


def build(root: Path, destination: Path, version: str, target: str, epoch: int = FIXED_EPOCH) -> list[Path]:
    if version != source_version(root):
        raise ValueError('requested release version does not match source __version__')
    if target == 'macos-arm64' and (platform.system() != 'Darwin' or platform.machine() != 'arm64'):
        raise ValueError('macos-arm64 release archives must be built and tested on native macOS arm64')
    if not 315532800 <= epoch <= 4354819199:
        raise ValueError('SOURCE_DATE_EPOCH must be within ZIP timestamp range 1980–2107')
    files = {}
    modes = {}
    for path in selected_files(root):
        name = path.relative_to(root).as_posix()
        files[name] = path.read_bytes()
        modes[name] = 0o755 if name.startswith('bin/') or name.endswith('.sh') else 0o644
    manifest = {
        'schema': 1, 'product': 'binobf', 'version': version, 'target': target,
        'distribution': 'Python 3 tool and source; native C compiler required only for VM object generation',
        'signing': 'No Developer ID signature or notarization is asserted for this Python distribution.',
        'files': {name: {'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'mode': oct(modes[name])}
                  for name, data in sorted(files.items())},
    }
    files['RELEASE_MANIFEST.json'] = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    modes['RELEASE_MANIFEST.json'] = 0o644
    prefix = f'binobf-v{version}'
    stem = f'{prefix}-{target}'
    destination.mkdir(parents=True, exist_ok=True)
    tar_path = destination / f'{stem}.tar.gz'
    with tar_path.open('wb') as raw:
        with gzip.GzipFile(filename='', fileobj=raw, mode='wb', compresslevel=9, mtime=epoch) as gz:
            with tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for name, data in sorted(files.items()):
                    item = tarfile.TarInfo(f'{prefix}/{name}')
                    item.size, item.mode, item.mtime = len(data), modes[name], epoch
                    item.uid = item.gid = 0
                    item.uname = item.gname = ''
                    archive.addfile(item, io.BytesIO(data))
    import datetime
    stamp = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).timetuple()[:6]
    zip_path = destination / f'{stem}.zip'
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(files.items()):
            item = zipfile.ZipInfo(f'{prefix}/{name}', stamp)
            item.create_system = 3
            item.external_attr = (stat.S_IFREG | modes[name]) << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(item, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    checksums = destination / 'SHA256SUMS'
    outputs = [tar_path, zip_path]
    checksums.write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in outputs), encoding='ascii')
    return outputs + [checksums]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--version')
    parser.add_argument('--platform', choices=['source', 'macos-arm64'], default='source')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    try:
        outputs = build(args.root.resolve(), args.output.resolve(), args.version or source_version(args.root),
                        args.platform, int(os.environ.get('SOURCE_DATE_EPOCH', FIXED_EPOCH)))
    except (OSError, ValueError, SyntaxError) as exc:
        parser.exit(2, f'package_release: {exc}\n')
    for path in outputs:
        print(path)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
