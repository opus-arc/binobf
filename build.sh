#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$root"
python=${PYTHON:-python3}
target=source
version=
test_only=0

if [ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ]; then
    target=macos-arm64
fi

while [ "$#" -gt 0 ]; do
    case "$1" in
        --platform) target=${2:?missing platform}; shift 2 ;;
        --version) version=${2:?missing version}; shift 2 ;;
        --test-only) test_only=1; shift ;;
        *) printf '%s\n' "Usage: ./build.sh [--platform source|macos-arm64] [--version VERSION] [--test-only]" >&2; exit 2 ;;
    esac
done

export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="$root/src"
"$python" -m unittest discover -s tests -v
"$python" bin/binobf --version
[ "$test_only" -eq 0 ] || exit 0

if [ -z "$version" ]; then
    version=$("$python" -c 'from binobf import __version__; print(__version__)')
fi
"$python" tools/package_release.py --version "$version" --platform "$target" --output dist

if [ "$target" = macos-arm64 ]; then
    "$python" tools/verify_release.py "dist/binobf-v$version-$target.tar.gz" --version "$version" --native
    "$python" tools/verify_release.py "dist/binobf-v$version-$target.zip" --version "$version" --native
else
    "$python" tools/verify_release.py "dist/binobf-v$version-$target.tar.gz" --version "$version"
    "$python" tools/verify_release.py "dist/binobf-v$version-$target.zip" --version "$version"
fi
