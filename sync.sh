#!/usr/bin/env bash
# Keep the copies of ci/ in the image repos identical to this one.
#
#   ./sync.sh --manifest      rewrite ci/SHARED.sha256 (after changing a shared file)
#   ./sync.sh --check         fail if ci/SHARED.sha256 is out of date
#   ./sync.sh <image repo>    copy the shared files and the manifest into <image repo>/ci
#
# Shared = every file in ci/ except README.md and the manifest. Files an image
# repo keeps in its own ci/ (pins.tsv, test-cpu.sh) are not touched.
set -euo pipefail
cd "$(dirname "$0")/ci"

shared() { find . -maxdepth 1 -type f ! -name README.md ! -name SHARED.sha256 | sed 's|^\./||' | LC_ALL=C sort; }
manifest() { shared | xargs sha256sum; }

case ${1:-} in
  --manifest) manifest > SHARED.sha256; echo "wrote ci/SHARED.sha256 ($(wc -l < SHARED.sha256) files)" ;;
  --check) manifest | diff -u SHARED.sha256 - || { echo "ci/SHARED.sha256 is out of date: run ./sync.sh --manifest" >&2; exit 1; } ;;
  "" | -*) sed -n '2,9p' "../sync.sh" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
  *)
    [ -d "$1/.git" ] || [ -f "$1/.git" ] || { echo "sync: $1 is not a git checkout" >&2; exit 1; }
    manifest | diff -q SHARED.sha256 - >/dev/null || { echo "sync: ci/SHARED.sha256 is out of date: run ./sync.sh --manifest first" >&2; exit 1; }
    mkdir -p "$1/ci"
    shared | while read -r f; do install -m "$(stat -c %a "$f")" "$f" "$1/ci/$f"; done
    install -m 644 SHARED.sha256 "$1/ci/SHARED.sha256"
    echo "synced $(wc -l < SHARED.sha256) files into $1/ci"
    ;;
esac
