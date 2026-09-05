#!/bin/sh
# Verify the four dlog-only workspace dependency graphs.
set -eu
repository_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "${1:-}" in
    "") ;;
    --archive-smoke)
        archive_dir=$(mktemp -d "${TMPDIR:-/tmp}/dlog-source-archive.XXXXXX")
        trap 'rm -rf -- "$archive_dir"' EXIT HUP INT TERM
        git -C "$repository_dir" archive HEAD | tar -x -C "$archive_dir"
        repository_dir=$archive_dir
        ;;
    *) echo "usage: $0 [--archive-smoke]" >&2; exit 2 ;;
esac
for workspace in dealing-dlog chain client client-cli; do
    cargo metadata --manifest-path "$repository_dir/$workspace/Cargo.toml" \
        --locked --offline --format-version 1 >/dev/null
done
echo "Dlog workspace source integrity OK"
