#!/bin/sh
set -eu
repository_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
archive_dir=$(mktemp -d "${TMPDIR:-/tmp}/poker-source-archive.XXXXXX")
trap 'rm -rf -- "$archive_dir"' EXIT HUP INT TERM
git -C "$repository_dir" archive HEAD | tar -x -C "$archive_dir"
cargo metadata --manifest-path "$archive_dir/Cargo.toml" --locked --offline --format-version 1 >/dev/null
echo "Committed source archive OK"
