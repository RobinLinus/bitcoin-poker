#!/bin/sh
set -eu
repository_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cargo metadata --manifest-path "$repository_dir/Cargo.toml" --locked --offline --format-version 1 >/dev/null
echo "Workspace dependency graph OK"
