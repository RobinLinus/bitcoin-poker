#!/bin/sh
# Verify that the patched Bulletproof backend will survive a source archive.

set -eu

allow_nested_vcs=0
archive_smoke=0

usage() {
    echo "usage: $0 [--allow-nested-vcs] [--archive-smoke]"
    echo
    echo "  --allow-nested-vcs  permit the local upstream checkout metadata"
    echo "  --archive-smoke     check locked Cargo metadata from git archive"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --allow-nested-vcs)
            allow_nested_vcs=1
            ;;
        --archive-smoke)
            archive_smoke=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_dir=$(CDPATH= cd -- "${script_dir}/.." && pwd)
vendor_dir="${repository_dir}/dealing/vendor/bulletproofs"
digest_file="${vendor_dir}/SOURCE_TREE_SHA256"

if [ ! -f "${vendor_dir}/src/accelerated_msm.rs" ]; then
    echo "FAIL: patched accelerated_msm.rs is missing from the vendored backend" >&2
    exit 1
fi

nested_vcs=$(find "$vendor_dir" -type d -name .git -print -quit)
if [ -n "$nested_vcs" ] && [ "$allow_nested_vcs" -ne 1 ]; then
    echo "FAIL: nested Git metadata would turn the patched backend into a gitlink" >&2
    echo "      ${nested_vcs}" >&2
    exit 1
fi

if [ ! -f "$digest_file" ]; then
    echo "FAIL: missing vendored source digest" >&2
    exit 1
fi
expected=$(sed -n '1p' "$digest_file")

hash_stream() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    else
        shasum -a 256 | awk '{print $1}'
    fi
}

actual=$(
    find "$vendor_dir" -type f \
        ! -path "${vendor_dir}/.git/*" \
        ! -path "${vendor_dir}/target/*" \
        ! -name SOURCE_TREE_SHA256 -print |
        LC_ALL=C sort |
        while IFS= read -r file; do
            relative=${file#"${vendor_dir}"/}
            size=$(wc -c < "$file" | tr -d ' ')
            printf '%s\000%s\000' "$relative" "$size"
            command cat "$file"
        done |
        hash_stream
)

if [ "$actual" != "$expected" ]; then
    echo "FAIL: vendored Bulletproof source digest mismatch" >&2
    echo "      expected ${expected}" >&2
    echo "      actual   ${actual}" >&2
    exit 1
fi

if git -C "$repository_dir" rev-parse --show-toplevel >/dev/null 2>&1; then
    if git -C "$repository_dir" ls-files --stage |
        awk '$1 == "160000" { found = 1 } END { exit !found }'
    then
        echo "FAIL: repository index contains a gitlink" >&2
        exit 1
    fi
    if ! git -C "$repository_dir" ls-files --error-unmatch \
        dealing/vendor/bulletproofs/src/accelerated_msm.rs >/dev/null 2>&1
    then
        echo "FAIL: accelerated backend source is not an ordinary tracked file" >&2
        exit 1
    fi
elif [ "$archive_smoke" -eq 1 ]; then
    echo "FAIL: --archive-smoke requires a repository commit" >&2
    exit 1
fi

if [ "$archive_smoke" -eq 1 ]; then
    archive_dir=$(mktemp -d "${TMPDIR:-/tmp}/bp52-source-archive.XXXXXX")
    cleanup() {
        rm -rf -- "$archive_dir"
    }
    trap cleanup EXIT HUP INT TERM
    git -C "$repository_dir" archive HEAD | tar -x -C "$archive_dir"
    cargo metadata --manifest-path "$archive_dir/dealing/Cargo.toml" \
        --locked --offline --format-version 1 >/dev/null
    cargo metadata --manifest-path "$archive_dir/dealing/benchmarks/wasm/Cargo.toml" \
        --locked --offline --format-version 1 >/dev/null
    cargo metadata --manifest-path "$archive_dir/chain/Cargo.toml" \
        --locked --offline --format-version 1 >/dev/null
    cargo metadata --manifest-path "$archive_dir/client/Cargo.toml" \
        --locked --offline --format-version 1 >/dev/null
    cargo metadata --manifest-path "$archive_dir/client-cli/Cargo.toml" \
        --locked --offline --format-version 1 >/dev/null
fi

echo "source integrity OK: ${actual}"
