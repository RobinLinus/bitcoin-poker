#!/bin/sh
# Run the BP52 Core qualification suites against an isolated, real Bitcoin
# Core regtest node. This script never downloads Core or a container image.

set -eu

mode=auto
suite=all
require_core=0
keep_datadir=0
native_started=0
docker_started=0
node_datadir=
container_name=

image=${BP52_CORE_IMAGE:-bitcoin/bitcoin@sha256:da25cedc66b1daefff9f412ee196c901a899c3fa68a33b20849c3e08b5c40d63}
wallet=${BP52_CORE_WALLET_NAME:-bp52-core-qualification}
rpc_port=$((24000 + ($$ % 10000)))

usage() {
    echo "usage: $0 [--native | --docker] [--suite all|dlog|dlog-graph|session|channel] [--require] [--keep-datadir]"
    echo
    echo "  --native         require bitcoind and bitcoin-cli on PATH"
    echo "  --docker         require an already-cached ${image} image"
    echo "  --suite NAME     run dlog leaf and graph tests, or only dlog-graph (default: all)"
    echo "  --require        fail instead of skip when neither backend is available"
    echo "  --keep-datadir   retain the native temporary datadir for inspection"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --native)
            mode=native
            ;;
        --docker)
            mode=docker
            ;;
        --require)
            require_core=1
            ;;
        --suite)
            if [ "$#" -lt 2 ]; then
                echo "error: --suite requires all, dlog, dlog-graph, session, or channel" >&2
                exit 2
            fi
            suite=$2
            shift
            ;;
        --keep-datadir)
            keep_datadir=1
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

case "$suite" in
    all|dlog|dlog-graph|session|channel)
        ;;
    *)
        echo "error: --suite requires all, dlog, dlog-graph, session, or channel" >&2
        exit 2
        ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
workspace_dir=$(CDPATH= cd -- "${script_dir}/.." && pwd)

bitcoind_path=${BP52_BITCOIND:-}
bitcoin_cli_path=${BP52_BITCOIN_CLI:-}
docker_path=${BP52_DOCKER:-}
cargo_path=${BP52_CARGO:-cargo}

if [ -z "$bitcoind_path" ]; then
    bitcoind_path=$(command -v bitcoind 2>/dev/null || true)
fi
if [ -z "$bitcoin_cli_path" ]; then
    bitcoin_cli_path=$(command -v bitcoin-cli 2>/dev/null || true)
fi
if [ -z "$docker_path" ]; then
    docker_path=$(command -v docker 2>/dev/null || true)
fi

native_available=0
if [ -n "$bitcoind_path" ] && [ -n "$bitcoin_cli_path" ]; then
    native_available=1
fi

docker_available=0
if [ "$mode" != native ] && { [ "$mode" = docker ] || [ "$native_available" -ne 1 ]; }; then
    if [ -n "$docker_path" ] && "$docker_path" image inspect "$image" >/dev/null 2>&1; then
        docker_available=1
    fi
fi

case "$mode" in
    auto)
        if [ "$native_available" -eq 1 ]; then
            mode=native
        elif [ "$docker_available" -eq 1 ]; then
            mode=docker
        else
            echo "SKIP: no native bitcoind/bitcoin-cli pair and no cached ${image} image" >&2
            echo "      install Bitcoin Core or pre-load the image; this script never downloads it" >&2
            if [ "$require_core" -eq 1 ]; then
                exit 1
            fi
            exit 0
        fi
        ;;
    native)
        if [ "$native_available" -ne 1 ]; then
            echo "FAIL: --native requires both bitcoind and bitcoin-cli" >&2
            exit 1
        fi
        ;;
    docker)
        if [ "$docker_available" -ne 1 ]; then
            echo "FAIL: --docker requires Docker and the already-cached ${image} image" >&2
            echo "      refusing to pull an image implicitly" >&2
            exit 1
        fi
        ;;
esac

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM

    if [ "$native_started" -eq 1 ]; then
        "$bitcoin_cli_path" -regtest -datadir="$node_datadir" \
            -rpcport="$rpc_port" stop >/dev/null 2>&1 || true
    fi
    if [ "$docker_started" -eq 1 ]; then
        "$docker_path" stop "$container_name" >/dev/null 2>&1 || true
    fi
    if [ -n "$node_datadir" ]; then
        if [ "$keep_datadir" -eq 1 ]; then
            echo "kept native regtest datadir: $node_datadir" >&2
        else
            rm -rf -- "$node_datadir"
        fi
    fi

    exit "$status"
}
trap cleanup EXIT HUP INT TERM

run_rust_suite() {
    case "$suite" in
        channel)
            "$cargo_path" test -p poker-bitcoin --test channel_core_regtest --locked \
                -- --ignored --test-threads=1 --nocapture
            "$cargo_path" test -p poker-settlement --test settlement_core_regtest --locked \
                -- --ignored --exact bitcoin_core_regtest_channel_hand --nocapture
            ;;
        all|dlog)
            "$cargo_path" test --manifest-path Cargo.toml \
                -p dealer-bitcoin --test bitcoin_core_regtest --locked \
                -- --ignored --exact bitcoin_core_regtest_dealer --nocapture
            "$cargo_path" test -p poker-bitcoin --test dealer_core_regtest --locked \
                -- --ignored --exact bitcoin_core_regtest_dealer_showdown --nocapture
            "$cargo_path" test -p poker-settlement --test settlement_core_regtest --locked \
                -- --ignored --exact bitcoin_core_regtest_settlement --nocapture
            ;;
        session)
            "$cargo_path" test -p poker-session --test hand --locked \
                -- --ignored --test-threads=1 --nocapture
            ;;
        dlog-graph)
            "$cargo_path" test -p poker-settlement --test settlement_core_regtest --locked \
                -- --ignored --exact bitcoin_core_regtest_settlement --nocapture
            ;;
    esac
}

run_test_native() {
    node_datadir=$(mktemp -d "${TMPDIR:-/tmp}/bp52-core-regtest.XXXXXX")
    echo "Starting isolated native Bitcoin Core regtest on RPC port ${rpc_port}" >&2
    "$bitcoind_path" -regtest -datadir="$node_datadir" -rpcport="$rpc_port" \
        -server=1 -listen=0 -acceptnonstdtxn=0 -fallbackfee=0.00001000 -daemonwait
    native_started=1

    "$bitcoin_cli_path" -regtest -datadir="$node_datadir" -rpcport="$rpc_port" \
        -rpcwait createwallet "$wallet" >/dev/null

    (
        cd "$workspace_dir"
        export BP52_CORE_ACTIVE=1
        export BP52_REQUIRE_BITCOIND=1
        export BP52_BITCOIN_CLI="$bitcoin_cli_path"
        export BP52_CORE_DATADIR="$node_datadir"
        export BP52_CORE_RPC_PORT="$rpc_port"
        export BP52_CORE_WALLET="$wallet"
        run_rust_suite
    )
}

run_test_docker() {
    container_name="bp52-core-regtest-$$"
    echo "Starting isolated Bitcoin Core regtest from cached ${image}" >&2
    "$docker_path" run --detach --rm --pull=never --name "$container_name" "$image" \
        -regtest -server=1 -listen=0 -acceptnonstdtxn=0 -fallbackfee=0.00001000 \
        -rpcport="$rpc_port" -printtoconsole=1 >/dev/null
    docker_started=1

    attempts=0
    until "$docker_path" exec --user bitcoin:bitcoin "$container_name" bitcoin-cli \
        -regtest -datadir=/home/bitcoin/.bitcoin -rpcport="$rpc_port" \
        getblockchaininfo >/dev/null 2>&1
    do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 60 ]; then
            echo "FAIL: Bitcoin Core did not become RPC-ready within 60 seconds" >&2
            "$docker_path" logs "$container_name" >&2 || true
            return 1
        fi
        sleep 1
    done

    "$docker_path" exec --user bitcoin:bitcoin "$container_name" bitcoin-cli \
        -regtest -datadir=/home/bitcoin/.bitcoin -rpcport="$rpc_port" \
        createwallet "$wallet" >/dev/null

    (
        cd "$workspace_dir"
        export BP52_CORE_ACTIVE=1
        export BP52_REQUIRE_BITCOIND=1
        export BP52_DOCKER="$docker_path"
        export BP52_CORE_DOCKER_CONTAINER="$container_name"
        export BP52_CORE_RPC_PORT="$rpc_port"
        export BP52_CORE_WALLET="$wallet"
        run_rust_suite
    )
}

if [ "$mode" = native ]; then
    run_test_native
else
    run_test_docker
fi
