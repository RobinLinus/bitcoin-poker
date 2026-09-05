# Browser Wasm build

From `client/`, run `scripts/build-browser-wasm.sh --docker` to build the
wallet, origin, transaction inspector, and dlog52 modules using the pinned build
container. Use `--validate-only` to build without publishing, or `--check` to
verify the checked-in artifacts against the manifest.

`browser-wasm-artifacts.json` defines the required exports and size limits.
The dlog52 module builds from `dealing-dlog/`; the other modules build from
`client/`. The dlog secret worker owns private dealing state. The legacy proof,
game, and chain Wasm modules are removed.
