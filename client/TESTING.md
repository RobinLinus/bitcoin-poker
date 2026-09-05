# Testing

From this directory:

```sh
cargo test --workspace --locked
node scripts/test-browser.mjs
scripts/build-browser-wasm.sh --check
```

Browser contracts cover the retained dlog application and shared infrastructure.
They do not qualify funded browser play; that integration is unfinished.
For native on-chain qualification run
`../chain/scripts/bitcoin-core-regtest.sh --docker --suite dlog --require`.
