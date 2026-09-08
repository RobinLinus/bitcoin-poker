# Cashout and reconnect regression — September 8, 2026

The supplied browser log recorded 43 repeats of `Wasm artifact request failed
(404): transaction` during cashout. A deployment retires the page's global asset
prefix even when the transaction inspector is unchanged. The generic poll error
label incorrectly displayed a connection retry for this permanent asset error.

The loader now retries a retired Wasm URL at the current unversioned endpoint,
verifying the bytes against the page's original manifest. Changed Wasm is still
rejected. Manual reconnect checks for a newer app and reloads before creating
workers under a retired prefix. Non-network failures pause with their error
instead of repeatedly displaying a reconnect status. A durable, fully signed
cashout can publish and confirm without rejoining the relay or waiting for its
opponent; its exact transaction is retained.

Validation:

- 137 browser contract tests passed, including retired asset verification,
  changed-artifact rejection, a signed cashout with an unavailable relay, and
  permanent cashout failure retaining the saved transaction.
- Chrome executed the real transaction inspector (115,436 bytes, ABI 2) after
  its versioned URL deliberately returned 404.
- Two isolated persistent Chrome profiles played a complete MutinyNet hand.
  One profile was disconnected after saving both cashout signatures and before
  publication, then reconnected. Its native session restored in 3,027 ms. Both
  players cashed out; the interrupted player retained the exact saved transaction.
  Reconnect through confirmation took 18,563 ms, including block confirmation.
- A simulated deployment change triggered a page reload and restored the completed
  cashout from the actual encrypted browser profile in 3,917 ms, with no page errors.

- Opening the same saved seat in a second tab failed clearly in 2,091 ms and
  cleared the Reconnect busy state, instead of waiting indefinitely for its lock.

Reproduce the funded integration with two authorized wallet keys in a private file:

```sh
PLAYWRIGHT_MODULE=/path/to/playwright node tools/playable-e2e.mjs \
  --funded --origin=http://127.0.0.1:3118 --hands=1 --cashout-reconnect \
  --keys-file=/private/path/wallets.keys --output=/private/path/new-run
```

Keep the resulting persistent profiles private: they contain wallet and recovery
material. Do not substitute JSON browser storage exports for those profiles.
