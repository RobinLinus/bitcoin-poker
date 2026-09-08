# Consecutive playable hands

The playable table now has a mutually confirmed **Next hand** flow. The same two
browser seats move to a fresh hand without exchanging another invitation. Poker
balances carry forward, the dealer alternates between physical seats, and each
hand generates fresh identities, reveal keys, score keys and a shuffle.

Funding reuses both confirmed payout outputs and one sponsor output for the fee
top-up. The host enters the disposable faucet key for that top-up; the key is not
retained. The cancellation transaction restores the two prior payout amounts to
their original owners and returns the remaining top-up to the sponsor. Both
players save this return before releasing payout-spending signatures.

## Validation

- The native integration test completes two consecutive hands with asymmetric
  carried stacks and dealer rotation, including restoration of pending actions.
- All four managed Bitcoin Core scenarios pass. The showdown scenario rolls its
  payout into a new hand, deals again with the opposite dealer and settles a
  fold. The fold and timeout scenarios also confirm rollover funding and the
  multi-recipient cancellation return. These Core tests use smaller test stacks.
- All 31 browser contract tests pass, including consent binding, role changes,
  insufficient-stack handling, durable large payout messages and funding errors.
- Strict Clippy for session/Wasm/relay and the browser artifact manifest check pass.

The packaged session Wasm is
`d74e0886301977df81667d9214c4a3dfd3bb2c3b6b16470046c27d0a9fc3f10b`.

## MutinyNet browser checkpoint

Both existing seats independently restored the confirmed payout
`f81de3f854f62dad865bd3a2b09324345d8d5d7d2a8b59383133c701e3fb57a9`
from [the original full hand](playable-table.md), chose Next hand, and automatically
entered hand 2 (`8ffb1267810564a8fd125d77da7e21ca56c04408c1d13a912ed0e5ac279ef2d3`).
The host carried 19,400 poker sats and the guest 20,600; the guest is now dealer.
The old payout amounts also include unused fee reserve (31,800 and 33,000 sats),
which is reused by the next funding transaction rather than counted as poker winnings.

The live second hand is saved before funding. The supplied faucet wallet has
confirmed outputs of 43,500 and 2,046 sats, while the current 2× fee policy needs
one sponsor output of at least 68,530 sats, including change. An additional faucet
payment was requested. The live payout-spend, full-size preparation and second
MutinyNet settlement have **not** been claimed as tested; the completed two-hand
chain test above ran against managed Bitcoin Core regtest.
