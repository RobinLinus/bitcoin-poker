# Playable table qualification · 2026-09-05

The root page under the schema-4 MutinyNet configuration is now the playable
table. Two independently keyed browser seats joined through an invitation and
completed a real full-graph hand using the visible poker buttons.

The tested path was Raise/Call preflop, Bet/Call on the flop, then Check/Check on
the turn and river. Hole delivery, board reveals and showdown published
automatically. Each player independently confirmed the chain before changing
cards, stacks, pot or legal actions. The guest won with a pair of eights against
the host's pair of threes.

[Payout transaction](https://mutinynet.com/tx/f81de3f854f62dad865bd3a2b09324345d8d5d7d2a8b59383133c701e3fb57a9)
confirmed in block 3,403,026, paying 31,800 sats to the host and 33,000 sats to the
guest. The 20 transactions used 68,200 test sats in fees. The
[public record](playable-table-2026-09-05.json) includes every transaction ID.
Development and network interruptions are included in the block span; this is
an integration result, not a setup-latency measurement.

The guest refreshed after submitting a call, and both seats reloaded during the
hand. Exact pending transactions and confirmed accounting recovered without
re-entering the faucet key. A later engine independently replayed the settled
journal and verified all candidate signatures before displaying the opponent's
public showdown cards; the older transaction-signing engine remained pinned.
Both seats then reloaded the settled hand with matching payouts and public cards.
The guest's New table button returned to the create/join lobby.

The final session runtime passed all four managed Core scenarios: full hand,
fold, origin return and unilateral timeout. Native tests cover card visibility,
showdown display and pending-transaction recovery. All 25 browser contract tests,
strict Clippy for the session/Wasm/relay, and the Wasm manifest check passed.

This MVP uses host-sponsored test funding for both seats, a 12-block turn deadline,
and fresh identities for each new table. General wallet/cash-out UX and trustless
multi-depositor funding remain outside this test-table flow.
