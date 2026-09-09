# Reconnecting during hand entry — September 8, 2026

The supplied 22:30 UTC log successfully reconnects to the relay and restores the
terminal parent hand, then fails while reopening the selected successor with
`Saved channel state is stale`. The favicon 404 is unrelated.

The current protocol's recovery revision is 1 both before entry and after entry.
Restoring a selected candidate before receiving its peer's Entry registers an
empty package at revision 1. Entry then adds one launch transaction to each
owner's recovery path, still at revision 1. The equal-revision byte comparison
incorrectly rejects this forward transition, including when reconnecting from
its saved pending-entry checkpoint.

The browser's monotonic check now recognizes this specific entry transition:
two empty paths become two single-launch paths, with unchanged version, hand,
funding, roots and other metadata, and no penalties. It still rejects reversal,
changed launch transactions, foreign hand/funding identities, and lower revisions.
This corrects current protocol validation; there is no schema migration, engine
fallback or saved-hand reset.

A native Wasm reproduction used isolated copies of completed test profiles,
reconstructed pre-entry state in memory, and received a real peer Entry. The
pending-entry package was byte-identical after journal/artifact restoration.
Before the fix, registering it over the empty revision-1 package raised the same
stale-state error; after the fix it succeeded. The test used an in-memory defense
store and fake chain adapter, with no broadcasts or changes to original profiles.

The browser contract suite passes 163 tests, including entry progression,
idempotent reconnect, changed identities, malformed path progression, conflicting
launches, reversal and lower-revision rejection.

The funded browser regression can restart each selected successor worker twice
before peer entry, then continue through automatic redealing and cashout:

```sh
PLAYWRIGHT_MODULE=/path/to/playwright node tools/playable-e2e.mjs \
  --funded --origin=http://127.0.0.1:3102 --hands=3 --reconnect-entry \
  --verify-retired-storage --cashout-reconnect \
  --keys-file=/private/path/wallets.keys --output=/private/tmp/entry-reconnect-e2e
```

This three-hand run passed: both browsers restored the selected entry worker
twice, completed all hands without page errors or gameplay broadcasts, and
compacted both retired parents. A separate interruption during cashout restored
the exact same transaction and reached confirmed payouts in 30,981 ms.
