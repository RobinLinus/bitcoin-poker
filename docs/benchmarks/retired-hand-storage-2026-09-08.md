# Retired hand storage — September 8, 2026

The supplied 21:57–22:06 UTC browser log ends in `QuotaExceededError` during
`bindPayouts`, then pauses the table. Earlier preparation cleanup removed inbox
copies and abandoned candidates, but retained the native artifact and journal
of every completed hand: approximately 30 MB per retired hand.

Fully retired hands now retain their seed, terms, successor authorization proof,
and independent whole-hand justice package. Their large native checkpoints are
removed only after the completed retirement exchange, durable playable successor,
matching funding/hand identity, and exact final defense revision are verified.
The successor redirect is saved first. Replacement and deletion share one
IndexedDB transaction; failure retains the full old checkpoint. Active hands and
incomplete handovers are ineligible. Startup retries cleanup of older retired
hands under their exclusive player locks. Retired records cannot be opened as
playable native sessions.

Validation:

- 162 browser contract tests passed, including mismatched authorization, missing
  retirement acknowledgement, pending work, stale defense, corrupted journals,
  failed replacement, and cleanup with an already retired successor.
- An isolated copy of a completed three-hand Chrome profile shrank from
  94,638,954 to 33,394,622 encrypted checkpoint bytes after compacting two parents:
  **61,244,332 bytes reclaimed**. Wallet storage and independent defense packages
  remained byte-for-byte unchanged. The current checkpoint restored in the
  actual Session Wasm engine. The original profile was preserved.
- Injecting `QuotaExceededError` into that real IndexedDB replacement after
  deletion requests rolled back all changes, preserving both full checkpoints.
- Two isolated browsers completed five funded MutinyNet hands through the local
  relay, automatically compacting four parents each. Every retired parent had no
  remaining artifact/journal and retained its whole-hand penalty. Gameplay and
  redealing caused no broadcasts. A deliberate cashout disconnect recovered the
  exact same transaction and both wallets received confirmed payouts. No page
  errors occurred. Redeal-to-action times after the first transition were about
  four seconds; this change targets storage growth rather than setup latency.

Reproduce the funded integration with explicitly authorized test wallet keys:

```sh
PLAYWRIGHT_MODULE=/path/to/playwright node tools/playable-e2e.mjs \
  --funded --origin=http://127.0.0.1:3102 --hands=5 \
  --verify-retired-storage --cashout-reconnect \
  --keys-file=/private/path/wallets.keys --output=/private/tmp/retired-storage-e2e
```

Physical disk exhaustion can still prevent writes. Persistence failure must
continue to stop signature release. The test does not establish a fixed total
storage cap: active candidates and compact historical defense records still
occupy storage. Private profiles, keys and raw recovery packages are excluded
from this report.
