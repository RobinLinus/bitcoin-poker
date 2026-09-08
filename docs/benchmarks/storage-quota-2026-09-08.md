# Preparation storage exhaustion — September 8, 2026

The supplied log ended with `QuotaExceededError` while saving a background
preparation, followed by the same error while binding the next hand's payouts.
The table correctly stopped releasing signatures when persistence failed; the
underlying problem was unnecessary storage growth.

Changes:

- Checkpoint metadata, journal, artifact and obsolete snapshot deletions commit
  atomically. Overlapping checkpoint requests are serialized; engine snapshots
  and metadata are captured together before asynchronous encryption. Failed
  writes retain the previous complete recovery checkpoint.
- Once both peers have durably entered a prepared channel hand, discard bulk
  preparation payload copies from the source and merged inboxes. Keep control
  and revocation messages, replay cursors and message deduplication tombstones.
  Startup also compacts already completed preparations, after authenticating
  their saved journal and acquiring the corresponding player lock.
- Reclaim unused future hands after confirmed cashout and when reopening the app.
  The existing authenticated unactivated-journal check still protects selected
  and funded hands. Reclaim obsolete slots before allocating replacements.
- With less than 256 MiB of estimated remaining storage, only prepare the nearest
  future hand. Both players retain the same agreed buffer plan. A more distant
  preparation error cannot block an independently ready next hand.

Validation:

- 143 browser contract tests passed, including persistence concurrency, failed
  replacement, preparation cleanup barriers, retained control replay and cursors,
  and preparation under low storage headroom.
- Chrome IndexedDB failure injection aborted a replacement after deleting the
  previous artifact in the transaction. The previous artifact and metadata
  remained intact; retry committed successfully. Reproduce with
  `PLAYWRIGHT_MODULE=/path/to/playwright node tools/storage-regression.mjs`.
- Reopening an existing completed-game Chrome profile reduced encrypted checkpoint
  bytes from 203,841,160 to 32,616,665 (84% reclaimed) in 3,970 ms. The funded
  recovery artifact and defense package remained byte-for-byte identical.
- Two isolated persistent Chrome profiles completed three funded hands, automatic
  redeals in 3,814 / 4,637 ms, a deliberate cashout disconnect and reconnect, and
  confirmed payouts to both wallets. The final concurrency-qualified build also
  completed three hands, with 3,804 / 4,478 ms redeals and a 9,149 ms reconnect
  through confirmed cashout. The exact signed cashout was preserved.

Wallets, profiles, private artifacts and raw recovery transactions are excluded
from this report. Cleanup does not remove funded recovery checkpoints or wallet
keys. Exhaustion of physical disk space can still prevent any browser write;
failed durable writes must continue to stop signature release.
