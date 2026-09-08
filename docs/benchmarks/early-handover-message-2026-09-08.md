# Early successor message — September 8, 2026

The supplied browser log ends at 10:23:11.600 UTC with a successor worker's
`advance` failing with `previous hand not retired`. That error propagates to
the completed parent table and appears as “Play paused”.

Both browsers independently persist the previous hand's retirement and its
acknowledgement. One can therefore authorize the successor and send its first
hole-card move while the other is still completing local handover. The next
hand's worker continued polling and passed that early `Move` to the native
engine, whose retirement guard correctly rejected it.

The worker now retains early `Move` and `Ack` frames in its encrypted deferred
queue until the engine reports `playAllowed`. The queue and transport cursor
are checkpointed together. Entry and readiness messages continue processing,
so the parent can obtain the successor certificate and finish retirement.
After authorization, deferred messages go through the normal native validation
and recovery-registration path. No retirement checks were removed and no
transaction or Wasm formats changed.

Validation:

- The new regression fails against the old worker with the exact logged error.
- 150 browser contract tests pass. They cover durable deferral, entry progress,
  processing after authorization, no duplicate processing, restore after a
  cursor advance, and continued rejection of invalid frames.
- Two separate persistent Chrome profiles completed three funded hands with
  `tools/playable-e2e.mjs --delay-handoff --cashout-reconnect`. The receiver's
  play authorization was deliberately delayed five seconds. One early frame
  was deferred, play continued, and both wallets received confirmed cashout.
  Reconnecting during cashout preserved the exact signed transaction.

Deployment changes only `apps/web/src/onchain/channel-worker.js`. Reload both
players' tabs and reconnect to load it; retain existing wallet and game storage.
