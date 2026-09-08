# Next-hand scheduling — September 8, 2026

The reusable internal tree is already prepared during play. The remaining
critical path binds the final balances into payouts, signs and verifies those
payouts, activates the successor, retires the old hand, and exchanges hole cards.

This update:

- Lets local candidate selection overlap the peer's final readiness message.
  The matching payout-binding check still precedes entry-frame exchange.
- Prioritizes final payout work over short background crypto jobs, scoped to
  the channel and local seat. Other tables and the opposite seat remain free
  to progress. Errors and worker termination release the browser-owned lock.
- Avoids starting distant preparation jobs during handover and card exchanges.
  Normal play continues filling the same bounded three-slot buffer.
- Gives an authorized successor the fast protocol polling schedule during entry.
  Unselected candidates remain on the quiet background schedule.

Do not hold the shared CPU lock around whole tree construction: an already
running construction can then delay foreground finalization by several seconds.
Construction remains independent; priority gates only short crypto jobs.

## Browser measurements

Two separate persistent Chrome profiles, a local release-mode relay, real
MutinyNet funding and payouts, and automatic full-hand play. Timings start at
the completed hand and end when the next hand is actionable, including hole
cards. They exclude initial funding confirmation.

| Build | Consecutive-hand transitions |
| --- | --- |
| Saved baseline release | 4,013 / 4,489 / 4,392 ms |
| Optimized release, before restricting priority to its channel seat | 4,031 / 4,217 / 4,196 ms |
| Final channel-scoped release | 3,544 / 3,582 ms |

These are small sequential samples on one machine with different shuffled
hands, not a latency guarantee. The observed improvement is incremental;
balance-dependent payout work remains on the critical path. Debug-relay runs
were excluded from the release comparison.

All three release runs completed their hands and confirmed cashout. The final
run also disconnected after saving the fully signed cashout, then reconnected
and completed the exact same transaction. Cooperative moves and redeals did
not broadcast transactions.

147 browser contract tests passed. The disposable-browser check
`tools/redeal-priority-regression.mjs` exercises the shipped crypto worker with
an engine stub: foreground progress, background resumption, error release, and
unrelated-table independence. Full funded runs used the real engine.

The session Wasm and transaction protocol are unchanged. Deployment includes
only `channel-worker.js`, `crypto-worker.js`, `hand-buffer.js`, and
`table-session.js`; both players reload to use the new scheduler. No wallet,
profile, private checkpoint, or transaction data is included in this report.
