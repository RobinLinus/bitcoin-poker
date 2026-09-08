# Balance-independent future hands

Future channel hands now prepare one internal tree per slot instead of predicting balance-specific candidates. The bounded background buffer holds three future hands. Each slot has fresh dealer/score material and revocation commitments. The final payout signatures and entry authorization remain withheld until handover.

## Transaction identity

Node identities derive from the hand root and action path, without logical balance digests. Taproot compilation uses that path identity rather than the amount-state digest. Accounting still retains and verifies its full semantic digest. For future hands with both stacks above the maximum capped wager (₿4,800 under the current rules), the hand context commits the total channel value rather than its split. Nonterminal output values are unchanged along each path, so their transactions and signing digests stay identical as balances change.

A changed first transaction already propagates different TXIDs through all descendants. Static script templates and topology can be shared across hands; fresh card, score, and revocation commitments still change their instantiated scripts.

## Handover

The browser binds the verified previous hand's resulting balances, rebuilds the exact payout inventory, and retains authenticated artifacts only when their full signing contexts match. It signs and verifies all missing terminal transactions, including folds, timeouts and showdown payouts. Only a complete inventory permits launch signatures, candidate selection and funding-root authorization. Balance binding is one-time; conflicting rebinding and changed total funding are rejected. Authenticated partial checkpoints resume without granting readiness.

Short stacks can change legal betting topology. Those hands use exact-balance preparation using the already prepared deck instead of reusing incompatible internal signatures.

## Qualification — 2026-09-06

- 81 browser unit tests passed.
- 25 native tests passed across poker-session, poker-session-wasm and poker-settlement; six Core-dependent tests were excluded from that ordinary run.
- Two managed Bitcoin Core channel tests passed separately, covering contests and complete onchain hand materializations.
- The new native rebind regression proves 17,889 authorizations per owner remain reusable, including 1,306 adaptor packages. The remaining 38,272 requests per owner are terminal signatures. It checks partial-checkpoint restoration, activation rejection before completion, short-stack/changed-total rejection, conflicting rebinding, exact payout digests and completion after binding.
- Browser integration passed three full hands (24 betting actions), two automatic redeals, sitting out and confirmed cashout. Balances changed from [20000, 20000] to [19800, 20200], [19600, 20400], and [19400, 20600]. No gameplay or redeal transactions were broadcast.
- Initial setup including funding confirmation: 27.54 seconds. Three future internal trees ready at 81.45 seconds from setup start (53.90 seconds after initial activation).
- Handover times: 8.02 and 9.47 seconds. These include payout binding/signing and the hand retirement protocol; they are not instant handovers.
- Initial game: ff145c882d0ed11fbf73ffd012cc20e5605ff3e21560a95ac16028e3e4fc0e92.

Timings are indicative measurements on a shared desktop, not an isolated performance guarantee. The test intentionally waits for the buffer before playing to measure reuse; normal table play does not wait for all future slots.
