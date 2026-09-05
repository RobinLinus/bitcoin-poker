# Roadmap

The on-chain settlement graph is the backbone. Cooperative play is a later
optimization. The native backbone is implemented; see [status](status.md).

## Milestone 1: funded on-chain browser poker

1. Expose `SettlementGraph`, preparation, and verified snapshot restoration
   through a dedicated browser binding. Generate random, durable real keys.
2. Connect funding to the exact Taproot origin and graph budget. The current
   P2WSH funding utility and diagnostic bridge are not this integration.
3. Exchange and persist all required authorizations before activation. Preserve
   wallet/dealing secrets, score-key usage, observed openings, and pending spends.
4. Drive table controls from locally selected graph edges. Advance displayed
   state only on confirmed transactions; expose unilateral timeout claims.
5. Cover normal calls/raises, capped and short-stack play, folds, forced runouts,
   showdown/payout, abort/refund, refresh, reconnect, and opponent refusal.
6. Benchmark preparation of the full reference graph on browsers, derive actual
   deployment reserves/fees, and qualify complete hands on MutinyNet.
7. Deploy and run two-device sessions with rematch and recovery. Make block waits,
   opponent waits, pending transactions, and explorer links clear.

Done means a real funded dealer-protocol hand whose played transitions confirm
on-chain, with correct payouts and usable unilateral exits. A standalone card
gate, local scripted hand, or cooperative cashout does not satisfy the milestone.

## Milestone 2: cooperative optimization

Add authenticated cooperative moves and accelerated settlement over the same
on-chain recovery contract. Keep sufficient durable material to fall back to
confirmed graph transitions when the peer stops cooperating. Practice move logs
are test/application infrastructure, not proof of funded enforceability.

## Deferred

Mainnet, independent cryptographic audit, production fee bumping, watchtowers,
long-lived multi-hand channels, matchmaking, tournaments, and native UI parity.
