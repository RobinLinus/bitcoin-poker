# MutinyNet browser integration · 2026-09-05

The dedicated browser runner completed full-tree on-chain poker, fold, unilateral
refusal timeout and origin return on MutinyNet. The default application remains
practice; this is a same-operator integration page with two independently keyed
player workers, not a deployed two-device wallet/table.

## Setup measurements

The full graph has 56,132 nodes and 56,161 authorization requests per player.
Both players independently derive the inventory and verify all authorizations.
Four crypto workers per player retain generator checks and receiver verification.

| Trial | Setup through durable readiness | Player startup (separate) | Private reload |
| --- | ---: | ---: | ---: |
| Binary inventory, fresh 1 | 26.543 s | 0.488 s | 1.418 s |
| Binary inventory, fresh 2 | 26.700 s | 0.436 s | 0.942 s |
| Interrupted preparation, resumed | 26.760 s | — | 1.425 s |

Measured in Chromium 152 on the test machine (`hardwareConcurrency = 15`). These
are measured results, not a 30-second guarantee on other hardware. Fresh trials
use an unfunded origin and the real relay path, including authenticated dealing,
signing, verification and encrypted persistence. They publish no transactions.
The recovery measurement excludes the interrupted attempt and downtime.

Binary inventory transfer removes large repeated hex/JSON conversions at worker
startup. Construction takes approximately 9.4–9.9 seconds; initializing each
player's crypto pool after construction takes approximately 60–83 milliseconds.
The earlier retained-script funded trial used the older JSON ABI and took 34.796
seconds, missing the target. Its subsequent binary-ABI measurements are reported
separately rather than replacing that result. An earlier script build took 26.601
seconds and also completed a funded hand.

## Confirmed scenarios

| Scenario | Result | Fees |
| --- | --- | ---: |
| Full hand, retained scripts | [Confirmed payout](https://mutinynet.com/tx/f3e3b8bc1341720b67ce9438015862f4b3c325a983c5f1be20b6a935544cb029), 20 transactions | 68,200 sats |
| Fold | [Confirmed payout](https://mutinynet.com/tx/b7cb984e9250071619a1c2058826a9118037a66408cab972dc72471196506091) | 3,400 sats |
| Refusal timeout | [Confirmed payout](https://mutinynet.com/tx/b3ee8c140d7fbc91e2f34b06cb6f1895cd28375bce541f99074d1178694b6d98) | 2,000 sats |
| Origin return | [Confirmed return](https://mutinynet.com/tx/5cff31ab9ac1ab619b5a729e128c51899ae556770e5c79544dc24fe3f9c06115) | 3,000 sats |

Including the earlier short hand and full-hand qualification, aggregate fees were
240,100 test sats. The largest individual escrow was 176,500 sats. Wallet change
was preserved; no wallet sweep was performed.

Each game action was restored from its exact private pending transaction before
broadcast. The full hand additionally recovered after an Esplora outage and closed
browser tabs, using its pinned Wasm engine after a code upgrade. The setup recovery
trial refreshed during active preparation and completed by replaying the durable
relay log. Both players independently queried confirmed spends. Premature timeout
rejection was checked in Bitcoin Core; the live runner waited for CSV maturity.

The public [JSON report](mutinynet-browser-2026-09-05.json) identifies scripts,
Wasm hashes, bindings, counts, amounts and transaction IDs. Earlier and current
script fingerprints are retained explicitly. Commit `1ccb951` and the retained
reveal-metadata simplification intentionally change transaction IDs.

## Reproduce

Follow `apps/web/src/onchain/README.md`. Open `/tools/onchain-e2e` with the schema-4
MutinyNet test configuration. **List saved tests** restores archived campaigns
without re-entering a funding key. **Setup benchmark · no funding** measures fresh
full preparation without spending coins.

Native qualification passed the four managed Core session scenarios. Workspace
tests (excluding the diagnostic benchmark) passed; the benchmark is qualified in
release mode with the updated reference fingerprint. The browser contract suite
and strict Clippy checks for session, Wasm and relay also passed.
