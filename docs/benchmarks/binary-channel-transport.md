# Binary channel transport qualification

2026-09-06. Isolated headless Chrome, local relay, MutinyNet chain adapter. These are local relay measurements, not hosted latency measurements.

## Implemented

- Binary WebSocket frames: bounded metadata header plus raw byte attachments. Channel/table payloads, durable outboxes and encrypted snapshots retain bytes; no base64 in this path.
- Room handles avoid repeating authentication capabilities and full room identifiers after subscription.
- Canonical signing batches transmit batch ID plus packed responses, reconstructing request indices and sizes before ordinary cryptographic verification.
- Sparse commitments transmit locally owned slots only, split into 32 KiB chunks. Native checks reject missing, extra, zero, wrong-owner and foreign-hand commitments.
- Direct peer pushes, durable acknowledgement, replay after relay restart, 128 KiB delivery pages, bounded queues and foreground priority.
- Signing/verification job buffers transfer to crypto workers. Full worker inventory replication remains a separate optimization.
- Initial funding polling uses durable retry backoff and checks transaction status before publishing.

## Results

| Measurement | Result |
| --- | ---: |
| Initial playable setup | 18.531 s |
| Three future trees ready from test start | 59.614 s |
| First automatic handover | 7.375 s |
| Second automatic handover | 7.600 s |
| Payout upload bytes, both handovers combined | 9,859,264 |
| Payout upload bytes per handover, average | 4,929,632 |
| Total WebSocket uploads, all preparation/play/cashout | 93,307,982 |
| Total WebSocket downloads, all phases | 93,869,202 |
| WebSocket connections | 1 |

The old format's calculated payout payload was 7,348,224 bytes per handover before envelopes. The new measured upload is approximately 4.93 MB including envelopes, a reduction of about 33%. Totals also include initial preparation, three future trees and subsequent buffer replenishment; they are not just the active hand's data. Metadata is still a small JSON header; large cryptographic values are raw bytes. Counts exclude WebSocket/TCP/TLS framing.

Three hands passed with changing balances, 24 betting moves, sitting out and confirmed cashout. Funding remained unspent throughout cooperative play. One initial funding `publish` invocation occurred. The diagnostic also observed repeated cashout status/publish invocations while awaiting confirmation; the publish helper checks mempool state, so these counts are not actual broadcast counts.

Initial game: `0399dc2814602d89da9752bf2c5f36ccf04d8dbf75e1e066a975cb6d26561421`.
Confirmed cashout: `2c3f44ae6acc2b3a3a2f981d9372abb1ecab698448dae8d8307bd1dde9accce3`.

Separate relay browser test: 100 messages × 8,192 bytes delivered in seven uploads; 834,654 total upload bytes, zero idle exchanges over 200 idle polls. An actual relay restart passed replay without duplicate consumer delivery. Native channel tests include complete cooperative play and deferred payout restoration; all 105 browser contract tests passed, including malformed binary frames and failed durable push persistence. Relay unit/API tests passed.

## Remaining work

Worker inventory sharding, repeated-witness deduplication, missing-range recovery beyond existing durable replay, and hosted latency qualification are not included in this change. No claim is made that the entire earlier optimization plan is complete. The binary client and relay were rebuilt locally and deployed to the hosted server; see the deployment verification below.


## Hosted deployment verification

Deployed 2026-09-06 to https://3-122-53-147.sslip.io/. The Linux release build succeeded; the installed executable matches the build at SHA-256 `c415a05bbf3829721235e41ee31ae95e85f4c413c45a98db19ea1e5b95a85878`. Both relay and Caddy remained active, with a rollback executable retained.

Fifteen changed public assets, including session Wasm and its manifest, matched the local release byte-for-byte over valid HTTPS. An isolated Chrome check confirmed a secure lobby with HTTP 200 and no page errors. The hosted transport diagnostic delivered 100 × 8,192-byte simulated messages in seven uploads over one WebSocket: 834,654 bytes uploaded, 847,213 bytes downloaded, 3.391 s delivery, and zero idle exchanges. The production relay was not restarted again for this diagnostic, and no funds were spent. This is a transport smoke test, not a hosted three-hand latency benchmark. Reload both player tabs to use the new protocol.
