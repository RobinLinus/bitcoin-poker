# WebSocket transport qualification

The browser now shares one multiplexed WebSocket across table and private crypto workers. Push notifications eliminate idle network polling. Exchanges combine seat restoration, durable acknowledgements, bounded uploads and peer-only delivery. Signing pipelines its next batch while earlier batches are in flight.

Outgoing bytes use one immutable encrypted page for both replay and local delivery. Page metadata lets table consumers skip signature payloads without decrypting them. Epoch changes reset remote cursors and replay the original outgoing order; local message IDs suppress duplicates. The server remains transient.

## Verification (2026-09-06)

- 82 onchain browser-side tests pass, including failed storage, lost responses, reconnects, duplicate suppression, batching, idle traffic and filtered reads.
- 23 relay tests pass, including matching-epoch acknowledgements, capability isolation and batched exchanges.
- The real browser transport test sent 100 messages of 8 KiB each in four upload exchanges over one shared WebSocket. Local delivery took 127.71ms. Across 200 idle receive checks it made zero network exchanges. Senders downloaded none of their own payloads.
- Restarting the actual relay reconnected the socket and delivered exactly the next new message without duplicate delivery.

Three full poker hands, 24 betting actions, automatic redealing, sitting out and confirmed cashout passed over WebSocket. Only funding and cashout transaction IDs were published.

- Game: `a7bf3fc18f6abb1076ba045ea38eab47aabd536daaac19344e78a2aac16eaa4f`.
- Cashout: `a4f64695b1d8f5146aa0f9da1754610c1482aeac22dbe46d19fc05414f7d8e68`.
- Setup including funding confirmation: 26.37s.
- Eight prepared candidates ready at 264.31s after setup started.
- Move acceptance: median 304.84ms, p95 1,093.09ms across 24 samples.
- Prepared handover: 1.43s. A later balance-cache miss took 33.35s; networking changes do not eliminate unprepared cryptographic work.

After adding filtered reads and single-copy persistence, a further fresh hand and cashout passed:

- Game: `b60e6a2b64d6a827d589cfbb56b397b970ab28f30e24171212cede81a466807b`.
- Cashout: `c3909aeddad9eb59beaa38cb2547da9fb98b955973218ede905cbae0f9e7b20a`.
- Setup including confirmation: 21.15s. Eight betting actions completed without errors.

These are functional and indicative timing checks on a shared desktop, not an isolated performance comparison or latency guarantee. Use `/tools/relay-e2e` for transport qualification without funding any game.
