# Compact channel transport

Status: binary transport, packed batches, sparse commitments, direct push, bounded priority queues and funding retry backoff implemented and browser-qualified. See `../benchmarks/binary-channel-transport.md`. Worker inventory sharding and shared-witness deduplication remain follow-up work; worker job buffers now transfer ownership.

## Findings

The latest deferred-payout test produces 38,272 terminal signatures per owner materialization. Across both owners and both players, each required signature is uploaded once. The current batch encoding stores a four-byte request index and a four-byte length before each 64-byte signature, then base64 encodes the entire batch. That is approximately 7,348,224 bytes uploaded at handover, excluding envelopes and relay forwarding. Canonically scheduled packed signatures require 4,898,816 bytes plus small batch headers: about one third less. These are byte counts calculated from the format and measured request counts, not network timing measurements.

Revocation commitment frames currently include a 32-byte slot for every node from each player, filling the other player's slots with zeros. Ownership is independently derivable from the graph. Across the player pair, half these commitment slots can be omitted outright. Binary framing also removes base64 expansion.

The relay currently pushes only change notifications. A recipient then requests an exchange to fetch payloads, adding a request/response cycle. Crypto workers receive cloned full inventories, including work assigned to other workers, and are initialized again for payout binding. Actual WebSocket bytes should be instrumented in the shared socket worker; old HTTP preparation counters do not describe this transport accurately.

## Implementation order

1. Instrument bytes sent and received at the WebSocket boundary by phase and message type. Separately time storage, serialization, queue delay, worker initialization, signing and peer verification. Count duplicate funding submissions and reconnect replay bytes. Record exact initial setup, first future tree, and handover timings on localhost and the hosted connection.
2. Replace base64-in-JSON with bounded binary WebSocket frames. Keep bytes binary through private workers, MessagePorts, encrypted persistence and the relay. Register opaque room handles at subscription so capabilities and full room identifiers are not repeated in each data frame. Preserve authorization, frame limits, epochs, durable acknowledgements and idempotence. Use transferable ArrayBuffers when ownership can move; do not detach buffers still needed for persistence or another consumer.
3. Send commitment values only for locally owned slots in canonical graph order. Bind the frame to the hand, owner and inventory. Require exactly the expected count and reconstruct the complete local inventory without transmitted placeholder zeros. Add a native roundtrip equivalence test and reject truncated, extra, reordered, wrong-owner and foreign-hand frames.
4. Pack preparation batches by deterministic assignment. Once a phase/owner inventory hash is agreed, derive each batch's request indices and lengths locally. Send batch ID and concatenated responses. Request retransmission by missing batch ranges. Retain exact inventory/phase binding and duplicate conflict detection. Adaptors can omit their redundant context digest on the wire only if the receiver reconstructs it from the locally authenticated request before ordinary verification; never omit cryptographic verification or change nonce generation.
5. Push opaque payloads directly to authenticated subscribers instead of notification-then-fetch. Persist before acknowledging; reconnect from the durable cursor. Bound unacknowledged bytes. Prioritize moves, retirement, payout binding and their acknowledgements above speculative preparation. Use small bulk chunks and limit already-buffered bytes so a priority queue actually reduces head-of-line delays.
6. Reduce local copying and repeated initialization. Dispatch only assigned missing request contexts to bounded crypto workers rather than cloning every inventory into every worker. Keep locally authenticated receipt bindings to the complete expected inventory. Avoid JSON decimal arrays for hashes, signatures, retirement secrets and witnesses. Encode a shared reveal opening or score witness once where both owner materializations use the same data, then reconstruct owner-specific witnesses locally at the existing disclosure barrier.
7. Deduplicate funding submission while waiting for confirmation. Use transaction ID state, confirmed/mempool observations and bounded retry/backoff. The prior browser test called publish repeatedly with the same initial funding transaction. This does not change the number of transactions spent, but wastes external API requests.

## Constraints and expected results

The entire inventory is already computed independently; do not add transaction-body exchange. A packed payout exchange still carries roughly 4.90 MB of cryptographic signatures under the present complete-tree design. Random signatures and hashes offer little useful compression once encoding overhead and zero slots are removed. Reducing the number of terminal signatures would require a separately qualified recovery/protocol change, not just serialization work. Do not reuse signing nonces to reduce payload size.

Measure byte savings separately from latency improvements. Binary and deterministic packing should reduce payout upload bytes by approximately 33%; sparse binary commitment frames should reduce that component by approximately 62.5% versus dense base64, excluding headers. Direct push and priority scheduling target latency rather than byte count. Do not promise a handover time until the hosted benchmark measures it.

## Acceptance

- Byte-for-byte agreement on reconstructed authorization requests and verified artifacts.
- Missing, duplicate, conflicting, truncated, wrong-phase and wrong-owner frame tests.
- Relay restart and browser restart during partial background preparation and payout binding.
- Bounded queues with foreground latency measured during simultaneous background work.
- Three browser hands, changing balances, auto redeal, sitting out and cashout; no gameplay broadcasts.
- Report aggregate uploads separately from relay egress and local worker copies; compare the same scenarios and conditions.
