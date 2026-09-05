# DLOG52 on-chain opening extension v1

This research contract extension leaves DLOG52-DEAL-v1 proofs and certificates
unchanged. It supplies the reusable opening disclosure missing from the
single-card signature gate. It is part of the on-chain poker implementation,
not an off-chain gameplay protocol. Native graph integration and managed Core
tests exist; browser integration and MutinyNet release qualification remain.

For each reveal slot, the opponent supplies 52 Schnorr adaptor preauthorizations
for the exact reveal transaction's BIP341 SIGHASH_DEFAULT digest. Candidate v
uses the signed point T_v = V_revealer - v*M. The revealer knows its discrete
log gamma for exactly its accepted contribution. Adapting that preauthorization
with gamma produces an ordinary BIP340 signature. From the confirmed signature
and the corresponding preauthorization, the opponent extracts gamma, recovers v,
and rechecks V = v*M + gamma*G. It retains the opening for future card signatures.

Each slot requires a distinct opponent signing key. A three-slot flop reveal
checks three such signatures plus the revealer's live identity signature. A
completed signature for one slot cannot satisfy another slot's CHECKSIG. The
full graph descriptor must bind these keys and reject duplicates and overlaps
with identity or other signing capabilities. The signer must never distribute
an ordinary signature under a reveal key for a transaction whose signature is
supposed to disclose an opening.

Public preauthorization context binds deal ID, graph ID, node ID, revealer,
slot, authorization key, full commitment, and exact sighash. The recipient
verifies all 52 candidates before activation. Completion validates the supplied
opening and final Bitcoin signature. Extraction verifies the final signature,
checks its relationship to a stored adaptor, and checks the full signed-point
commitment. Merely parsing a witness or observing a relay message never counts
as confirmation.

The wire package is exactly 3,412 bytes: a 32-byte context digest followed by
52 canonical 65-byte musig2 adaptor signatures in increasing value order.
The context digest is tagged SHA256 with tag `DLOG52/onchain-reveal-context/v1`
over deal ID, graph ID, node ID, one-byte revealer, one-byte slot, x-only
authorizer, sighash, and the compressed signed commitment, in that order.
Here graph ID means the preactivation game/profile commitment, not a later
Merkle root of transaction records; this avoids a circular script commitment.

The implementation uses musig2 0.4.0's single-signer BIP340 adaptor API, with its
pure Rust k256 backend. The wrapper derives a separate nonce seed from caller
auxiliary entropy, full context, candidate value, and encryption point. This
binding is essential: reusing the same nonce across different encryption points
under the same signing key can disclose that key. Public adaptor packages are
durable, exact, and retransmitted unchanged. Secret material is never logged.

Disclosure and failure behavior:

| Phase | Published material | Result |
| --- | --- | --- |
| Deal Alice | Bob's openings at slots 0 and 2, extracted from his reveal spend | Alice combines them with her own private openings. |
| Deal Bob | Alice's openings at slots 1 and 3 | Bob combines them with his own private openings. |
| First community reveal | First revealer's slot openings | The other player can derive the board keys; first revealer still lacks the other's openings. |
| Second community reveal | Second revealer's slot openings | Both can derive board keys for later transaction sighashes. |
| Showdown | Candidate-key authentication of the owner's two hole cards and five board cards | Script authenticates card values and evaluates the claimed hand. |
| Refusal | No normal reveal spend; existing CSV timeout branch matures | Non-defaulting player settles the defined timeout without obtaining the missing opening. |

An on-chain hole-share disclosure makes one contribution public, not the full
hole card. This differs from the base specification's private SignedShareReveal
delivery. The extension does not publish the owner's other contribution and
does not send stage-0 private reveal messages into the public certificate.
The dlog setup transcript remains unchanged. No card is opened before its
graph-authorized phase.

Use real transaction sighashes and execute witnesses in a standard-policy
Bitcoin Core node. Required negative cases include mismatched contexts, modified
adaptors, wrong openings, wrong signatures, duplicated slot keys, and both
first- and second-revealer refusal. This extension does not claim an independent
cryptographic audit.

References: [BIP340 adaptor signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#adaptor-signatures),
[musig2 adaptor API](https://docs.rs/musig2/0.4.0/musig2/adaptor/index.html).
