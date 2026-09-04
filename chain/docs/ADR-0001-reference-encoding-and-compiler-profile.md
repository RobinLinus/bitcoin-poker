# ADR-0001: BP52-CHAIN-v1 reference encoding and compiler profile

Status: implementation-defined profile pending specification ratification.

The chain specification fixes protocol semantics but leaves several values
needed for cross-implementation byte agreement undefined. This implementation
uses the following fail-closed profile.

## Canonical encoding

- Integers are unsigned little-endian at their declared width.
- `Role`, `Street`, action, timeout-policy, node-kind, edge-kind, and Lamport
  purpose values are encoded by their explicit `repr(u8)` discriminants.
- Fixed arrays have no length prefix. Variable byte strings and vectors use a
  `u32` little-endian element/byte count followed by canonical elements.
- Decoders reject unknown discriminants, noncanonical lengths, overflow, and
  trailing bytes.
- The accepted deal uses its existing BP52-DEAL-v1 canonical codec.

## Deal-context extension

BP52-DEAL-v1 derives `game_id` from `network_id`, `funding_outpoint`, both
canonical identities, and a 32-byte `session_nonce`. The chain descriptor in
the supplied specification omits that nonce while requiring implementations
to rederive the identifier. The reference `ChainGameDescriptor` therefore
adds `deal_session_nonce: [u8; 32]` and includes it in its signed canonical
encoding. Omitting the value or merely trusting `deal.game_id` would not meet
the stated context-binding requirement.

The supplied descriptor likewise omits the fee-reserve amount even though the
funding equation, every `AmountState`, and the funding-readiness report require
it. The reference descriptor adds `fee_reserve_sat: u64`; the selected fee
policy must prove it covers the maximum executed path before funding.

Descriptor signatures are carried by a separate `SignedChainGameDescriptor`;
they are not recursively included in the descriptor or `chain_game_id`.
Verification produces an opaque `VerifiedChainDescriptor`. Public graph,
graph-root-exchange, and preauthorization-exchange entry points require that
capability, and concrete compilation additionally requires the opaque
`VerifiedAcceptedDeal`. Native verification can obtain it by replaying the
full DEAL archive; the browser path obtains the same capability by validating
the compact identity-signed DEAL attestation and accepted certificate.

## Terminal settlement

The reference v1 profile accepts only `TimeoutSettlementPolicy::PotOnly`.
`SlashRemainingStack` remains decodable as a reserved wire discriminant, but
descriptor validation, signed-descriptor verification, settlement accounting,
and compilation reject it. Every fold, timeout, and showdown therefore returns
each player's uncommitted remaining stack. Terminal branches distribute only
the pot according to the outcome and the unused fee reserve according to the
committed fee policy.

The fixed-limit profile supports implicit two-player all-ins without a new
action discriminant or caller-selected amount. Each nominal bet or raise is
capped at the minimum of the nominal target and both players' current-street
capacities (`committed + remaining`). Unmatchable excess therefore stays in the
larger player's remaining stack and is refunded by every terminal outcome. A
responder to an effective-stack-capped wager has only fold or call. Once a call
leaves either stack at zero, all later betting roots are omitted and the
ordinary two-party community reveal sequence runs directly to showdown. With
two players this requires no side pot.

## Funding-reference ambiguity

The v1 descriptor supplies only one 36-byte `funding_outpoint`. It does not
specify whether this is a pre-existing input/anchor or the root state output,
and it supplies neither the funding transaction inputs nor their previous
outputs. Treating it as an already-known root output is circular: that output's
script commits to the accepted deal, OTS bundles, and compiled graph, while the
accepted deal's game identifier already commits to the outpoint.

Compiler profile v2 resolves that cycle by interpreting `funding_outpoint` as
an already-created origin escrow. Preparation accepts and retains the exact
caller-observed origin `TxOut`, compiles every state, and exposes the exact
root-state `TxOut`. Materialization then accepts only the canonical
witness-independent activation template: version 2, zero locktime, one final
sequence input spending that origin with the bound parent output, and exactly
the root-state output at vout 0. Its fee is the checked difference between the
origin and root values. Every gameplay descendant is linked to
`activation_txid:0`; any outpoint, parent-output, output, fee, or transaction
shape substitution is rejected.

Supplying an origin `OutPoint` and `TxOut` to the compiler is not proof that the
UTXO exists, that both players contributed their complete stacks, or that its
spend authorization and pre-activation abort refunds satisfy the intended
protocol. The compiled game tree itself always refunds both uncommitted stack
remainders at terminal settlement. The browser integration supplies this
missing boundary with two exact staging contributions, a jointly authorized
origin, and a fully signed 144-block CSV abort refund. It verifies and durably
reads back that refund before releasing either funding signature. Other
integrations must provide an equivalent reviewed origin protocol; an observed
outpoint alone is never sufficient.

## Hashes and Merkle root

- `TaggedSHA256` is the BIP340 construction
  `SHA256(SHA256(tag) || SHA256(tag) || message)`.
- Logical-state digests and canonical node-record leaf hashes use ordinary
  SHA-256 over their canonical encodings.
- Node records are sorted lexicographically by `node_id`.
- The Merkle tree hashes `SHA256(left || right)`. At an odd level, the final
  hash is promoted unchanged rather than duplicated.
- `graph_root = SHA256(merkle_root)` as required by the specification.

## Reference compiler and fees

Compiler profile v8 is the sole current profile. It prices the reserve against
the exact descriptor-derived executed graph, uses direct semantic phase
transitions without intermediate advance nodes, and preserves the 33-transition
reference maximum. Construction debits every edge and fails on reserve
underflow or a dust terminal; independent verification checks the recorded
maximum path. It also binds the exact custom-signet identity, output-bound
two-party timeout authorization, descriptor-derived effective-stack all-ins,
the pre-existing-origin interpretation, and the opponent-preauthorization
action split. Previous compiler-profile identifiers are rejected rather than
migrated. Mainnet, testnet3, and regtest identifiers remain their
consensus-order genesis hashes. Every signet
identifier is a domain-separated commitment to signet's shared genesis plus
the consensus serialization of its complete challenge script; Mutinynet is
the first recognized signet. The raw shared signet genesis is rejected. This
prevents a backend connected to a different signet from satisfying the runtime
network check merely because both chains share the BIP325 genesis block.

The compiler emits version-2, zero-locktime transactions with one input and
fixed outputs. Runtime data remains absent from non-witness serialization.
Normal inputs use final sequence; timeout inputs use the node CSV sequence.
The fixed-fee prototype policy assigns an exact fee to every edge and rejects
dust or reserve underflow. Its identifier commits to the fee amount, dust
threshold, and reserve disposition.

Mainnet construction and broadcast are rejected. Regtest and explicitly
recognized signets are available for prototype execution while every
production-readiness gate remains enforced.

### Taproot signature profile

Every transaction authorization uses a 64-byte BIP340 signature with Taproot
`SIGHASH_DEFAULT`. Under BIP341 this commits to all inputs and all outputs with
the same transaction-binding semantics required here from `SIGHASH_ALL`.
Every Tapscript additionally executes `OP_SIZE 64 OP_EQUALVERIFY` immediately
before `OP_CHECKSIGVERIFY`. Consequently an explicit sighash byte cannot be
smuggled into a valid branch: `SIGHASH_ALL`, `SIGHASH_NONE`, `SIGHASH_SINGLE`,
and their `ANYONECANPAY` variants all produce a 65-byte witness element and
fail the size gate.

The compiler-profile identifier commits to this choice, the betting
authorization split, two-party timeout authorization, direct phase
transitions, and the effective-stack/runout rules. Predicate identifiers and
semantic program encodings are domain separated; artifacts from any other
profile identifier fail closed.

For each betting decision, only the opponent's fixed transaction signature is
exchanged. The actor selects a branch by producing their own 64-byte live
signature for that exact transaction. Betting actions therefore use no
Lamport key or witness. Alice and Bob instead have separate 24-bit Lamport
purposes for their exact showdown scores; Bob's transaction signature binds
the payout outputs, while his score certificate separately binds the dynamic
witness-only rank claim.

Every nonterminal P2TR state includes an additional hidden, unspendable
`OP_RETURN <BP52SC1> <logical_state_digest>` tapleaf. The digest covers the
canonical full logical state, including both remaining stacks, pot, fee
reserve, phase, actor, and betting counters. The leaf is omitted from the
executable-leaf API, but its TapLeaf hash changes the output key and therefore
the state transaction ID. No separate `OP_RETURN` output is created and no pot
field needs to be revealed on chain.

Every timeout leaf executes CSV and then verifies two canonical Alice/Bob
signatures over the same `SIGHASH_DEFAULT` digest. The defaulting player’s
signature is part of the fixed preauthorization exchange; the beneficiary’s
signature is retained privately and disclosed only when exercising the mature
timeout. The fixed signature makes output substitution impossible while the
private signature preserves beneficiary branch control.

Runtime witness builders require a `ConfirmedActiveNode` borrowed from a
non-cloneable `ChainMonitor`. The monitor is bound to the authenticated graph
root and checks the exact observed root outpoint/output plus a nonzero local
confirmation depth. Timeout signing additionally requires a borrowed
`MatureTimeout`; any observed tip regression halts authorization. Prepared
transactions are non-cloneable, remain tied to that live capability for
broadcast, and the broadcaster must report the descriptor's exact network
identifier from the same RPC session before submission. For custom signets,
that report must be derived from both the shared signet genesis and the RPC
node's complete `signet_challenge` value.

`ChainBackend` is sealed to the compiler's verified `CompiledGraph`, preventing
an application from substituting a self-consistent but unauthenticated graph
behind a live-signing capability.

## Literal-tree count erratum and fixed-limit profile

The supplied section 27 recurrences count each subtree root. With the first
Deal-Alice obligation as the gameplay root, they evaluate to 56,132 logical
nodes, hence 56,131 gameplay child transactions, and the stated maximum path
of 33 transactions after activation. The origin-to-root activation belongs to
the surrounding escrow protocol rather than the gameplay tree; counting from
the origin adds one transaction and produces a 34-transaction
origin-to-settlement path without adding a synthetic logical state.

Those figures describe the selected 100-big-blind fixed-limit profile. A
descriptor still prunes future betting after a matched all-in, but this profile
retains the complete four-wager-per-street topology. Its manifest node count,
gameplay transaction count, maximum path, Lamport inventory, and signature
request counts are derived from the actual graph rather than padded.

The reference implementation preserves the 33-transaction liveness upper
bound. Every descriptor has at most 56,132 logical nodes and 56,131 gameplay
transactions; adding activation yields at most 56,132 transaction templates.
The manifest reports the exact values for that descriptor. It does not invent
a witness-free gameplay no-op.

## Audited 100-big-blind profile

The audited profile accepts exactly ₿27,000 from each participant. The
surrounding origin funding transaction pays ₿500, creating a ₿53,500 origin;
activation pays another ₿500 and creates the ₿53,000 gameplay root. The chain
descriptor uses:

- `unit_sat = 100` (small blind 100, big blind 200);
- `max_bets_per_street = 4`;
- `alice_starting_stack_sat = bob_starting_stack_sat = 20,000`;
- `fee_reserve_sat = 13,000`;
- all three CSV delays equal to 144 blocks;
- `TimeoutSettlementPolicy::PotOnly`; and
- the class-fee policy `(betting=₿224, reveal=₿264, Alice showdown=₿2,203,
  Bob payout=₿3,089, timeout=₿232)` with a ₿330 dust threshold.

The resulting full-cap graph has 56,132 logical nodes, 56,131 possible
gameplay transactions, and a 33-transaction maximum executed path. Its
₿12,556 worst-path fee leaves ₿444 of reserve slack. Fold and timeout paths
return both uncommitted stack remainders and split every unused reserve unit
under the descriptor's named-remainder policy.

The public `HeadsUpFixedLimitV1Session` contains only the accepted deal,
funding outpoint, deal nonce, identity keys, button, reveal order, and split
remainder recipient. `HEADS_UP_FIXED_LIMIT_V1_PROFILE.descriptor(session)` fills
every fixed descriptor field. `origin_output(script_pubkey)` fixes the
₿53,500 origin value. After `prepare_chain_graph`, callers obtain the
session-specific committed P2TR output from `gameplay_root_output` and the only
accepted origin-to-root transaction from `activation_template`; they must not
reconstruct either from constants. The browser path stream-compiles the graph
and `validate_graph_summary` checks the complete profile and inventory before
activation.

The exact graph inventory is below. Community reveal order does not change the
counts because each street contains one obligation for each role; the button
does change the preflop action and action-timeout signers.

| Material | Alice (Alice button) | Bob (Alice button) | Alice (Bob button) | Bob (Bob button) |
| --- | ---: | ---: | ---: | ---: |
| Lamport score keys | 5,103 | 5,103 | 5,103 | 5,103 |
| Fixed preauthorizations exchanged before activation | 33,168 | 22,963 | 33,169 | 22,962 |
| Live signatures generated only for a selected branch | 8,930 | 24,239 | 8,930 | 24,239 |
| Accepted deal-share preimages retained locally | 9 | 9 | 9 | 9 |

The two fixed-signature counts always sum to 56,131: exactly one participant
preauthorizes each possible transaction. Reveal edges are preauthorized only
by the non-revealer, Alice-score edges only by Bob, and Bob-payout edges only
by Alice; the executing participant signs the selected edge live. Every
terminal path conserves the ₿53,000 gameplay root after fees, and every
emitted output remains above the ₿330 dust threshold.

At 64 bytes per fixed signature, the complete two-role inventory is 3,592,384
bytes. Each private runtime stores only its peer's non-derivable packed vector:
1,469,632 or 2,122,752 bytes for the two role counts above. Its own vector,
transaction requests, and templates are regenerated from the descriptor and
local signer as needed. Setup may transiently cache sorted request rows, then
drops them after exchange. Streaming compilation retains at most the compiled
parent/child Taproot states, and local Lamport use is tracked in a 1,276-byte
two-bit bitmap rather than an expanded secret-key vector.

The absolute fees assume a relay floor no greater than ₿1 per virtual
byte. Exhaustive enumeration of this 25-edge graph plus maximum permitted
witness element sizes gives the following safe ceilings:

| Class | Maximum vbytes | Largest tapscript |
| --- | ---: | ---: |
| Betting | 223 (charged 224) | 111 bytes |
| Reveal | 264 | 243 bytes |
| Alice showdown | 2,203 | 6,371 bytes |
| Bob payout | 3,089 | 8,863 bytes |
| Timeout | 232 | 116 bytes |

The Bob-payout ceiling includes a 129-byte control block, two terminal P2TR
outputs, two score certificates, fourteen maximum-length card openings, and
the complete evaluator witness. All executable scripts remain below the
10,000-byte consensus script limit and all ordinary witness elements remain at
or below 520 bytes. The 34-transaction activation-plus-gameplay maximum must be
broadcast as a confirmed sequence rather than an unconfirmed ancestor chain.
The profile is a prototype:
if the target relay raises its mempool minimum above ₿1 per virtual
byte, these immutable presigned transactions cannot fee-bump and must not be
activated. The Mutinynet Esplora API does not provide an authenticated promise
that its backing node's dynamic `mempoolminfee` will remain below that bound;
the deployment must treat an unavailable or higher relay-policy check as an
activation blocker. The profile cannot make an already exchanged transaction
package fee-adjustable without changing its committed txids and signatures.

## Security boundary

The logical compiler, native predicates, deterministic transaction templates,
and witness construction are testable without Bitcoin Core. Consensus and
standardness claims require the mandatory independent Bitcoin Core regtest
campaign; an in-process evaluator is not treated as a substitute.

Unused Lamport private keys have no plaintext persistence codec. The owning
crate seals only fresh keys whose complete secret material matches the expected
compiled public key. Its canonical XChaCha20-Poly1305 envelope authenticates
the format version, algorithm, chain game, exact node, purpose, nonce, and
ciphertext length. A successful seal erases the live owner; every error leaves
it usable. Opening consumes the ciphertext owner and re-derives all public
hashes before returning a fresh key. `LamportStorageKey` protects and zeroizes
the caller-supplied wrapping key, while durable OS/HSM custody, backup, and
single-writer coordination remain outside this library boundary.
