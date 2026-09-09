# No-limit Hold’em on a fixed transaction sequence

Status: proposed protocol design, September 2026. This is a construction and
qualification specification, not a proven protocol or a working Bitcoin Script
implementation. It incorporates the user's proposal of alternating game moves
and local fraud-proof opportunities on a fixed sequence.

## 1. Construction in one sentence

Presign a bounded sequence of fixed-value transaction outputs; carry the actual
poker state in authenticated witness data; provide local fraud exits and exact,
contestable payout transactions at every position.

The full betting history no longer chooses transaction outpoints. It chooses the
witnesses on a fixed sequence. This addresses the exponential history expansion
in the current implementation. The remaining enumeration is over sequence
positions and payout amounts, plus a small number of authorization classes.

Our first reference construction separates payout claimants. A later optimization
may share their transaction bodies, but must preserve accountability. Do not
assume that optimization in the reference inventory or performance estimates.

## 2. Scope and security contract

- Two players, a fixed accepted private deal, fixed blinds, no additional poker
  funds during a hand, and exact integer amounts. Fee reserves are separate.
- Either participant can recover without new signatures from the other after
  activation. The opponent may stop responding at any boundary.
- Ordinary off-chain play remains possible. Unilateral recovery publishes the
  fixed sequence and follows the same rules on-chain.
- An honest participant validates every received transition, stores recovery
  material before acknowledging it, and monitors during contest periods. This
  retains the project's browser-online assumption; it introduces no relay judge,
  custody service, or server recovery monitor.
- Fold, voluntary protocol surrender and timeout return uncommitted balances
  and award only the contested pot to the beneficiary, consistently with the
  current timeout policy. A surrender is an explicit protocol action on the
  assigned turn, including a reveal obligation; it is distinct from an ordinary
  poker Fold and cannot override an already settled outcome.
- Proposed fraud remedy: the proven offender loses the protected funds to the
  counterparty, as with the existing justice mechanism. This is distinct from
  ordinary timeout accounting. If fraud must also use pot-only accounting, the
  justice paths need another exact-payout design; do not silently substitute it.

Safety objectives: no profitable invalid transition, no false accusation of an
honest signer, no outdated payout after acknowledged progress, and no exposure
of future private cards. Liveness includes a bounded path to payout after the
opponent stops cooperating.

## 3. Parameters and payout granularity

Let:

- `B`: big blind in integer base units.
- `q`: smallest represented monetary quantum, dividing both blinds and the
  represented balances. Full base-unit no-limit uses `q = 1`.
- `V`: total poker funds, excluding fee reserve.
- `S = ceil(V / (2B))`: an upper bound on effective stack depth in BB for this
  fixed total. The exact hand may have unequal stacks and a lower effective cap.
- `L`: allocated sequence positions, including initial and terminal capacity.
- `K = V/q + 1`: a simple upper bound on payout distributions.
- `c`: contest delay; `t`: additional response allowance.

One payout distribution is determined by Alice's amount `a`; Bob receives
`V - a`. There is no second independent payout dimension. Fees and unused reserve
refunds are added separately using the fixed policy for that sequence position.

An important correction to the initial rough estimate: 201 distributions for
two 100BB stacks assumes whole-BB payouts. Ordinary 0.5BB small blinds already
produce half-BB results when folded. A representable half-BB quantum gives 401
distributions. If `B = 100` base units and `q = 1`, the bound is 20,001 instead.
Minimum raise size bounds sequence length; it does not force amounts onto a BB
grid. Do not label a coarser sizing profile full base-unit no-limit.

## 4. A bounded abstract state machine

The public state carries only what is necessary to validate the next operation:

```
phase, street, next_actor
uncommitted_A, uncommitted_B, collected_pot
wager_A, wager_B, last_full_raise
check / acted / reopening flags, big_blind_option
reveal_progress, public-card/score references where available
terminal_kind and terminal allocation when settled
```

The total `uncommitted_A + uncommitted_B + collected_pot + wager_A + wager_B`
must always equal `V`. The current wager is derivable from street contributions.
Use exact checked arithmetic and explicit uncalled-excess normalization.

The static context binds channel, hand slot, accepted deal, rules, sequence
position and purpose. Context does not need to be redundantly sent as hundreds
of signed bits: the public keys and scripts already fix it.

The operation set contains Check, Call, BetTo, RaiseTo, Fold, protocol surrender,
the assigned card-share deliveries, showdown operations, and forced Pass. Pass
is allowed only when the fixed slot owner differs from `next_actor`; it copies
the state unchanged. It never grants an extra poker action or permits skipping
a reveal. Terminal states cannot resume betting.

### Sequence-length bound

For the following abstract bound, normalize wagers to effective capacity, group
each participant's phase-specific card delivery into one operation, and use two
showdown operations. Concrete Script resource limits may require further splits.

Across streets, track the sum of closed-street matched contributions plus the
current largest effective contribution. It is monotone and at most the effective
stack. Every full Bet/Raise increases it by at least `B`; at most one final short
all-in can fall below that increment in heads-up play. Conservatively there are
at most `S` aggressive operations.

There are at most two passive Check/Call operations per street, including the
preflop limp/big-blind-option case: at most eight. Allow one additional terminal
Fold/surrender. Add eight grouped card-share deliveries and two showdown
operations. This gives at most `S + 19` semantic operations.

Betting alternates internally within each of its four street segments. Treat
the eight reveal operations and two showdown operations as separate segments:
at most fourteen segments total. At most one forced Pass is needed to align
each segment with a strictly alternating slot owner. Hence a conservative
abstract bound is `S + 33` progress operations, plus the initial position.

Under these assumptions, 208 allocated positions cover the 100BB example and
408 cover the 200BB example with slack. They are engineering allocations, not
claims that the maximum legal hand consists of exactly 208 or 408 moves. Prove
the bound against an independent rules model, including short blinds and all-in
runouts, before freezing the format. Recalculate if a reveal/showdown operation
must be split or other protocol operations enter the main sequence.

## 5. Authenticate transitions without permitting false fraud proofs

At position `i`, the actor signs a structured transition certificate:

```
M_i = (echoed_predecessor_state, operation, claimed_successor_state)
```

Use independent bit/field commitments, scoped to this actor, hand, position and
purpose. The opponent's prior certificate authenticates the echoed predecessor;
the actor's certificate authenticates its own copy of that predecessor, its
operation and its resulting state. Initial state authority comes from a
two-party initialization certificate, bound to the preceding settled hand.

The normal spend verifies certificate authenticity and equality of the supplied
predecessor and its signed echo. It also verifies required cryptographic card
delivery evidence. Full poker transition correctness can be challenged locally.
Checking cheap invariants directly in normal spends is permitted as an
optimization, but must not leave a gap in the fraud predicates.

**A local fraud proof against Bob must use Bob's signed input, action and output.**
It must not allow Alice to substitute a different Alice-signed predecessor and
then accuse Bob of having processed that different input incorrectly. Alice can
create another signature with her own key even after publishing the first one.

This message-echo pattern is informed by the message-linking construction in
[BitVMX, section 3](https://bitvmx.org/knowledge/bitvmx-a-cpu-for-universal-computation-on-bitcoin).
The poker protocol's safety proof remains separate from that source.

Each bit has two secret preimages and public hashes. Revealing both values for
the same context supplies an equivocation proof. Keys are one-use per position
and purpose; packet retries resend identical certificates. Native persistence
must prevent a crash from causing an honest player to sign a second value.

Do not assume a hash of a serialized state is sufficient. Scripts must verify
the actual fields used in the predicate. The baseline uses explicitly signed
fields and does not assume OP_CAT, signature introspection, or arbitrary
cross-transaction witness reads. See the original
[BitVM commitment construction](https://bitvm.org/bitvm.pdf).

## 6. Fixed transaction sequence

For each owner materialization, build outputs `U_0 ... U_(L-1)` and fixed
continuations `T_i: U_i -> U_(i+1)`.

```
U_i -- fixed T_i, variable authenticated witness --> U_(i+1)
 |
 +-- local fraud / equivocation --> counterparty recovery
 |
 +-- Claim(i, Alice, a) --> protected payout outputs
 |
 +-- Claim(i, Bob,   a) --> protected payout outputs
```

All ordinary operation leaves at `U_i` authorize the same `T_i` body: identical
inputs, sequences, amounts and output scripts. Neither chosen bet size nor card
opening changes its txid. The appropriate normal leaf still has its own Bitcoin
sighash and may need a separate preauthorization. A common transaction body is
not a common signature for every leaf.

The peer's presignature fixes the transaction; the actor supplies its own live
signature and authenticated witness. Use script-only outputs or an explicitly
authorized cooperative path; there must be no participant-controlled unilateral
key-path bypass. Retain both existing owner roots for hand retirement until a
separate construction establishes that one root is sufficient.

The witness-independence and Tapleaf-specific signature constraints follow
[BIP 341](https://bips.dev/341/) and [BIP 342](https://bips.dev/342/).

### Conservative on-chain timing

Normal continuation from `U_i` waits `c` blocks. Local fraud can be proved
immediately. A timeout claim waits `c + t` blocks from confirmation of `U_i`.
This prevents a pre-recorded continuation from immediately moving past the
opponent's opportunity to challenge the previous witness.

For a simple first inventory, give all ordinary payout claims the same sequence
delay `c + t`, including terminal claims. This lets reasons share a body within
one claimant/amount. Faster terminal payouts require another sequence value and
therefore another transaction family; count it explicitly if added.

Protected payout outputs have a fresh contest delay `c` measured from their own
confirmation. CSV checks on one input do not add: two comparisons against `c`
and `t` enforce only their maximum. Encode `c + t` explicitly when needed.
See [BIP 68](https://bips.dev/68/) and [BIP 112](https://bips.dev/112/).

This conservative construction can take approximately `L*c` blocks to unroll
a long existing prefix. That is a material usability cost, unlike off-chain
preparation latency. Removing per-position waits is a later protocol change
requiring a proof that old evidence cannot be bypassed by replaying saved moves.

## 7. Exact payout candidates at every position

For each position, claimant `p`, and distribution `a`, preauthorize a claim
transaction `Q_(i,p,a)`. Its two protected outputs have amounts:

```
Alice: a     + fixed_remaining_reserve_refund_A(i)
Bob:   V - a + fixed_remaining_reserve_refund_B(i)
```

The fixed schedule also pays the actual claim fee. A dedicated claim certificate
`E_(i,p)` states the reason, the relevant echoed state/transition and allocation
`a`. Its signature is created only when this participant irreversibly enters
unilateral closing; it is not part of speculative preparation.

The claim leaf authenticates `E`, binds it to this position, claimant and exact
distribution, and enforces the applicable temporal/role gate. Local checks and
fraud predicates together establish that:

- Fold/surrender pays the other player the pot and returns unmatched/uncommitted
  amounts correctly.
- Timeout applies to the actual outstanding obligation and cannot override an
  already terminal hand.
- Showdown follows the accepted deal, completed reveals, verified scores, and
  the exact tie/odd-unit rule.
- A claimant relying on its own most recent state also supplies the predecessor
  echo and transition needed to check it. A self-authenticated amount alone is
  not evidence of entitlement.

Each payout output has a normal recipient-key spend after the contest delay and
immediate counterparty justice paths for an invalid claim, claimant equivocation
or use of a retired exit. Both outputs stay protected; paying one immediately
would let part of a fraudulent allocation escape.

For a concrete accounting example, start with ₿1,000 per player. After both
contribute ₿30 preflop, the collected pot is ₿60 and each has ₿970 uncommitted.
On the flop Bob wagers ₿20 and Alice folds. Return Bob's unmatched ₿20 and award
him the collected ₿60: the poker payout is Alice ₿970, Bob ₿1,030. The fixed
continuation outputs did not move those intermediate wager amounts between
players; their witnesses recorded them. The selected payout template finally
encodes the exact distribution, plus separately accounted reserve refunds.

Justice spends and eventual wallet sweeps can be created when needed because
their scripts directly authorize the beneficiary; they need no future opponent
signature. They still count toward executed transactions, fees and recovery work.
Never confuse presigned template count with the total transactions of an exit.

### Why the reference construction separates claimants

If a common payout output has an unconditional Alice-retirement justice leaf,
Bob could publish a payout through his own claim path and use Alice's disclosed
retirement secret to seize it. Alice never published the obsolete claim.

Separate `Q_(i,A,a)` and `Q_(i,B,a)` output scripts avoid that ambiguity. Penalty
conditions identify the actual claimant by the fixed transaction body. Its own
live Bitcoin claim signature is retained locally and never shared during play,
so the opponent cannot publish that claimant's obsolete payout to frame them.
This is in addition to, not a substitute for, owner-specific hand roots.

A possible optimization uses shared payout bodies whose justice leaves require
the accused player's claim certificate for this exact `(i,a)`, as well as the
fraud or retirement evidence. An honest player must never both release that
claim certificate and retire/resume from the same position. This is a separate
false-framing proof and crash-safety obligation. Do not halve the reference
inventory until that construction passes adversarial tests.

## 8. Off-chain progress and retirement of old payouts

Simply retaining every old timeout claim is unsafe after later cards or actions
have been disclosed. Give each participant a distinct exit-retirement secret at
each position. It retires that participant's payout claims from `U_i`, never the
selected continuation transaction `T_i`.

The update handshake is:

1. Actor constructs its one-use transition certificate and complete enforceable
   continuation under both owner variants, persists it, then sends the move.
2. Receiver verifies authenticity, full poker/card correctness and equality of
   both variants. It persists the continuation and recovery state.
3. Each participant releases its exit-retirement secret only after it possesses
   the enforceable replacement continuation. Persist outgoing revocations before
   sending them. Acknowledgments establish which exits have been retired.
4. Gate subsequent private-information release on the required durable update
   and retirement barriers. Record interrupted states explicitly.

If cooperation fails before acknowledgment, the actor can publish its already
enforceable move before the old timeout matures. If the receiver has acknowledged
and retired its exit, publishing that obsolete claim is punishable. A locally
signed peer response is not by itself proof it was timely: do not let a late
responder manufacture such a signature after a legitimate timeout and confiscate
the honest timeout claimant's funds.

When a claim signature/certificate is released or a unilateral close begins,
freeze the corresponding off-chain session. Do not resume it or release
retirement material that could be used to frame that now-public claim.

Existing `poker-session/src/channel.rs` and the retirement barrier are useful
implementation patterns. Their fixed-tree proof does not automatically establish
this new protocol. Hand-to-hand retirement remains a distinct barrier.

## 9. Local fraud predicates and example

Candidate predicates include:

| Predicate | Signed evidence and check |
| --- | --- |
| Wrong actor/phase | Accused's predecessor echo, operation and phase/actor fields |
| Invalid wager | Accused's minimum-raise, outstanding wager, stacks, reopening state and selected amount |
| Wrong accounting | Accused's input/output amounts; recompute the local transfer and conservation |
| Invalid Pass/advance | Accused's actor/phase and whether a mandatory operation was skipped |
| Invalid payout claim | Claimant's authenticated premise, reason and exact amount matching this payout candidate |
| Equivocation | Both preimages for an accused participant's bit in the same context |
| Retired payout | Claimant-specific retirement evidence for this sequence position |

For example, Bob's signed input says the current wager is 4BB and the last full
raise is 3BB. Bob signs a raise to 5BB while his signed stack and reopening fields
exclude the short-all-in exception. Alice can prove invalidity using those Bob
signed fields. She cannot supply her own newly signed assertion that the last
raise was 3BB when Bob actually signed an input where it was 1BB.

For every predicate, specify both the invalid-state condition and the witness
authentication checks. Testing only successful fraud proofs is insufficient:
maliciously chosen premises against an honest certificate must fail.

Cryptographic card openings should remain directly checked against the accepted
deal where the existing gate supports that. A signed boolean saying “revealed”
is not disclosure. Hidden hole cards must stay hidden until the required phase;
do not put their values into the public betting-state certificate. Slot-variable
reveal placement needs new authorization contexts, even if the underlying dealer
protocol and score verifier are reused.

## 10. Counts and resource budget

Ignoring small root/continuation overhead, a shared-claimant design has `L*K`
payout templates per owner. The claimant-separated reference has `2*L*K` per
owner, or `4*L*K` for the current two-owner channel structure.

| Effective depth bound | Positions | BB / quantum | Distributions | Shared candidates, one owner | Reference candidates, one owner |
| --- | ---: | ---: | ---: | ---: | ---: |
| 100BB | 208 | 1 (illustrative whole-BB payouts) | 201 | 41,808 | 83,616 |
| 100BB | 208 | 2 (half-BB quantum) | 401 | 83,408 | 166,816 |
| 100BB | 208 | 100 (e.g. BB = ₿100, quantum = ₿1) | 20,001 | 4,160,208 | 8,320,416 |
| 200BB | 408 | 1 (illustrative whole-BB payouts) | 401 | 163,608 | 327,216 |
| 200BB | 408 | 2 (half-BB quantum) | 801 | 326,808 | 653,616 |

The current reference has 56,131 post-activation gameplay transactions, before
comparing matching owner/contest constructions. The original approximately
42,000 estimate is a useful lower-level inventory example, not yet the count of
a complete standard-blind, two-owner implementation.

Track at least four separate quantities: non-witness transaction bodies,
Tapleaf-specific signatures, script bytes and witness bytes. Hash-based state
certificates add substantial work that the transaction count alone conceals.

For illustration, six amount fields of `w` bits, repeated as predecessor,
actor-signed echo and successor, already require `18*w` Lamport preimages before
flags, action fields, claim data or card evidence. At 16 bits this is 9,216 raw
preimage bytes; at 64 bits it is 1,152 stack items and exceeds the 1,000-item
limit before other data. Use bounded widths derived from `V/q`, remove redundant
fields and qualify each leaf. Do not just reuse unrestricted u64 certificates.

Tapscript still imposes stack and element limits, and standard transaction relay
adds policy constraints. Verify actual generated transactions against the target
Core node. Sources: [BIP 342 resource limits](https://bips.dev/342/).

Calculate fixed fees from each transaction class's bounded witness size at
0.1 ₿/vB, rounding final fees up. The longest fallback path determines the needed
reserve. Budget claim sweeps and fraud witnesses too. Fee sponsorship/CPFP is a
separate design choice; presigned descendants cannot accept arbitrary txid changes.

Every nonzero payout output must satisfy relay policy. Tiny poker balances cannot
be silently rounded away: specify fixed reserve padding/refunds sufficient for
the two protected outputs, or explicitly mark those payout cases unsupported
until a different exact settlement construction is qualified. Padding is part
of the required reserve, never extra poker winnings.

## 11. Preparation and next hands

A sequence covering the entire agreed balance range can be independent of the
initial split, unlike the current fixed-limit deep-stack optimization. Given
the same total `V`, bounds, fee schedule and slot keys, prepare the sequence and
all payout amounts in background workers before the actual split is known.

Activate it only after both parties authenticate the exact initial state from
the previous settled hand and bind that state to this slot. The initial state
certificate must be mandatory on the first transition and first-position claim
paths; the relay cannot choose it. Funding-root signatures remain withheld until
selection and the existing hand-retirement barrier permits entry.

If total value, payout quantum, fee policy, permitted depth or accepted deal
changes, the old preparation is not reusable. Prove that all internal scripts
and sighashes are independent of the late-bound split before enabling reuse.
Future certificates must not disclose cards or permit speculative activation.

## 12. Required proof and prototype before implementation approval

The design is accepted only when each of these obligations has a concrete
construction and executable tests:

1. **Transaction identity:** two different legal wager amounts execute different
   witnesses over the same fixed continuation body and same child txid.
2. **Authentic state linkage:** a later step cannot select an unauthorized
   predecessor; conflicting self-authored versions are detectable without
   enabling false accusations against the other participant.
3. **Local fraud coverage:** every invalid state transition either fails normal
   Script validation or has an available, correctly attributed fraud path.
4. **Exit correctness:** every legal reachable state has exact fold/surrender,
   eligible timeout and terminal settlement paths, including extreme amounts.
5. **Publication accountability:** the peer cannot publish an honest player's
   retired claim or use a different claimant's transaction to frame that player.
6. **Prefix preservation:** retirement of exits never invalidates the selected
   path required for unilateral recovery.
7. **Crash and timing safety:** every send/persist/revoke cut retains an enforceable
   exit. Test delayed responses, simultaneous closes, replay and reorgs. Signature
   existence alone must not prove timely action.
8. **Information safety:** no rollback after card disclosure, no optional reveal
   bypass, no selection among future decks after inspecting openings.
9. **Resources:** all leaf families meet consensus, policy, fee, storage and
   browser preparation budgets at the actual `B/q`, not just the BB illustration.

First build a tiny two-player instance with a few representable amounts, two
variable wagers, a forced role handoff, one card-delivery gate and a claim at
every position. Use claimant-separated outputs. Test both honest paths and
false-framing attempts in Bitcoin Core regtest, then add receipt/exit retirement
and interrupt the handshake at every boundary. Count the resulting real
templates and signatures before extrapolating to 100BB or 200BB.

Only then evaluate shared-claimant payout bodies and shorter on-chain contest
latency. Integrate the exact no-limit rules, generalized certificates, preparation,
session/Wasm ABI and browser UI after the protocol prototype passes. No funded
production path changes are part of this design document.
