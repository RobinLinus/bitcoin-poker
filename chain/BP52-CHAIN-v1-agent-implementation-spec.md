# BP52-CHAIN-v1

## Agent Implementation Specification for Two-Party Fixed-Limit Texas Hold’em on Bitcoin

**Status:** Implementable research/prototype specification. It is not approved for mainnet or real-funds use without independent cryptographic, Bitcoin Script, transaction-graph, and economic review.

**Protocol identifier:** `BP52-CHAIN-v1`

**Dependency:** `BP52-DEAL-v1`

**Normative language:** The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

---

## 1. Objective

Implement one heads-up fixed-limit Texas Hold’em hand as a finite Bitcoin transaction tree.

The implementation MUST provide:

1. binding to one accepted `BP52-DEAL-v1` deal;
2. binding to a pre-existing origin escrow and deterministic activation into
   the gameplay root;
3. on-chain-enforceable delivery of both players’ hole cards;
4. a fully unrolled fixed-limit betting tree;
5. two-round revelation of the flop, turn, and river;
6. action, reveal, and showdown timeout paths;
7. five-card poker-hand verification;
8. Alice’s score commitment across one transaction boundary;
9. Bob’s combined showdown-and-payout transaction;
10. deterministic terminal settlement;
11. deterministic compilation, serialization, signing, and regtest execution.

The construction and joint authorization of the pre-existing origin escrow is
an explicit surrounding-protocol boundary in this version. The reference
implementation MUST keep funding authorization fail-closed until that package,
including pre-activation refunds, is specified and verified.

After activation, no valid protocol outcome may require the parties to
negotiate or construct a new cooperative transaction.

---

## 2. Security and execution model

There are exactly two players:

```text
A = Alice
B = Bob
```

At most one player is malicious.

The network and mempool are adversarial. Either player may delay, abort, send malformed witnesses, reveal contradictory off-chain data, or attempt to broadcast competing valid branches.

The protocol guarantees eventual unilateral settlement through timelocked paths. It does not guarantee that a transaction broadcast close to a timeout will win a confirmation race.

Every nonterminal state is represented by a unique Bitcoin outpoint. Competing child transactions spend the same outpoint, so at most one branch can confirm.

Dynamic game data MUST appear only in SegWit/Taproot witness data. Every
activation and gameplay transaction’s non-witness serialization MUST be fixed
before activation authorization so that descendant transaction IDs and
signatures can be prepared in advance.

---

## 3. Scope

### 3.1 In scope

`BP52-CHAIN-v1` specifies:

- one two-player Hold’em hand;
- one accepted nine-card `BP52-DEAL-v1` result;
- blinds and fixed-limit betting;
- exactly four bets total per betting street;
- implicit effective-stack all-ins, including deterministic short bets and
  raises, followed by a forced community-card runout after a matching call;
- hole-card delivery;
- flop, turn, and river revelation;
- fold, timeout, showdown, win, and split outcomes;
- opponent-only preauthorization plus the active player’s live Bitcoin
  signature for betting actions;
- defaulting-player preauthorization plus the beneficiary’s post-CSV live
  Bitcoin signature for timeout settlements;
- Lamport one-time certificates for Alice’s and Bob’s showdown scores;
- a deterministic transaction-tree compiler;
- reference hand scoring and script predicates;
- graph signing and funding gates;
- mandatory unit, property, and regtest tests.

### 3.2 Out of scope

The following require a new protocol version:

- no-limit or pot-limit betting;
- more than two players;
- multiple hands under one funding output;
- side pots;
- partial blind posting below one full big blind;
- caller-selected bet, raise, or all-in amounts;
- run-it-twice;
- rake;
- native verification of the off-chain deal proofs inside Bitcoin;
- proof that a claimed five-card hand is the best among all 21 subsets;
- a production fee-bumping design;
- mainnet deployment.

---

## 4. Inputs from BP52-DEAL-v1

The chain protocol consumes one mutually signed accepted deal:

```rust
struct AcceptedDeal {
    protocol_version: u16,
    game_id: [u8; 32],
    attempt: u32,
    hashes_a: [[u8; 32]; 9],
    hashes_b: [[u8; 32]; 9],
    verification_transcript_root: [u8; 32],
    signature_a: [u8; 64],
    signature_b: [u8; 64],
}
```

Before graph construction, both players MUST verify:

1. both accepted-deal signatures;
2. the expected `game_id`;
3. the expected protocol version;
4. the full archived deal transcript;
5. all deal proofs and uniqueness checks;
6. that all 18 hashes are distinct;
7. that the attempt is the accepted attempt.

The Bitcoin-facing card relation is:

```text
SHA256(x[P,i]) = h[P,i]
16 <= len(x[P,i]) <= 67
v[P,i] = len(x[P,i]) - 16
card[i] = (v[A,i] + v[B,i]) mod 52
```

Equivalently:

```text
sum_len = len(x[A,i]) + len(x[B,i]) - 32  // 0..102

card[i] =
    sum_len       if sum_len < 52
    sum_len - 52  otherwise
```

The chain protocol relies on `BP52-DEAL-v1` for the fact that the nine resulting cards are pairwise distinct.

---

## 5. Slot and card mapping

The fixed slot mapping is:

```text
slot 0 = Alice hole card 1
slot 1 = Bob hole card 1
slot 2 = Alice hole card 2
slot 3 = Bob hole card 2
slot 4 = flop card 1
slot 5 = flop card 2
slot 6 = flop card 3
slot 7 = turn
slot 8 = river
```

Card identifiers use:

```text
rank_index = floor(card_id / 4)
suit_index = card_id mod 4
```

Ranks:

```text
0=2, 1=3, 2=4, 3=5, 4=6, 5=7, 6=8,
7=9, 8=10, 9=Jack, 10=Queen, 11=King, 12=Ace
```

Suits:

```text
0=Clubs, 1=Diamonds, 2=Hearts, 3=Spades
```

---

## 6. Fixed-limit v1 profile

The v1 tree profile is deliberately finite.

Let:

```text
UNIT = integral Bitcoin base-unit amount displayed with the BIP-177 ₿ symbol
```

Then:

```text
small blind            = 1 * UNIT
big blind              = 2 * UNIT
preflop bet increment  = 2 * UNIT
flop bet increment     = 2 * UNIT
turn bet increment     = 4 * UNIT
river bet increment    = 4 * UNIT
MAX_BETS_PER_STREET    = 4
```

`MAX_BETS_PER_STREET = 4` means:

```text
one opening bet + at most three raises
```

On preflop, the posted big blind counts as the first bet.

Heads-up unlimited raising is NOT used.

There are no antes and no rake.

### 6.1 Implicit effective-stack all-ins

Each player's locked poker stack MUST be at least one full big blind:

```text
starting_stack[P] >= 2*UNIT
```

This keeps blind posting unconditional for either button assignment. Partial
blind posting is not part of this profile.

There is no separate `ALL_IN` action code and no caller-selected wager amount.
For every `BET` or `RAISE`, the graph derives one exact target from the nominal
fixed-limit target and both players' ability to match it. A target below the
nominal fixed-limit target is the unique short all-in wager for that state.

An all-in bet or raise does not itself end betting: the opponent retains exactly
the `FOLD` and `CALL` choices, plus the ordinary action timeout. A matching call
ends betting for the hand. Both players then perform the existing reveal
obligations for every remaining community street, with no intervening betting,
before the ordinary Alice-first showdown.

Because there are exactly two players, side pots are unnecessary. Value which
cannot be matched MUST remain in the larger player's `remaining` stack and MUST
NOT enter the contestable pot. Terminal settlement therefore refunds it through
the ordinary remaining-stack output.

Fee reserves are separate from poker stacks.

---

## 7. Game descriptor

The compiler consumes a canonical descriptor:

```rust
enum Role {
    Alice = 0,
    Bob = 1,
}

enum TimeoutSettlementPolicy {
    // Normal poker semantics: return uncommitted stacks and award the
    // current pot to the nondefaulting player.
    PotOnly = 0,

    // Reserved discriminant. BP52-CHAIN-v1 implementations MUST reject it;
    // a future slashing profile would require a new protocol/profile version.
    SlashRemainingStack = 1,
}

struct RevealOrder {
    flop_first: Role,
    turn_first: Role,
    river_first: Role,
}

struct ChainGameDescriptor {
    chain_protocol_version: u16,         // 4
    deal: AcceptedDeal,

    network_id: [u8; 32],

    // The pre-existing origin-escrow outpoint used by the surrounding funding
    // protocol and bound into the BP52-DEAL-v1 game context. It is not the
    // gameplay-root outpoint; the canonical activation transaction creates
    // that root at activation_txid:vout0.
    funding_outpoint: [u8; 36],

    // Session nonce used by BP52-DEAL-v1 game-id derivation.
    deal_session_nonce: [u8; 32],

    alice_xonly_pk: [u8; 32],
    bob_xonly_pk: [u8; 32],

    button: Role,
    unit_sat: u64,

    alice_starting_stack_sat: u64,
    bob_starting_stack_sat: u64,
    fee_reserve_sat: u64,

    action_csv: u16,
    reveal_csv: u16,
    showdown_csv: u16,

    reveal_order: RevealOrder,
    timeout_policy: TimeoutSettlementPolicy,

    split_remainder_recipient: Role,

    fee_policy_id: [u8; 32],
    compiler_id: [u8; 32],
}
```

The descriptor MUST be canonically encoded and signed by both long-term BIP340
identity keys before graph signing begins. BP52-CHAIN-v1 requires
`timeout_policy == PotOnly`; validation and compilation MUST reject
`SlashRemainingStack`.

The implementation MUST verify that `funding_outpoint`, `deal_session_nonce`,
identity keys, and network context are exactly those used to derive the
accepted deal’s `game_id`. It MUST NOT rebind an accepted deal to a different
funding context. Both `deal_session_nonce` and `fee_reserve_sat` are part of the
canonical descriptor encoding, descriptor signatures, and `chain_game_id`.

For the reference heads-up profile:

- the button posts the small blind;
- the nonbutton posts the big blind;
- the button acts first preflop;
- the nonbutton acts first on flop, turn, and river;
- Alice always reveals first at showdown, independent of dealer position.

---

## 8. Canonical identifiers

Define:

```text
chain_game_id = TaggedSHA256(
    "BP52/chain-game/v1",
    Encode(ChainGameDescriptor)
)
```

Every node has a unique path-dependent identifier:

```text
root_node_id = TaggedSHA256(
    "BP52/chain-root/v1",
    chain_game_id
)

child_node_id = TaggedSHA256(
    "BP52/chain-node/v1",
    parent_node_id || edge_code || child_state_digest
)
```

A node identifier MUST remain unique even when two paths have the same abstract poker balances. This is a literal transaction tree, not a fan-in DAG.

---

## 9. State accounting

Each nonterminal node has a logical state:

```rust
enum Street {
    Preflop,
    Flop,
    Turn,
    River,
}

struct AmountState {
    alice_remaining: u64,
    bob_remaining: u64,
    pot: u64,
    fee_reserve_remaining: u64,
}

struct BettingState {
    street: Street,
    actor: Role,

    alice_committed_this_street: u64,
    bob_committed_this_street: u64,

    current_wager: u64,
    bets_used: u8,                 // 0..4
    consecutive_checks: u8,        // 0..1
    big_blind_option_pending: bool,

    amounts: AmountState,
}
```

For every state:

```text
game_value =
    alice_remaining
  + bob_remaining
  + pot
  + fee_reserve_remaining
```

Every transition MUST conserve value except for its fixed transaction fee.

The compiler MUST use checked integer arithmetic and reject overflow, underflow, dust, and negative effective outputs.

---

## 10. Abstract Bitcoin transaction model

Each nonterminal protocol state is represented by one Taproot state output.
Terminal logical nodes instead create the direct player settlement outputs.

Every nonterminal Taproot state MUST also contain one hidden, provably
unspendable state-commitment leaf:

```text
OP_RETURN <versioned-state-domain> <logical_state_digest>
```

The reference v1 `versioned-state-domain` is the seven ASCII bytes
`BP52SC1`.

`logical_state_digest` commits to the canonical complete state, including both
remaining stacks, the pot, unused fee reserve, phase, actor, and betting
counters. The leaf is included in the Taproot Merkle root but is not an edge and
can never authorize a spend. Consequently the P2TR output key and transaction
ID identify the exact logical state without a separate `OP_RETURN` transaction
output or an on-chain-readable pot field.

Each normal edge is a fixed transaction template that:

1. spends exactly the parent state outpoint;
2. commits to all child outputs with a non-malleable sighash;
3. carries every required counterparty preauthorization signature;
4. requires the responsible player’s runtime authorization through the
   edge-specific Lamport witness, secret preimage, or live Bitcoin signature;
5. verifies every other edge-specific runtime predicate;
6. creates exactly the intended child state output, or terminal settlement outputs.

Signature policy MUST be explicit per edge. A signature whose later disclosure
would let the counterparty select an owner-controlled branch MUST remain
private until the owner intentionally exercises that branch.

In particular, Alice’s preauthorization signature for each Bob terminal payout
template MAY be exchanged before activation, but Bob’s own signature for that
terminal template MUST remain private and MUST NOT be disclosed until that
branch is exercised. For every timeout template, the defaulting player’s fixed
signature MUST be exchanged before activation; it binds the exact pot-only
settlement outputs. The beneficiary’s second signature MUST remain private
until the CSV delay has expired and that timeout branch is intentionally
exercised. The reference readiness implementation precomputes, verifies, and
retains every exact Bob-payout and timeout-beneficiary signature in protected
local storage. Its runtime signer MAY reproduce an equivalent valid signature
when the branch is exercised; neither private copy is exchanged in advance.

Each timeout edge:

1. spends the same parent output;
2. is disabled until the node-specific relative timelock expires;
3. verifies the defaulting player’s pre-exchanged signature over the exact
   timeout transaction;
4. requires the nondefaulting beneficiary’s live signature;
5. creates the deterministic timeout settlement outputs.

After preauthorization exchange, the beneficiary can exercise the timeout
unilaterally after CSV. The beneficiary cannot substitute outputs because the
defaulting player’s `SIGHASH_DEFAULT` signature commits to the compiled
transaction.

Every gameplay transaction authorization in the reference implementation MUST
use a 64-byte Taproot/Tapscript
`SIGHASH_DEFAULT` signature for fixed transitions. Under BIP341 this commits
to the same input/output set as `SIGHASH_ALL`, while the fixed 64-byte encoding
rejects every alternative sighash mode. Bob’s private signature on a terminal
template MUST commit to that template’s outputs. A different signature profile
requires a distinct compiler and predicate domain; it is not part of the
reference v1 profile.

### 10.1 Witness-only variability

The following MUST NOT alter transaction IDs:

- the active player’s betting-action Bitcoin signature;
- hash preimages;
- selected five-card subset;
- Alice’s score certificate;
- Bob’s score certificate;
- category-specific hand proof data.

This permits descendants to be pre-signed before those values are known.

### 10.2 No previous-witness introspection

Bitcoin scripts cannot inspect a previous transaction’s witness.

Therefore, later transactions MUST repeat any previously published data they need, including:

- card-share preimages;
- Alice’s score and Lamport signature;
- other public witness values.

The runtime MUST obtain repeated values from the confirmed chain transaction or its local transcript.

### 10.3 Authorization matrix

The reference authorization policy is:

| Transaction class | Pre-exchanged authorization | Runtime authorization |
|---|---|---|
| Betting action | opponent’s fixed transaction signature only | active player’s live BIP340 signature for the selected action transaction |
| Hole-card reveal | both fixed transaction signatures | revealer’s committed preimages |
| Community reveal | both fixed transaction signatures | revealer’s committed preimages |
| Alice showdown | both fixed transaction signatures | Alice’s hole preimages and score OTS |
| Bob terminal payout | Alice’s fixed signature only | Bob’s private BIP340 signature disclosed only for the selected payout, hole preimages, valid hand witness, and score OTS |
| Timeout | defaulting player’s fixed transaction signature | beneficiary’s private BIP340 signature disclosed only after CSV |

An implementation MAY replace this matrix with an equivalent construction, but
it MUST preserve branch control and MUST pass the front-running tests in
Section 35.

---

## 11. Share and card predicates

Implement the following consensus-equivalent script macros and pure reference functions.

```text
VerifyShareOpening(expected_hash, x):
    require 16 <= len(x) <= 67
    require SHA256(x) == expected_hash
    return len(x) - 16
```

```text
VerifyCardOpening(slot, xA, xB):
    a = VerifyShareOpening(h[A,slot], xA)
    b = VerifyShareOpening(h[B,slot], xB)

    s = a + b
    require 0 <= s <= 102

    if s < 52:
        card_id = s
    else:
        card_id = s - 52

    return card_id
```

The script backend MAY implement `card_id`, rank, and suit through explicit finite lookup branches rather than division or modulo opcodes.

The pure Rust reference implementation MUST be the source of test vectors, but Script behavior MUST be tested independently on Bitcoin Core regtest.

---

## 12. Lamport-style score authorization

### 12.1 Primitive

For an `n`-bit message, a Lamport public key is:

```text
PK[j][b] = SHA256(SK[j][b])
j in 0..n-1
b in {0,1}
```

A signature reveals:

```text
SIG[j] = SK[j][message_bit[j]]
```

Verification requires:

```text
SHA256(SIG[j]) == PK[j][message_bit[j]]
```

Bits MUST be interpreted most-significant bit first from a fixed-width big-endian message encoding.

Every OTS key MUST be independently generated for one exact node and purpose.

No OTS key may be reused across:

- nodes;
- attempts;
- games;
- Alice-score and Bob-score purposes.

### 12.2 Betting actions use the transaction signature

Each legal action is already represented by a distinct, output-bound Bitcoin
transaction. The opponent pre-signs every legal child transaction at that
decision node, but the active player does not disclose their own signatures in
advance. At runtime the active player chooses one action by signing and
broadcasting that exact transaction.

The acting player’s 64-byte `SIGHASH_DEFAULT` signature MUST commit to the exact
selected transaction and all outputs. Because signatures are witness data,
adding it at runtime does not change the transaction ID or invalidate
precomputed descendants. Competing action transactions spend the same parent
outpoint, so only one can confirm.

Merely deleting the action OTS while continuing to exchange both Bitcoin
signatures is forbidden: that would allow either participant to choose the
other participant’s action.

### 12.3 Showdown scores

Alice’s showdown node has a fresh 24-bit OTS key.

Alice signs only the canonical packed `HandScore`.

The selected five-card subset is not signed.

Each Bob-terminal node likewise has a fresh 24-bit OTS key controlled by Bob.
Bob signs only the canonical packed `HandScore` computed from his selected
five-card subset. This prevents third parties from replacing the witness-only
score claim after Bob has authorized the payout transaction. Bob’s selected
subset need not be signed because Script recomputes the signed score from it.

### 12.4 Public-key bundles

After the logical tree is known and before Bitcoin scripts are derived, each
party creates a canonical OTS public-key bundle for every node it controls.

```rust
enum LamportPurpose {
    AliceScore24Bit,
    BobScore24Bit,
}

struct LamportPublicEntry {
    node_id: [u8; 32],
    purpose: LamportPurpose,
    bit_width: u8,
    public_hash_pairs: Vec<[[u8; 32]; 2]>,
}

struct LamportPublicBundle {
    chain_game_id: [u8; 32],
    role: Role,
    entries: Vec<LamportPublicEntry>,
    bundle_root: [u8; 32],
    signature: [u8; 64],
}
```

Entries MUST be sorted by `(node_id, purpose)` and have the exact expected
count. Both parties MUST verify the peer bundle and include both bundle roots in
the graph manifest.

### 12.5 Secret handling

The runtime MUST:

- keep unused OTS secrets encrypted at rest;
- zeroize a node’s unused OTS secrets after one branch confirms;
- never export an OTS secret bundle in logs or diagnostics;
- warn and halt if it detects local reuse of one OTS key for two messages.

---

## 13. Origin escrow, activation, and blind posting

Before `BP52-DEAL-v1` begins, the surrounding funding protocol supplies a
pre-existing origin escrow whose outpoint is known and bound into the deal
`game_id`. The reference compiler authenticates the observed origin `TxOut`.
The browser profile separately verifies both exact contributions, the origin
spend authorization, and a fully signed CSV abort refund before releasing the
funding signatures.

The gameplay-root output locks:

```text
alice_starting_stack
+ bob_starting_stack
+ fee_reserve
```

The canonical activation transaction has exactly one final-sequence input
spending the descriptor-bound origin and exactly one output at vout 0 equal to
that gameplay-root output. Its values satisfy:

```text
root_value       = alice_starting_stack + bob_starting_stack + fee_reserve
activation_fee   = origin_value - root_value
root_outpoint    = activation_txid:vout0
```

The compiler MUST reject origin underfunding and every input, parent-output,
root-output, version, locktime, sequence, output-count, or fee substitution.
The exact origin output and activation template become part of the agreed graph
artifacts. Activation MUST remain unavailable until the surrounding protocol
has verified both players' complete contributions, origin authorization, and
pre-activation refund package. The browser's exact two-input origin protocol is
the reference integration of this gate.

The first protocol state already accounts for forced blinds:

```text
if button == Alice:
    alice_remaining -= UNIT
    bob_remaining   -= 2*UNIT

    alice_committed_this_street = UNIT
    bob_committed_this_street   = 2*UNIT
else:
    bob_remaining   -= UNIT
    alice_remaining -= 2*UNIT

    bob_committed_this_street   = UNIT
    alice_committed_this_street = 2*UNIT

pot                      = 3*UNIT
current_wager            = 2*UNIT
bets_used                = 1
actor                    = button
consecutive_checks       = 0
big_blind_option_pending = false
```

If the button calls, the next preflop state sets
`big_blind_option_pending = true` for the big blind. A big-blind check then
completes preflop; a big-blind raise clears the flag and continues normally.

Each postflop street starts with:

```text
alice_committed_this_street = 0
bob_committed_this_street   = 0
current_wager               = 0
bets_used                   = 0
consecutive_checks          = 0
big_blind_option_pending    = false
actor                       = nonbutton
```

No hole-card share may be revealed before the activation-created gameplay-root
output is confirmed to the configured depth.

Before authorizing activation, each party MUST possess and verify all
counterparty preauthorization signatures needed to execute every branch on
which it may later rely. A party MUST NOT demand disclosure of the peer’s
runtime actor signature for a branch controlled by that peer.

This set includes the defaulting player’s fixed signature for every timeout
whose beneficiary is the counterparty. Refusing or omitting any such signature
prevents activation.

---

## 14. Hole-card dealing

Hole cards are delivered on-chain after the activation-created gameplay root
has reached the configured confirmation depth.

### 14.1 Deal Alice

Bob reveals:

```text
x[B,0]
x[B,2]
```

The transaction verifies:

```text
VerifyShareOpening(h[B,0], x[B,0])
VerifyShareOpening(h[B,2], x[B,2])
```

Alice combines these public shares with her secret:

```text
x[A,0]
x[A,2]
```

and learns slots `0` and `2`.

Bob’s revealed preimages remain public and may be repeated in Alice’s showdown witness.

If Bob does not complete this reveal before `reveal_csv`, Alice uses the timeout settlement.

### 14.2 Deal Bob

Alice reveals:

```text
x[A,1]
x[A,3]
```

The transaction verifies:

```text
VerifyShareOpening(h[A,1], x[A,1])
VerifyShareOpening(h[A,3], x[A,3])
```

Bob combines them with:

```text
x[B,1]
x[B,3]
```

and learns slots `1` and `3`.

If Alice does not complete this reveal before `reveal_csv`, Bob uses the timeout settlement.

### 14.3 Required sequence

```text
FUNDED
  -> DEAL_ALICE       // Bob reveals x[B,0], x[B,2]
  -> DEAL_BOB         // Alice reveals x[A,1], x[A,3]
  -> PREFLOP
```

A timeout at either step terminates the hand.

---

## 15. Betting rules engine

### 15.1 Legal actions

Let:

```text
actor_capacity   = actor_committed_this_street + actor_remaining
opponent_capacity = opponent_committed_this_street + opponent_remaining
to_call          = current_wager - actor_committed_this_street
```

If `to_call > 0`, legal actions are:

```text
FOLD
CALL
RAISE, only if bets_used < 4 and the derived raise target is greater
       than current_wager
```

If `to_call == 0`, legal actions are:

```text
CHECK
BET, only if bets_used == 0, the street has not been opened, and the
     derived bet target is nonzero
RAISE, only for the preflop big-blind option or after prior aggression,
       only if bets_used < 4, and only if the derived raise target is
       greater than current_wager
```

The implementation MAY expose only the semantically appropriate label (`BET`
or `RAISE`) in each state. It MUST reject an action code that does not match the
state. In particular, once a wager has reached either player's effective
capacity, the responder has only `FOLD` and `CALL`; a further raise target cannot
strictly increase `current_wager`.

### 15.2 Bet increments

```text
increment(Preflop) = 2*UNIT
increment(Flop)    = 2*UNIT
increment(Turn)    = 4*UNIT
increment(River)   = 4*UNIT
```

A bet or raise has a nominal target exactly one increment above the applicable
base wager. The actual target is capped by the amount both players can contest.

For a bet:

```text
nominal_wager = increment(street)
```

For a raise:

```text
nominal_wager = current_wager + increment(street)
```

For both actions:

```text
new_wager = min(nominal_wager, actor_capacity, opponent_capacity)
transfer  = new_wager - actor_committed_this_street
```

The action is legal only when `new_wager` strictly exceeds `current_wager` for
a raise, or is nonzero for an opening bet. If `new_wager < nominal_wager`, this
is the unique implicit short all-in bet or raise. It retains the ordinary `BET`
or `RAISE` action code and increments `bets_used`; there is no additional amount
choice or wire encoding.

The transition subtracts `transfer` from the actor’s remaining stack, adds it
to the pot, sets the actor’s street commitment to `new_wager`, increments
`bets_used`, clears `consecutive_checks`, and passes action.

The effective-stack cap ensures that value which the opponent cannot match
never enters the pot. No custom amount is accepted.

### 15.3 Calls

A call transfers exactly `to_call` from the actor’s remaining stack to the
pot and increases the actor’s street commitment by `to_call`.

Because every wager was capped by both capacities when it was created,
`to_call` is always fully payable. A separate short-call amount is neither
needed nor accepted.

A call facing an outstanding voluntary bet or raise completes the betting
street. The preflop small-blind call is the sole exception: it passes the
big-blind option rather than completing the street, unless either player's
remaining stack is then zero.

### 15.4 Forced all-in runout

After a call equalizes the street commitments, if either player's remaining
stack is zero, betting is complete for the entire hand. The call transaction
connects directly to the first reveal obligation for the next unrevealed
community street, or directly to Alice showdown when the river is already
revealed.

For every remaining community street:

1. the configured first revealer publishes its committed shares;
2. the second revealer publishes its committed shares;
3. the graph skips that street's betting root; and
4. the graph proceeds to the next reveal street or showdown.

Every reveal and showdown timeout remains available. No automatic intermediate
transaction and no all-in-specific witness are introduced.

### 15.5 Checks

On postflop streets:

- the first check passes action;
- the second consecutive check completes the street.

Preflop uses the explicit big-blind option:

- if the small blind calls the big blind, the big blind may check to complete preflop or raise;
- that check is not represented as a second ordinary postflop check.

### 15.6 Folds and action timeouts

A fold immediately terminates the hand.

An action timeout is economically equivalent to a fold. The v1 profile does
not permit stronger slashing.

### 15.7 Raise cap

At `bets_used == 4`, no raise edge may exist.

A player facing the fourth bet has only:

```text
FOLD
CALL
```

### 15.8 Action order

Preflop:

```text
button/small blind acts first
big blind has the option after a call
```

Flop, turn, and river:

```text
nonbutton acts first
button acts second
```

---

## 16. Betting-tree generation

Implement two deterministic generators:

```rust
fn expand_preflop(state: BettingState) -> Node;
fn expand_postflop(state: BettingState, next_phase: Node) -> Node;
```

For every betting node:

1. compute the legal actions;
2. create exactly one child transaction for every legal action;
3. create exactly one action-timeout transaction;
4. recursively expand every nonterminal child;
5. reject duplicate edge labels;
6. sort edges canonically by action code, with timeout last.

A betting-complete edge connects directly to the first reveal node of the next
street, or to Alice showdown after river. If either remaining stack is zero,
each second community-reveal edge applies the same rule again instead of
creating that street's betting root. Thus a matched all-in runs out the board
using the ordinary reveal nodes.

No “betting complete” intermediate transaction is created unless required by the Bitcoin backend.

---

## 17. Community-card revelation

Every community street has two enforced reveal transactions.

### 17.1 Reveal ordering

For each street, `RevealOrder` identifies the first revealer.

The second revealer learns the completed community card before publishing its own share. Therefore the second reveal MUST have a timeout branch awarding settlement to the first revealer.

The first reveal also has a timeout branch.

### 17.2 Flop

Slots:

```text
4, 5, 6
```

If Alice is first:

```text
FLOP_REVEAL_A:
    reveal x[A,4], x[A,5], x[A,6]

FLOP_REVEAL_B:
    reveal x[B,4], x[B,5], x[B,6]

then:
    FLOP_BETTING
```

If Bob is first, reverse the roles.

Each reveal transaction verifies the three relevant hashes and length bounds.

The reveal transaction does not need to encode the resulting cards into the next output. Later hand-verification transactions repeat all six flop preimages.

### 17.3 Turn

Slot:

```text
7
```

```text
TURN_REVEAL_FIRST
  -> TURN_REVEAL_SECOND
  -> TURN_BETTING
```

Each reveal verifies one preimage.

### 17.4 River

Slot:

```text
8
```

```text
RIVER_REVEAL_FIRST
  -> RIVER_REVEAL_SECOND
  -> RIVER_BETTING
```

Each reveal verifies one preimage.

---

## 18. Seven-card ordering and subset witnesses

Alice’s seven cards are ordered:

```text
A7[0] = slot 0
A7[1] = slot 2
A7[2] = slot 4
A7[3] = slot 5
A7[4] = slot 6
A7[5] = slot 7
A7[6] = slot 8
```

Bob’s seven cards are ordered:

```text
B7[0] = slot 1
B7[1] = slot 3
B7[2] = slot 4
B7[3] = slot 5
B7[4] = slot 6
B7[5] = slot 7
B7[6] = slot 8
```

The unsigned subset witness is an integer `0..20` mapped lexicographically:

```text
 0: [0,1,2,3,4]
 1: [0,1,2,3,5]
 2: [0,1,2,3,6]
 3: [0,1,2,4,5]
 4: [0,1,2,4,6]
 5: [0,1,2,5,6]
 6: [0,1,3,4,5]
 7: [0,1,3,4,6]
 8: [0,1,3,5,6]
 9: [0,1,4,5,6]
10: [0,2,3,4,5]
11: [0,2,3,4,6]
12: [0,2,3,5,6]
13: [0,2,4,5,6]
14: [0,3,4,5,6]
15: [1,2,3,4,5]
16: [1,2,3,4,6]
17: [1,2,3,5,6]
18: [1,2,4,5,6]
19: [1,3,4,5,6]
20: [2,3,4,5,6]
```

The subset is a witness only. It is not Lamport-signed and does not persist into a later state.

A backend MAY implement the 21 choices as separate Taproot leaves.

---

## 19. Canonical five-card score

### 19.1 Rank components

Use rank indices `0..12`, where `12` is Ace and larger is stronger.

Every score is represented as six nibbles:

```text
(category, r1, r2, r3, r4, r5)
```

Unused rank fields MUST be zero.

Categories are:

```text
8 = Straight Flush
7 = Four of a Kind
6 = Full House
5 = Flush
4 = Straight
3 = Three of a Kind
2 = Two Pair
1 = One Pair
0 = High Card
```

Category layouts:

```text
Straight Flush: (8, high,      0,        0,      0,  0)
Four Kind:      (7, quads,     kicker,   0,      0,  0)
Full House:     (6, trips,     pair,     0,      0,  0)
Flush:          (5, c1,        c2,       c3,     c4, c5)
Straight:       (4, high,      0,        0,      0,  0)
Three Kind:     (3, trips,     k1,       k2,     0,  0)
Two Pair:       (2, high_pair, low_pair, kicker, 0,  0)
One Pair:       (1, pair,      k1,       k2,     k3, 0)
High Card:      (0, c1,        c2,       c3,     c4, c5)
```

Kickers and distinct card ranks are ordered descending.

### 19.2 Packed integer

Pack the score as:

```text
score =
    category * 16^5
  + r1       * 16^4
  + r2       * 16^3
  + r3       * 16^2
  + r4       * 16
  + r5
```

Equivalent bit layout:

```text
score =
    (category << 20)
  | (r1 << 16)
  | (r2 << 12)
  | (r3 << 8)
  | (r4 << 4)
  | r5
```

The packed score is a positive 24-bit integer and fits safely in Bitcoin Script’s signed numeric range.

Ordinary integer comparison MUST exactly match poker ordering.

### 19.3 Wheel straight

The rank set:

```text
Ace, 2, 3, 4, 5
```

is a straight with:

```text
high = rank_index(5) = 3
```

It ranks below a six-high straight.

---

## 20. Reference `Eval5`

Implement:

```rust
fn eval5(cards: [CardId; 5]) -> Result<HandScore, PokerError>;
```

The function MUST reject:

- a card outside `0..51`;
- duplicate card identifiers;
- malformed input.

Algorithm:

1. derive each rank and suit;
2. count occurrences of every rank;
3. sort ranks descending;
4. detect flush;
5. derive sorted unique ranks;
6. detect ordinary straight or wheel;
7. classify in this exact precedence:
   - straight flush;
   - four of a kind;
   - full house;
   - flush;
   - straight;
   - three of a kind;
   - two pair;
   - one pair;
   - high card;
8. produce the exact canonical score above.

Exact category rules:

```text
Straight Flush:
    is_flush && is_straight

Four of a Kind:
    one rank count == 4

Full House:
    one rank count == 3
    and a different rank count == 2

Flush:
    all five suits equal
    and not straight flush

Straight:
    five distinct ranks in sequence,
    including the wheel special case,
    and not a flush

Three of a Kind:
    one rank count == 3
    and remaining ranks are singletons

Two Pair:
    exactly two rank counts == 2

One Pair:
    exactly one rank count == 2

High Card:
    five singleton ranks,
    not a straight,
    not a flush
```

The Rust `eval5` function classifies in the exact precedence above. A
category-specific Script leaf proves only the positive facts for its claimed
category. It MUST NOT prove that a stronger category is absent. Thus a
straight flush also satisfies straight, flush, and high-card leaves; choosing
the weaker score can only reduce the claimant's payout.

---

## 21. No proof of seven-card optimality

For a player’s seven cards and claimed score, verification is:

```text
there exists one subset_id in 0..20 such that
the selected five cards satisfy the positive predicate for claimed_score
```

The protocol MUST NOT compute or verify:

```text
claimed_score == max(Eval5(all 21 subsets))
```

A player who chooses a valid but weaker subset can only reduce that player’s own payout.

This incentive argument removes the need for a seven-card maximum circuit.

---

## 22. Alice showdown transaction

After river betting completes, Alice acts first.

### 22.1 Runtime witness

Alice supplies:

```text
newly revealed:
    x[A,0]
    x[A,2]

repeated public preimages:
    x[B,0]
    x[B,2]
    x[A,4], x[B,4]
    x[A,5], x[B,5]
    x[A,6], x[B,6]
    x[A,7], x[B,7]
    x[A,8], x[B,8]

claim:
    score_A
    LamportSignature_A(score_A)
    subset_A in 0..20
```

### 22.2 Verification

The Alice showdown spend MUST:

1. verify all 14 preimages needed to reconstruct Alice’s seven cards;
2. reconstruct slots `0`, `2`, and `4..8`;
3. select five cards using `subset_A`;
4. verify `Eval5(selected) == score_A`;
5. verify Alice’s 24-bit Lamport signature over `score_A`;
6. create the final Bob-showdown state output.

`subset_A` is not signed.

### 22.3 Alice timeout

The river-betting-complete state has an Alice-showdown timeout.

If Alice does not publish a valid showdown transaction before `showdown_csv`, Bob receives the timeout settlement.

---

## 23. Alice score certificate across the transaction boundary

The Alice score certificate is:

```rust
struct AliceScoreCertificate {
    score_a: u32,                  // canonical 24-bit score
    lamport_signature: Vec<[u8; 32]>, // exactly 24 elements
}
```

It is revealed in Alice’s showdown transaction and repeated in Bob’s terminal transaction.

The final showdown output commits to Alice’s score OTS public key.

Bob’s transaction MUST verify the repeated certificate under that same public key.

Because Bitcoin cannot inspect the parent witness, the child verifies the certificate again rather than reading the prior value.

Security requirement:

- an honest Alice MUST issue exactly one score certificate;
- Bob cannot forge a different score certificate;
- if a malicious Alice intentionally releases multiple valid certificates under her own one-time key, Bob may use any released certificate, which cannot improve Alice’s outcome against an honest Bob.

A stronger consensus-level binding of the exact parent-witness score would require score-specific output templates and is outside this v1 profile.

---

## 24. Bob showdown and payout transaction

Bob’s showdown and settlement are the same transaction.

There is no intermediate `BOB_SHOWDOWN` transaction followed by a separate payout transaction.

### 24.1 Runtime witness

Bob supplies:

```text
newly revealed:
    x[B,1]
    x[B,3]

repeated public preimages:
    x[A,1]
    x[A,3]
    x[A,4], x[B,4]
    x[A,5], x[B,5]
    x[A,6], x[B,6]
    x[A,7], x[B,7]
    x[A,8], x[B,8]

Alice certificate:
    score_A
    LamportSignature_A(score_A)

Bob certificate and hand claim:
    score_B
    LamportSignature_B(score_B)
    subset_B in 0..20

transaction authorization:
    Bob’s private BIP340 signature for the selected terminal template
```

Bob MUST Lamport-sign `score_B` with the fresh score key committed by the exact
Bob-terminal node. Bob’s ordinary Bitcoin signature binds the chosen payout
transaction and its outputs, but Bitcoin’s transaction sighash does not commit
to the remaining witness stack. The score certificate separately authenticates
Bob’s exact witness-only rank claim.

### 24.2 Verification

Every Bob terminal spend MUST:

1. verify Bob’s private BIP340 signature over the exact terminal transaction template;
2. verify all 14 preimages needed to reconstruct Bob’s seven cards;
3. reconstruct slots `1`, `3`, and `4..8`;
4. select five cards using `subset_B`;
5. verify `Eval5(selected) == score_B`;
6. verify Bob’s 24-bit Lamport signature over `score_B`;
7. verify Alice’s repeated score certificate;
8. enforce the branch-specific score comparison;
9. create the branch-specific terminal outputs.

Alice MUST NOT be able to reuse Bob’s newly revealed hole-card preimages with a
different terminal template, because she lacks Bob’s private signature for that
different template.

### 24.3 Bob-win transaction

Valid only if:

```text
score_B > score_A
```

It awards the current pot to Bob under the settlement accounting rules.

### 24.4 Split transaction

Valid only if:

```text
score_B == score_A
```

It creates independently spendable Alice and Bob outputs.

The odd-base-unit remainder is assigned to `split_remainder_recipient`.

### 24.5 Alice-win cooperative transaction

Valid only if:

```text
score_B < score_A
```

It awards the current pot to Alice.

Bob may have no incentive to publish this branch, so liveness MUST NOT depend on it.

### 24.6 Bob timeout

The final showdown output has a Bob timeout path.

If Bob does not publish any valid terminal showdown transaction before `showdown_csv`, Alice receives the timeout settlement.

Thus Bob cannot improve his poker outcome by withholding a losing hand.

---

## 25. Terminal accounting

For normal fold or showdown settlement under standard poker accounting:

```text
AliceWin:
    Alice receives alice_remaining + pot
    Bob receives bob_remaining

BobWin:
    Alice receives alice_remaining
    Bob receives bob_remaining + pot

Split:
    Alice receives alice_remaining + alice_share(pot)
    Bob receives bob_remaining + bob_share(pot)
```

For unequal stacks, the effective-stack cap leaves every unmatchable base unit in
the larger player's `remaining` field. It is therefore refunded independently
of the showdown result and is never awarded or split as part of `pot`.

Every v1 timeout uses `TimeoutSettlementPolicy::PotOnly` and the same accounting
as a fold by the defaulting player. The defaulting player keeps their
uncommitted remaining stack; only the pot is awarded to the beneficiary.
`TimeoutSettlementPolicy::SlashRemainingStack` is a reserved wire value and
MUST be rejected by descriptor validation and compilation.

Unspent fee reserve disposition MUST be deterministic under `fee_policy_id`.

No terminal transaction may require a subsequent cooperative spend.

---

## 26. Complete phase order

```text
ORIGIN ESCROW CREATED AND CONFIRMED
        |
        v
BP52-DEAL-v1 ACCEPTED
        |
        v
DESCRIPTOR SIGNED
        |
        v
GRAPH COMPILED AND VERIFIED
        |
        v
COUNTERPARTY PREAUTHORIZATIONS EXCHANGED
        |
        v
LOCAL PRIVATE RUNTIME INVENTORY VERIFIED
        |
        v
ACTIVATION AUTHORIZED, BROADCAST, AND CONFIRMED
        |
        v
DEAL_ALICE
        |
        v
DEAL_BOB
        |
        v
PREFLOP BETTING TREE
        |
        v
FLOP REVEAL FIRST
        |
        v
FLOP REVEAL SECOND
        |
        v
FLOP BETTING TREE
        |
        v
TURN REVEAL FIRST
        |
        v
TURN REVEAL SECOND
        |
        v
TURN BETTING TREE
        |
        v
RIVER REVEAL FIRST
        |
        v
RIVER REVEAL SECOND
        |
        v
RIVER BETTING TREE
        |
        v
ALICE SHOWDOWN
        |
        +------------------------------+
        |                              |
        | Bob showdown + payout        | Bob timeout
        v                              v
BOB WIN / SPLIT / ALICE WIN        ALICE WIN
```

Every obligation node also has its own timeout terminal branch.

Every betting node also has fold and action-timeout outcomes where applicable.
After a matched all-in, each arrow from a second community reveal bypasses the
corresponding betting tree and proceeds to the next reveal pair or showdown.

The first phase above belongs to the surrounding origin-funding protocol. The
browser profile supplies a two-input contribution package and requires a fully
signed CSV abort refund before either funding signature is released. CHAIN
then verifies the observed origin and canonical activation template; the origin
package remains outside the gameplay graph and does not alter its node IDs.

---

## 27. Descriptor-derived literal-tree size and reference maximum

All graph counts are exact outputs of the signed descriptor. Effective-stack
all-ins prune betting subtrees after a matched call, so short-stack descriptors
generally have fewer nodes, templates, score keys, and signature requests than
the exact 100-BB reference maximum.

The exact 100-BB reference count assumes:

- community and hole-card values remain witness data and do not create
  card-value branches;
- previously revealed preimages are repeated at showdown instead of being
  encoded into intermediate state outputs;
- four bets total per street;
- neither effective-stack cap is reached before ordinary river completion;
- one timeout terminal per betting decision;
- two reveal rounds per community street;
- two hole-card deal rounds;
- Alice-first showdown;
- three Bob terminal comparison branches;
- subset and hand-category choices are Script/Taproot witness branches, not separate transactions;
- no fee-bump helper transactions are counted.

### 27.1 Exact 100-BB local betting counts

Preflop:

```text
decision nodes       = 8
fold leaves          = 7
continuations        = 7
timeout leaves       = 8
```

Postflop, per street:

```text
decision nodes       = 10
fold leaves          = 8
continuations        = 9
timeout leaves       = 10
```

### 27.2 Recurrences

```text
N_showdown = 7

N_postflop(next) = 10 + 8 + 10 + 9*next
                   = 28 + 9*next

N_two_reveals(next) = 2 reveal nodes
                    + 2 timeout leaves
                    + next
                    = 4 + next

N_preflop(next) = 8 + 7 + 8 + 7*next
                = 23 + 7*next

N_hole_deal(next) = 4 + next
```

Working backward:

```text
showdown                         =       7
river betting                    =      91
river reveal + river betting     =      95
turn betting onward              =     883
turn reveal onward               =     887
flop betting onward              =   8,011
flop reveal onward               =   8,015
preflop onward                   =  56,128
hole dealing + whole game        =  56,132
```

Therefore the exact 100-BB reference fixture MUST produce the following
gameplay graph:

```text
56,132 logical state/terminal nodes, including the Deal-Alice gameplay root
56,131 post-activation gameplay transaction templates
```

For every valid descriptor:

```text
actual logical node count                 <= 56,132
actual gameplay transaction count         = actual logical node count - 1
actual activation-inclusive templates     = actual logical node count
actual maximum post-activation path       <= 33
```

The graph manifest MUST carry the actual descriptor-derived node count,
transaction count, and maximum path length. OTS public-key bundles,
preauthorization requests, and retained private runtime inventories MUST be
derived from the actual graph rather than padded to the reference maximum.

There is no `52^5` community-card multiplier and no `21^2` showdown multiplier.
Card values and subset selections are witness choices inside fixed transaction
templates and Taproot branches.

Each non-root logical node corresponds to exactly one transaction spending its
parent. The Deal-Alice root is instead created by the canonical origin-to-root
activation transaction. Including that activation gives:

```text
56,132 activation-inclusive transaction templates in the exact 100-BB fixture
```

The activation is outside the logical gameplay graph and does not invent an
extra state node. The compiler MUST expose the actual three counts and retain
the exact 100-BB profile as a deterministic regression test.

### 27.3 Maximum executed path

Only one root-to-leaf path confirms.

The longest ordinary showdown path in the exact 100-BB fixture contains:

```text
2 hole-card reveal transactions
5 preflop action transactions
3 * (2 community reveal + 6 betting action transactions)
1 Alice showdown transaction
1 Bob showdown/payout transaction

total = 33 post-activation gameplay transactions
```

Every all-in runout is no longer than this path because it replaces future
betting decisions with direct transitions between already-required reveal
nodes. The manifest reports the actual maximum path for its descriptor.

Including the origin-to-root activation, the longest origin-to-settlement path
contains 34 transactions.

Fee reservation SHOULD be based on maximum executed path length, not the total
number of pre-signed branches. The reference qualification fixture retains the
`33 * gameplay_fee` reserve as a conservative descriptor-independent
upper bound, even when an all-in-pruned manifest reports a shorter exact
maximum. Every unused base unit of that reserve is returned by terminal
settlement.

---

## 28. Deterministic graph compilation

The compiler MUST:

1. validate the descriptor and accepted deal;
2. instantiate all logical states;
3. assign canonical path-dependent node IDs;
4. collect and verify both signed OTS public-key bundles;
5. derive every state Taproot output independently of runtime witnesses;
6. verify the exact origin-to-root activation template, derive the gameplay
   root as `activation_txid:vout0`, and instantiate all gameplay transaction
   templates top-down because each child input commits to its parent txid;
7. compute stable txids from fixed non-witness serializations;
8. generate signature requests for both parties;
9. compute a canonical graph manifest containing both OTS bundle roots;
10. verify value conservation and all timeouts;
11. produce a graph root commitment.

Define:

```text
graph_root = SHA256(MerkleRoot(canonical_node_records))
```

Each canonical node record MUST include:

```text
node_id
parent_node_id or ROOT
node_kind
logical_state_digest
creating transaction or ROOT
required witness predicate ID
timeout parameters
child node IDs
```

For every non-root record, the creating transaction includes the exact input
outpoint, non-witness serialization, output scripts and values, fee, and txid.
The Deal-Alice gameplay-root record has neither a parent nor a creating
transaction because the separate activation transaction creates it.

The compiler MUST reject nondeterminism. Two independent implementations given identical inputs MUST produce identical graph roots.

---

## 29. Graph signing and funding gate

Use a commit-then-open exchange for the graph and signature bundles.

Minimum flow:

```text
1. Both compute graph_root independently.
2. Both exchange signed graph_root commitments.
3. Both verify equality.
4. Both stream-generate every required counterparty preauthorization
   signature without retaining their own completed vector.
5. Both commit to their preauthorization signature bundles.
6. Both open those bundles.
7. Both verify every received counterparty signature.
8. Both verify they can unilaterally exercise every path they may need.
9. Each retains only the peer's verified packed preauthorization vector and a
   compact local one-time-key state. Actor-controlled transaction signatures,
   deterministic requests, and active transaction templates are re-derived
   only for the selected edge. Defaulting-player timeout signatures belong to
   the exchanged preauthorization bundles in steps 4–7.
10. The surrounding origin protocol consumes compact signed graph/readiness
    receipts and authorizes activation only after it has also verified both
    contributions, the origin spend policy, and the fully signed abort refund.
```

If any step after origin creation fails, the activation transaction is not
broadcast. In the browser integration, these checks advance automatically once
both exact deposits confirm; automatic execution does not weaken any gate.

The implementation MUST provide a local “funding readiness report” listing:

- graph root;
- node count;
- transaction count;
- maximum path length;
- total locked value;
- fee reserve;
- every timeout;
- reveal order;
- timeout settlement policy;
- count of verified counterparty preauthorization signatures;
- list of runtime signature classes intentionally not exchanged;
- any unresolved warnings.

---

## 30. Fee handling

The conversation did not fix a production fee mechanism.

For the v1 prototype:

- graph semantics MUST be testable with zero-fee logical transactions;
- regtest MUST use a deterministic fixed-fee schedule;
- each transaction template MUST include the exact fee expected by `fee_policy_id`;
- fee accounting MUST be part of every state;
- no fee may be taken silently from a player’s poker stack;
- mainnet deployment is forbidden until a reviewed fee-bumping strategy exists.

A future fee strategy may use anchors, CPFP, external fee inputs, or another reviewed construction, but it MUST NOT permit modification of game-state outputs or invalidate pre-signed descendants.

---

## 31. Required Rust workspace additions

Integrate with the existing `bp52` workspace using modules equivalent to:

```text
crates/
  bp52-poker/
    src/card.rs
    src/score.rs
    src/eval5.rs
    src/subsets.rs

  bp52-lamport/
    src/key.rs
    src/sign.rs
    src/verify.rs
    src/script.rs

  bp52-chain-types/
    src/descriptor.rs
    src/state.rs
    src/node.rs
    src/outcome.rs
    src/codec.rs

  bp52-chain-compiler/
    src/betting.rs
    src/reveals.rs
    src/showdown.rs
    src/graph.rs
    src/manifest.rs

  bp52-chain-bitcoin/
    src/taproot.rs
    src/predicates.rs
    src/transactions.rs
    src/signing.rs
    src/fees.rs

  bp52-chain-runtime/
    src/witness.rs
    src/monitor.rs
    src/timeout.rs
    src/broadcast.rs

  bp52-chain-cli/
    src/main.rs
```

Protocol, codec, compiler, and poker crates MUST use:

```rust
#![forbid(unsafe_code)]
```

---

## 32. Required API surface

At minimum:

```rust
pub fn validate_chain_descriptor(
    descriptor: &ChainGameDescriptor,
) -> Result<(), ChainError>;

pub fn evaluate_five_cards(
    cards: [u8; 5],
) -> Result<u32, PokerError>;

pub fn selected_five(
    seven: [u8; 7],
    subset_id: u8,
) -> Result<[u8; 5], PokerError>;

pub fn verify_claimed_hand(
    seven: [u8; 7],
    subset_id: u8,
    claimed_score: u32,
) -> Result<(), PokerError>;

pub fn prepare_chain_graph(
    verified_descriptor: &VerifiedChainDescriptor,
    verified_deal: &VerifiedAcceptedDeal,
    lamport_public_material: &LamportPublicMaterial,
    origin_output: TxOut,
    fee_policy: &dyn FeePolicy,
) -> Result<PreparedChainGraph, CompilerError>;

pub fn compile_chain_graph(
    prepared: PreparedChainGraph,
    activation_template: TransactionTemplate,
) -> Result<CompiledGraph, CompilerError>;

pub fn verify_compiled_graph(
    verified_descriptor: &VerifiedChainDescriptor,
    graph: &CompiledGraph,
) -> Result<GraphVerificationReport, CompilerError>;

pub fn build_action_witness(
    graph: &dyn ChainBackend,
    monitor: &mut ChainMonitor,
    action: Action,
    signer: &dyn BitcoinSigner,
) -> Result<Witness, RuntimeError>;

pub fn build_reveal_witness(
    graph: &dyn ChainBackend,
    active: &ConfirmedActiveNode<'_>,
    preimages: &[Vec<u8>],
) -> Result<Witness, RuntimeError>;

pub fn build_alice_showdown_witness(
    graph: &dyn ChainBackend,
    monitor: &mut ChainMonitor,
    public_preimages: &PublicPreimageStore,
    alice_secret: &dyn SecretPreimageSource,
    subset_id: u8,
    score: u32,
    score_ots: &mut LamportSecretKey,
) -> Result<Witness, RuntimeError>;

pub fn build_bob_payout_witness(
    graph: &dyn ChainBackend,
    monitor: &mut ChainMonitor,
    public_preimages: &PublicPreimageStore,
    bob_secret: &dyn SecretPreimageSource,
    subset_id: u8,
    score_b: u32,
    outcome_branch: ShowdownOutcome,
    bob_score_ots: &mut LamportSecretKey,
    bob_signer: &dyn BitcoinSigner,
) -> Result<Witness, RuntimeError>;
```

No public API may accept a caller-supplied slot mapping, deck size, number of players, rank ordering, score base, or maximum bets under protocol version 4.

---

## 33. Mandatory poker tests

### 33.1 Exhaustive five-card evaluation

Evaluate all:

```text
C(52,5) = 2,598,960
```

distinct five-card hands.

Verify:

- every hand receives exactly one category;
- category frequencies match known combinatorial counts;
- packed score ordering agrees with an independent reference evaluator;
- suit permutation does not change rank-only categories;
- card-order permutation does not change the score;
- every score has canonical zero padding.

### 33.2 Edge cases

Test:

- royal and nonroyal straight flushes;
- all quad ranks and kickers;
- full-house ordering;
- flush kicker ordering;
- wheel straight and straight flush;
- overlapping straight candidates;
- trips, two pair, pair, and kicker ordering;
- board-only ties;
- equal category with different final kicker;
- duplicate-card rejection;
- invalid card rejection.

### 33.3 Subsets

Verify:

- exactly 21 subset entries;
- lexicographic ordering;
- no duplicate subset;
- every entry is sorted and contains five distinct indices;
- every `5-of-7` subset occurs exactly once.

---

## 34. Mandatory betting and graph tests

### 34.1 Local betting trees

For the exact 100-BB amount state in which neither effective cap can be reached,
verify the reference maximum local counts:

```text
preflop:
    8 decisions
    7 folds
    7 continuations
    8 timeouts

postflop:
    10 decisions
    8 folds
    9 continuations
    10 timeouts
```

### 34.2 Whole tree

For the exact 100-BB reference fixture, assert:

```text
logical nodes including gameplay root      = 56,132
post-activation gameplay templates         = 56,131
templates including canonical activation   = 56,132
maximum post-activation showdown path       = 33
maximum origin-to-settlement path           = 34
```

For unequal short-stack descriptors, assert that manifest and inventory counts
equal the actual compiled graph, do not exceed those reference maxima, and agree
across independent builds.

### 34.3 Rules

Test every state for:

- correct actor;
- exact legal-action set;
- no raise after four bets;
- exact nominal fixed bet increment and deterministic effective-stack cap;
- implicit short all-in bet and raise retain the ordinary action code;
- an all-in aggressor gives the responder only fold and call;
- a matched all-in suppresses every remaining betting street;
- an all-in preflop call suppresses the big-blind option;
- correct big-blind option;
- check-check completion;
- call completion;
- fold terminal;
- timeout terminal;
- correct postflop actor;
- correct street transition.

### 34.4 Accounting

For every node and edge:

- no overflow or underflow;
- exact pot update;
- exact remaining-stack update;
- unmatched excess remains in the larger player's remaining stack;
- unequal-stack win and split settlements never award unmatched excess to the
  shorter player;
- value conservation minus fee;
- correct terminal payout;
- correct split remainder;
- no dust output unless explicitly allowed;
- fee reserve never negative.

---

## 35. Mandatory reveal and showdown tests

Test:

1. Bob cannot deal Alice with a wrong preimage.
2. Alice cannot deal Bob with a wrong preimage.
3. Every reveal rejects lengths outside `16..67`.
4. Every community street requires two distinct reveal transactions.
5. Either reveal timeout produces the configured settlement.
6. Previously revealed preimages can be repeated successfully later.
7. Alice showdown reconstructs exactly slots `0,2,4,5,6,7,8`.
8. Bob showdown reconstructs exactly slots `1,3,4,5,6,7,8`.
9. Alice subset is unsigned.
10. Alice score without a valid OTS signature fails.
11. Alice score not witnessed by the selected hand fails.
12. Bob score requires a valid node-bound Lamport signature.
13. Every Bob terminal branch requires Bob’s private Bitcoin signature, which
    is never exchanged before that branch is exercised.
14. Alice cannot copy Bob’s revealed preimages into a differently paying
    terminal template without Bob’s signature for that template.
15. Bob score not witnessed by the selected hand fails.
16. Bob-win branch accepts only `score_B > score_A`.
17. Split accepts only equality.
18. Alice-win cooperative branch accepts only `score_B < score_A`.
19. Bob timeout pays Alice according to policy.
20. Alice timeout pays Bob according to policy.
21. A weaker but valid five-card claim is accepted.
22. No max-over-21 check exists in Script or Rust claim verification.
23. Every timeout rejects a missing or invalid defaulting-player
    preauthorization.
24. A beneficiary cannot redirect timeout outputs by signing a different
    transaction; the original opponent preauthorization fails on that digest.

---

## 36. Mandatory Lamport tests

For Alice-score and Bob-score OTS:

- valid signature passes;
- one changed message bit fails;
- one changed preimage fails;
- one changed public hash fails;
- wrong node key fails;
- wrong game key material fails;
- score width is exactly 24 bits;
- score bit ordering is consistent across Rust and Script;
- accidental local key reuse causes a hard error;
- unused secrets are zeroized after branch confirmation.

Fuzz all Lamport witness decoders and reject trailing data.

---

## 37. Mandatory Bitcoin Core regtest tests

For every transaction class:

- valid witness confirms;
- wrong Bitcoin signature fails;
- wrong Alice or Bob score Lamport witness fails;
- wrong preimage fails;
- early timeout fails;
- mature timeout confirms;
- a beneficiary-signed timeout with substituted outputs fails because the
  defaulting player’s preauthorization binds the exact compiled template;
- sibling branches conflict as double spends;
- child txid remains stable across valid witness variations;
- descendants remain valid after parent witness insertion;
- terminal outputs match accounting;
- all scripts and witnesses satisfy consensus and standardness limits selected for the prototype;
- mempool package behavior is documented.

At least one complete regtest execution MUST cover:

```text
deal
preflop capped raising
flop two-round reveal
flop check-check
turn two-round reveal
turn capped raising
river two-round reveal
river call
Alice showdown
Bob win payout
```

Additional complete executions MUST cover:

- Alice win via Bob showdown timeout;
- split;
- preflop fold;
- reveal timeout;
- action timeout;
- Alice showdown timeout;
- unequal-stack all-in aggression followed by fold;
- unequal-stack all-in aggression followed by call, forced remaining-board
  runout, and showdown;
- a reveal timeout during a forced all-in runout.

---

## 38. Security invariants for code review

A reviewer MUST confirm:

1. The graph binds the exact accepted-deal hashes and game ID.
2. Activation cannot be authorized before all required counterparty
   preauthorization signatures and local private runtime inventory are verified.
3. No hole-card share is revealed before the activation-created gameplay root
   reaches the configured confirmation depth.
4. Bob’s Alice-hole-card shares are on-chain enforceable.
5. Alice’s Bob-hole-card shares are on-chain enforceable.
6. Each community street has two reveal rounds.
7. Each reveal round has a timeout.
8. Each betting decision has exactly one timeout.
9. Illegal actions have no transaction edge.
10. Four bets total is enforced on every street.
11. All-in amounts are implicit effective-stack caps, never caller supplied;
    the responder retains fold/call, and only a matched all-in forces runout.
12. Dynamic witness data never changes txids.
13. Later transactions repeat prior witness data rather than assuming introspection.
14. Every hand claim is backed by one exact five-card `Eval5`.
15. No seven-card optimality check is present.
16. Alice’s score, but not her subset, is Lamport-signed.
17. Bob’s score, but not his subset, is Lamport-signed.
18. Bob’s showdown and payout are one transaction.
19. Bob’s private Bitcoin signature binds the selected terminal payout template.
20. Bob’s terminal signatures are not disclosed during graph pre-signing.
21. Revealed Bob preimages cannot authorize an alternate payout template.
22. Every timeout requires the defaulting player’s fixed preauthorization and
    the beneficiary’s private post-CSV signature over the same exact template.
23. Bob’s later noncooperation cannot block Alice’s timeout recovery.
24. Every terminal path settles all locked value deterministically.
25. OTS keys are unique per node and purpose.
26. The graph root is deterministic across independent builds.
27. The exact 100-BB fixture produces exactly 56,132 logical nodes, 56,131
    post-activation gameplay templates, and 56,132 templates when the canonical
    activation is included; every descriptor manifest and inventory reports its
    actual graph-derived counts.
28. Mainnet execution is disabled in released builds until all audit gates pass.

---

## 39. Production-readiness gates

Real-funds deployment is forbidden until all of the following are complete:

1. independent review of `BP52-DEAL-v1`;
2. independent review of this chain protocol;
3. audit of the exact Taproot/Tapscript construction;
4. audit of the Lamport implementation and key lifecycle;
5. audit of the five-card Script evaluator;
6. exhaustive cross-implementation poker test vectors;
7. deterministic graph-root agreement between two implementations;
8. transaction-parser and witness-parser fuzzing;
9. Bitcoin Core regtest and signet integration;
10. reviewed fee-bumping and pinning analysis;
11. reviewed timeout economics;
12. storage, backup, and crash-recovery analysis for approximately 56,000 templates;
13. reproducible builds and dependency review;
14. written analysis of mempool races and reorg handling.

---

## 40. Required implementation order

The agent SHOULD implement in this order:

### Milestone 1 — Pure poker core

- card decoder;
- subset table;
- canonical `HandScore`;
- exhaustive `Eval5`;
- score comparison tests.

### Milestone 2 — Pure betting engine

- fixed-limit rules;
- preflop generator;
- postflop generator;
- implicit effective-stack all-ins and forced runout;
- exact descriptor-derived local counts;
- pot and stack accounting.

### Milestone 3 — Logical full tree

- reveal nodes;
- timeout nodes;
- showdown nodes;
- descriptor-derived graph counts plus the reference
  56,132-node / 56,131-gameplay-template maximum regression;
- deterministic node IDs and graph manifest.

### Milestone 4 — Lamport layer

- Alice score OTS;
- Bob score OTS;
- canonical witness encoding;
- zeroization and reuse detection.

### Milestone 5 — Bitcoin predicate layer

- share opening;
- card reconstruction;
- five-card category predicates;
- score comparisons;
- Taproot leaf generation.

### Milestone 6 — Transaction compiler

- witness-independent state-output construction;
- exact origin-to-root activation validation;
- top-down gameplay txid construction from `activation_txid:vout0`;
- normal edge templates;
- timeout templates;
- settlement outputs;
- fixed-fee prototype policy.

### Milestone 7 — Signing and funding gate

- graph-root agreement;
- signature-bundle commit/open;
- full counterparty signature verification;
- readiness report.

### Milestone 8 — Runtime

- chain monitor;
- public-preimage store;
- action witness builder;
- reveal witness builder;
- Alice showdown builder;
- Bob payout builder;
- timeout broadcaster.

### Milestone 9 — Regtest and hardening

- complete-path tests;
- fuzzing;
- crash recovery;
- benchmarks;
- independent test vectors;
- audit preparation.

---

## 41. Final implementation result

A successful implementation produces:

1. a mutually signed `ChainGameDescriptor`;
2. one deterministic graph root;
3. exact descriptor-derived logical-node and gameplay-transaction counts, with
   the 100-BB reference graph bounded at 56,132 nodes and 56,131
   post-activation templates, plus the canonical activation template;
4. all required counterparty preauthorization signatures;
5. retained private runtime signing capability for actor-controlled branches;
6. encrypted local Lamport and card-preimage secrets;
7. a funding-readiness report;
8. a runtime capable of following any valid branch;
9. unilateral timeout recovery from every obligation state;
10. a terminal transaction for every fold, timeout, Bob win, Alice win, or split;
11. a complete public audit transcript.

The defining architecture is:

```text
surrounding funding protocol
    -> pre-existing origin escrow bound into the deal context

BP52-DEAL-v1
    -> accepted hidden deal bound to 18 SHA-256 hashes

BP52-CHAIN-v1 compiler
    -> exact origin-to-root activation template
    -> finite post-activation fixed-limit transaction tree

runtime witnesses
    -> betting actions
    -> card-share reveals
    -> Alice score certificate
    -> Bob score certificate and selected-hand witness

Bitcoin
    -> enforces one valid path
    -> settles without post-activation cooperation
```

Origin construction, contribution proofs, activation authorization, and
pre-activation refunds remain an explicit fail-closed boundary of this version;
they are not implied by the compiler or runtime artifacts above.
