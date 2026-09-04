# Poker on Bitcoin: Core Mechanism

## Overview

We represent one heads-up poker hand as a precomputed tree of Bitcoin
transactions. Each output is one game state, and each transaction spending it
is one legal next move. Only the path actually played is published on-chain.

The main problems are:

1. representing hidden cards in a form Bitcoin can later verify;
2. proving that the jointly generated cards are all different without
   revealing them;
3. enforcing the rules of poker without covenants;
4. revealing cards and ranking hands in Bitcoin Script; and
5. guaranteeing settlement if either player stops cooperating.

## Representing a card on-chain

For each card position, Alice and Bob each choose a secret byte string whose
length encodes a number from 0 to 51. They publish the SHA-256 hash of the
string as a commitment. The card is the sum of their two numbers modulo 52:

```text
alice_value = length(alice_preimage) - 16
bob_value   = length(bob_preimage) - 16
card        = (alice_value + bob_value) mod 52
```

Neither player controls the card alone. When the card must be revealed, the
Bitcoin script checks both preimages against their hashes, checks their
lengths, and computes the card. Because the sum is at most 102, the modulo
operation is just: subtract 52 if the sum is 52 or greater.

This is the simple Bitcoin-facing part of the design. The difficult part is
proving before funding the game that all nine hidden cards are distinct.

## Proving that the cards are unique

SHA-256 commitments are useful to Bitcoin, but they are not algebraic: we
cannot add two hashes or compare the hidden values inside them. The dealing
protocol therefore gives every secret value two additional representations:
a Pedersen commitment and a threshold-encrypted group element.

Each player proves in zero knowledge that the value in their Pedersen
commitment is exactly the length encoded by their SHA-256 preimage. A second
proof links that same committed value to its encrypted representation. These
links are the essential bridge: the efficient off-chain uniqueness check now
applies to exactly the values that Bitcoin will later recover from preimage
lengths.

The encrypted values are homomorphic, so Alice's and Bob's encrypted
contributions can be added to obtain an encryption of each card's unreduced
sum. Two cards are equal modulo 52 exactly when the difference between their
sums is `0`, `52`, or `-52`. For every pair of card positions, the parties
therefore construct encrypted differences for those three cases.

The parties then run a small two-party computation: each independently blinds
every encrypted difference with a fresh nonzero random factor, proves that the
blinding was done correctly, and contributes a partial decryption. If a final
decrypted result is the identity element, the two card positions collide and
the deal is rejected. Otherwise the cards are different. Blinding prevents
the decrypted nonzero differences from revealing the underlying card values.

The important insight is that the expensive zero-knowledge work is used only
to connect SHA-256 preimage lengths to homomorphic values. Once that connection
is proven, uniqueness reduces to simple encrypted pairwise comparisons rather
than a general-purpose secure computation of SHA-256 and modulo arithmetic.

## Keeping hole cards private

Each player initially knows only their own contribution to every card. To deal
Alice a hole card, Bob privately sends Alice his preimage for that position;
Alice can combine it with her own contribution, but Bob still cannot determine
the card because he does not know Alice's preimage. Bob's hole cards are dealt
in the opposite direction. Community-card contributions are revealed by both
players during the hand, and hole cards become public only at showdown.

## Turning poker into a transaction tree

The complete fixed-limit game is expanded in advance into a finite tree. A
node records the street, whose turn it is, both remaining stacks, the pot, the
current wager, and the number of bets made. Each legal check, bet, call, raise,
fold, reveal, showdown, or timeout is a transaction leading to another node or
to final payout outputs.

All competing moves from one state spend the same output. Bitcoin's
double-spend rule therefore guarantees that only one branch can confirm. The
tree stays finite because bet sizes and the number of raises are fixed, there
are only two players, and only one hand is represented.

Every nonterminal state is a Taproot output. Its Taproot tree contains the
scripts that authorize its possible next transitions, plus a hidden,
unspendable leaf committing to the complete logical poker state. This binds the
output to the exact stacks, pot, phase, and actor without publishing a separate
data output.

## Presigning to emulate covenants

Bitcoin does not currently provide the covenant needed to say, "this output
may only be spent into one of these poker states." We emulate that restriction
with signatures prepared before activation.

For every possible move, the opponent of the player who controls that move
presigns the exact transaction. The signature commits to its input, outputs,
fee, and next state. When it is Alice's turn, for example, Bob's signatures
already authorize every legal Alice branch, but Alice chooses one by adding
her live signature and broadcasting that transaction. She cannot create a new
move or redirect the money because it would invalidate Bob's signature.

All transaction IDs are fixed before the game starts. Values known only during
play—live signatures, card preimages, and hand-ranking evidence—are placed in
the SegWit/Taproot witness, which does not affect the transaction ID. This
allows later transactions to be constructed and signed before earlier runtime
witnesses exist.

The central tradeoff is size: covenant-like enforcement is achieved by
enumerating and signing the whole finite game tree off-chain.

## Revealing community cards

Each community street uses two reveal transactions, one for each player's
contribution. The first reveal exposes only one half of the card; the second
completes it. Both steps have timeout branches, so a player cannot learn a
completed community card and then lock the game by refusing to reveal.

Revealed preimages live in transaction witnesses. Bitcoin Script cannot read a
previous transaction's witness, so later showdown transactions repeat the
card preimages they need. The hashes committed at setup let every later script
verify those repeated values independently.

## Ranking a poker hand

At showdown, the script reconstructs a player's two hole cards and the five
community cards. The player selects one of the 21 possible five-card subsets
and supplies a canonical score for it.

The showdown Taproot leaf contains a finite ranking program. It branches over
the possible hand categories—straight flush, four of a kind, full house,
flush, straight, three of a kind, two pair, pair, and high card—and checks the
exact rank and kicker rules for the claimed category. The result is packed so
ordinary integer comparison determines the winner.

The large Taproot construction primarily provides leaves for game-state
transitions. Hand categories are cases inside the showdown script rather than
separate state transactions. This keeps dynamic card data in the witness while
the payout transaction itself remains fixed and presignable.

The script verifies that the chosen five cards have the claimed score, but it
does not test all 21 subsets to prove that the player chose the strongest one.
Choosing a weaker valid hand can only hurt that player's own payout, so the
protocol uses that incentive to avoid a much larger on-chain maximum circuit.

## Carrying the score across transactions

Showdown happens in two steps: Alice reveals and authenticates her score, then
Bob reveals his hand and selects the win, loss, or split payout transaction.
Because a child transaction cannot inspect its parent's witness, Alice's score
must be repeated in Bob's transaction.

A fresh one-time hash-based signature binds Alice's repeated score to the exact
showdown state. Bob uses the same mechanism for his own witness-only score.
The final script verifies both scores, compares them, and checks that the
selected payout branch matches the result.

## Timeouts and unilateral settlement

Every point at which a player owes an action, card reveal, or showdown step has
a relative-timelocked fallback transaction. The player who could default
presigns that exact fallback before activation. After the delay, the other
player can add their own signature and broadcast it without further
cooperation.

The presignature fixes the settlement outputs, so the beneficiary cannot use
the timeout to redirect more money than the rules allow. A timeout returns
both uncommitted stacks and awards the current pot to the non-defaulting
player.

Before activation, the players also prepare a delayed refund from the initial
shared funding output. This covers failure during setup. After activation, the
presigned game tree and its timeout branches cover every remaining outcome.

## Settlement

Every transition preserves the sum of Alice's remaining stack, Bob's remaining
stack, the pot, and the fee reserve, minus the transaction's fixed fee. Fold,
timeout, win, and split branches create the final player outputs directly.

All-in bets are capped at the amount the opponent can match. Unmatched chips
remain in the larger stack instead of entering the pot, so a two-player game
does not need side pots. After a matched all-in, the existing reveal branches
run out the board and lead to the normal showdown.

In short: preimage lengths represent cards, zero-knowledge proofs connect those
commitments to a homomorphic uniqueness check, presigned transactions emulate
covenants, Taproot scripts validate reveals and hand ranks, and timelocks make
the final payout recoverable without cooperation.

## Scope

The current construction represents one two-player fixed-limit hand. It does
not cover no-limit betting, more than two players, multiple hands per funding
output, rake, or production fee bumping. The graph and signature exchange are
large, the private deal is computationally expensive, and the system remains
research software that must not be used with mainnet funds.
