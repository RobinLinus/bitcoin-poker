# BP52-DEAL-v1

## Two-party, hash-opening card deal for Bitcoin

**Status:** Implementable research specification; not approved for mainnet use without an independent cryptographic audit.

**Protocol identifier:** `BP52-DEAL-v1`

**Purpose:** Generate a two-player Texas Hold’em deal represented at the Bitcoin-facing boundary by exactly two ordered arrays of nine SHA-256 hashes. For slot `i`, the lengths of Alice’s and Bob’s corresponding hash preimages determine one card. The protocol proves off-chain, without revealing the cards, that the nine resulting cards are pairwise distinct.

The design uses:

1. SHA-256 preimage-length commitments for the Bitcoin interface;
2. Ristretto255 Pedersen commitments and threshold exponential ElGamal ciphertexts for hidden numeric representations;
3. one aggregated Bulletproof-style R1CS proof per player for the SHA-256/preimage-length relation;
4. a small generalized Schnorr proof per player, batched over nine slots, linking each Pedersen commitment to its ElGamal ciphertext;
5. a specialized threshold-ElGamal two-party computation for the uniqueness test.

The specialized uniqueness protocol directly consumes the homomorphic ciphertexts. It does **not** evaluate SHA-256 and does **not** run elliptic-curve arithmetic inside a generic garbled circuit.

---

## 1. Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

---

## 2. Scope

BP52-DEAL-v1 specifies only:

- generation of nine hidden card values;
- binding those values to two arrays of SHA-256 hashes;
- proof that every hash has a preimage whose length encodes the same hidden value as the corresponding ciphertext;
- proof that the nine paired values represent distinct cards;
- selective opening of card shares;
- the Bitcoin-facing card-opening predicate.

The following are outside this specification:

- funding, escrow, timeout, and penalty transactions;
- guaranteed fairness after abort;
- betting rules and poker hand evaluation;
- wallet key management beyond the requirements stated here;
- native Bitcoin Script verification of Bulletproofs or Ristretto proofs.

The surrounding Bitcoin protocol is assumed to punish a party that fails to send a required message or required preimage by the applicable deadline.

---

## 3. Security model

### 3.1 Adversary

- There are exactly two parties, `A` and `B`.
- At most one party is malicious.
- The malicious party may choose arbitrary inputs, deviate from the protocol, send malformed messages, or abort.
- Abort fairness is delegated to the external Bitcoin penalty protocol.
- The network is adversarial. Every protocol message is authenticated and transcript-bound.

### 3.2 Security goals

For every accepted deal:

1. **Hash binding:** each published hash is bound to a preimage of a proven length;
2. **representation consistency:** the length-derived value equals the plaintext of the corresponding ElGamal ciphertext;
3. **uniqueness:** the nine resulting card identifiers are pairwise distinct;
4. **privacy:** before an authorized reveal, a party learns no peer contribution and no complete card value beyond what follows from its own inputs and the fact that the deal is valid;
5. **selective reveal:** a player can learn its own hole cards without revealing those complete cards to the opponent;
6. **Bitcoin verifiability:** once both preimages for a slot are public, a Bitcoin script or transaction graph can verify the two hashes and the claimed card using only SHA-256 and preimage lengths.

### 3.3 Explicit leakage

The efficient uniqueness protocol in this version has the following deliberate leakage profile:

- for an **accepted** attempt, it reveals only that all nine cards are distinct;
- for a **rejected** attempt, it additionally reveals which slot pairs collided and whether the unreduced sums differed by `-52`, `0`, or `+52`.

All secrets from a rejected attempt MUST be erased and MUST NOT be reused. With fresh honest randomness in every attempt, this rejected-attempt leakage does not reveal any card from the subsequently accepted attempt.

A strict one-bit-only uniqueness functionality is a possible future mode, but requires a substantially heavier committed-input MPC or collaborative proof system and is not BP52-DEAL-v1.

---

## 4. Fixed protocol parameters

```text
DECK_SIZE          = 52
N_SLOTS            = 9
PREIMAGE_BASE_LEN  = 16 bytes
PREIMAGE_MAX_LEN   = 67 bytes
SECURITY_LEVEL     = approximately 128 bits
```

### 4.1 Card contribution

For party `P ∈ {A,B}` and slot `i ∈ {0,...,8}`:

```text
v[P,i] ∈ {0,...,51}
len(x[P,i]) = PREIMAGE_BASE_LEN + v[P,i]
h[P,i] = SHA256(x[P,i])
```

`x[P,i]` is a raw byte string. It is not text and has no character encoding.

### 4.2 Resulting card

For slot `i`:

```text
card[i] = (v[A,i] + v[B,i]) mod 52
```

Equivalently:

```text
card[i] = (len(x[A,i]) + len(x[B,i]) - 32) mod 52
```

The protocol accepts only if all `card[i]` are pairwise distinct.

### 4.3 Card mapping

Card identifier `0..51` is mapped canonically as follows:

```text
rank_index = floor(card_id / 4)
suit_index = card_id mod 4

rank_index:
  0=2, 1=3, 2=4, 3=5, 4=6, 5=7, 6=8,
  7=9, 8=10, 9=Jack, 10=Queen, 11=King, 12=Ace

suit_index:
  0=Clubs, 1=Diamonds, 2=Hearts, 3=Spades
```

Examples:

```text
Clubs Jack = 9
Hearts Ace = 38
```

### 4.4 Slot mapping

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

---

## 5. Cryptographic group and generators

### 5.1 Group

All off-chain commitments, ElGamal operations, and algebraic proofs use the prime-order Ristretto255 group.

Let:

- `q` be the Ristretto scalar-field order;
- `G` be the standard Ristretto base point;
- `M` be an independently derived message generator.

### 5.2 Independent message generator

`M` MUST be deterministically derived with hash-to-group from the exact ASCII string:

```text
BP52-DEAL-v1/message-generator
```

The reference implementation MUST use the Ristretto hash-to-group operation exposed by the selected `curve25519-dalek` version, with SHA-512 as required by that API.

The implementation MUST verify at initialization that:

```text
M != identity
M != G
M != -G
```

No party may select or replace `M`.

**Critical:** ElGamal plaintexts use `M`, while secret keys and encryption randomness use `G`. Using the same generator for both would allow a party in the uniqueness protocol to brute-force the small plaintext differences from published blinding points.

### 5.3 Pedersen commitments

The value commitment for scalar `v` with blinding `gamma` is:

```text
Com(v; gamma) = v*M + gamma*G
```

The Bulletproof Pedersen generator configuration MUST therefore be:

```text
value generator    = M
blinding generator = G
```

---

## 6. Threshold exponential ElGamal

### 6.1 Per-attempt key generation

Every deal attempt uses a fresh joint key.

Party `P` samples a nonzero scalar:

```text
sk[P] <-$ Z_q^*
PK[P] = sk[P] * G
```

Each party publishes `PK[P]` and a Schnorr proof of knowledge of `sk[P]`, bound to:

- protocol identifier;
- game identifier;
- attempt number;
- party role;
- both long-term Bitcoin identity keys.

The joint key is:

```text
Y = PK[A] + PK[B]
```

The attempt MUST be rejected if `Y` is the identity.

No party knows the joint secret key `sk[A] + sk[B]`.

### 6.2 Encryption

To encrypt `v ∈ Z_q` with nonzero randomness `r`:

```text
Enc_Y(v; r) = (R, S)
R = r*G
S = v*M + r*Y
```

Ciphertext addition, subtraction, and scalar multiplication are component-wise:

```text
C1 + C2 = (R1+R2, S1+S2)
C1 - C2 = (R1-R2, S1-S2)
a*C      = (a*R, a*S)
```

A deterministic encryption with zero randomness is used only for public constants:

```text
Enc_Y(t; 0) = (identity, t*M)
```

### 6.3 Partial decryption

For ciphertext `(R,S)`, party `P` computes:

```text
Z[P] = sk[P] * R
```

The plaintext group element is:

```text
PlainPoint = S - Z[A] - Z[B]
```

The protocol never jointly decrypts an original card-contribution ciphertext. It decrypts only independently blinded difference ciphertexts during the uniqueness test.

---

## 7. Bitcoin-facing output interface

The minimal accepted output is:

```rust
struct AcceptedDeal {
    protocol_version: u16,          // 1
    game_id: [u8; 32],
    attempt: u32,
    hashes_a: [[u8; 32]; 9],
    hashes_b: [[u8; 32]; 9],
    verification_transcript_root: [u8; 32],
    signature_a: [u8; 64],          // BIP340
    signature_b: [u8; 64],          // BIP340
}
```

The Bitcoin transaction graph consumes `hashes_a` and `hashes_b`. The full off-chain certificate is archived separately.

All 18 SHA-256 hashes MUST be pairwise distinct. This prevents one revealed preimage from satisfying multiple hash locks.

---

## 8. Share and card opening predicates

### 8.1 Share opening

```text
VerifyShareOpening(h, x):
    require 16 <= len(x) <= 67
    require SHA256(x) == h
    return len(x) - 16
```

### 8.2 Card opening

```text
VerifyCardOpening(slot, xA, xB, claimed_card):
    a = VerifyShareOpening(h[A,slot], xA)
    b = VerifyShareOpening(h[B,slot], xB)
    require claimed_card in 0..51
    require a+b == claimed_card OR a+b == claimed_card+52
    return true
```

The two-comparison rule avoids requiring a modulo opcode in Bitcoin Script.

### 8.3 Hole-card privacy

To deliver Alice’s hole card in slot `0` or `2`, Bob reveals only `x[B,i]` to Alice. Alice already knows `x[A,i]`, so she learns the complete card. Bob does not know `x[A,i]` and therefore does not learn Alice’s complete card.

To deliver Bob’s hole card in slot `1` or `3`, Alice analogously reveals only `x[A,i]` to Bob.

Community cards are revealed by both parties at the applicable game stage.

At showdown, a player makes its complete hole card publicly verifiable by publishing its own previously hidden share; the opponent’s share for that slot was already delivered when the hole card was dealt.

---

## 9. Public and secret per-slot data

For party `P` and slot `i`:

### 9.1 Secret witness

```text
v[P,i]       : u8 in 0..51
x[P,i]       : byte string of length 16+v[P,i]
r[P,i]       : nonzero Scalar, ElGamal randomness
gamma[P,i]   : Scalar, Pedersen blinding
```

### 9.2 Public data

```text
h[P,i] = SHA256(x[P,i])
V[P,i] = v[P,i]*M + gamma[P,i]*G
C[P,i] = Enc_Y(v[P,i]; r[P,i])
```

### 9.3 Required proofs

Each player publishes:

1. one aggregated `HashLengthProof` over all nine `(h[P,i], V[P,i])` pairs;
2. one batched `EncryptionLinkProof` over all nine `(V[P,i], C[P,i])` pairs.

---

## 10. Contribution generation

For each slot, an honest party MUST:

1. sample `v` uniformly from `0..51` using rejection sampling;
2. allocate exactly `16+v` bytes;
3. fill every byte with output from the operating-system CSPRNG;
4. compute the SHA-256 hash over exactly those bytes;
5. sample nonzero ElGamal randomness `r`;
6. sample Pedersen blinding `gamma` uniformly from `Z_q`; resample it if `V = v*M + gamma*G` is the identity;
7. compute `V` and `C`;
8. retain `x` in zeroizing secret memory.

Uniform sampling from `0..51` MUST NOT use a biased `random_byte % 52`. A valid byte-based method is:

```text
repeat:
    z <- random u8
until z < 208
v = z mod 52
```

---

## 11. Bulletproof hash-length proof

### 11.1 Decision

BP52-DEAL-v1 uses a Bulletproof-style fixed R1CS proof for the SHA-256/preimage-length relation. It does **not** put ElGamal curve arithmetic inside the R1CS circuit.

One proof is generated per player and covers all nine slots.

A standalone Bulletproof range proof is insufficient: it can establish only that `v` lies in a range. The protocol requires a programmable arithmetic-circuit proof because it must additionally establish `SHA256(x)=h` and `len(x)=16+v` for the same committed `v`.

### 11.2 Public statement

For role `P`, the public statement is:

```text
(game_id, attempt, role, Y, G, M, circuit_id,
 h[P,0..8], V[P,0..8])
```

### 11.3 Witness relation

The prover proves knowledge of, for every slot `i`:

```text
v_i, gamma_i, x_i
```

such that:

```text
V_i = v_i*M + gamma_i*G
v_i ∈ {0,...,51}
len(x_i) = 16 + v_i
SHA256(x_i) = h_i
```

### 11.4 Fixed circuit shape

The circuit shape MUST be independent of every witness value.

For each slot, allocate:

- 52 one-hot selector bits `lambda[0..51]`;
- 67 private message bytes represented as 536 Boolean bits;
- a committed scalar `v` opened by the Bulletproof commitment `V`;
- all intermediate SHA-256 Boolean variables.

Enforce:

```text
lambda[k] * (lambda[k] - 1) = 0       for every k
sum(lambda[k]) = 1
v = sum(k * lambda[k])
```

This simultaneously proves that `v` is exactly one integer in `0..51`.

The witness supplies a 67-byte buffer. Bytes after the selected logical length MUST be constrained to zero.

### 11.5 Exact variable-length SHA-256 construction

Let `L = 16+v`. Since `16 <= L <= 67`, SHA-256 uses at most two 512-bit compression blocks.

The circuit MUST construct canonical SHA-256 padding for exactly `L` bytes and MUST always instantiate two compression gadgets so that circuit shape and proof size do not reveal whether `L <= 55`.

Construct `block_1` as follows:

- if `L <= 55`, it contains the message, `0x80`, zero padding, and the 64-bit big-endian bit length `8*L` in bytes `56..63`;
- if `56 <= L <= 63`, it contains the message, `0x80`, and zeros to byte `63`;
- if `64 <= L <= 67`, it contains the first 64 message bytes.

Construct `block_2` as follows:

- if `L <= 55`, it is exactly 64 zero bytes and is ignored by the final selector;
- if `56 <= L <= 63`, it contains zeros followed by the bit length in bytes `56..63`;
- if `64 <= L <= 67`, it contains the remaining message bytes, `0x80`, zeros, and the bit length in bytes `56..63`.

Then compute:

```text
H1 = SHA256_Compress(IV, block_1)
H2 = SHA256_Compress(H1, block_2)
is_long = sum(lambda[40..51])   // L >= 56
Digest = select(is_long, H2, H1)
```

Every digest bit MUST equal the corresponding public bit of `h_i`.

The implementation MUST follow FIPS SHA-256 bit ordering and big-endian word parsing exactly.

### 11.6 Aggregation

All nine slot relations for one player MUST be included in one fixed circuit and one proof. This reduces proof overhead but does not reduce the linear SHA-256 proving work.

### 11.7 Generator capacity

Let `n_mul` be the exact number of multiplication constraints in the compiled nine-slot circuit. The Bulletproof generator capacity MUST be:

```text
gens_capacity = next_power_of_two(n_mul)
party_capacity = 1
```

The implementation MUST reject proof generation or verification if the local generator capacity is smaller than the value committed into the circuit manifest. Generator vectors MUST be deterministically produced by the proof backend; they MUST NOT be supplied over the network.

### 11.8 Circuit identity

The implementation MUST define:

```text
circuit_id = SHA256(canonical_circuit_manifest)
```

The manifest MUST include at least:

- protocol version;
- slot count;
- base and maximum preimage lengths;
- SHA-256 gadget version;
- exact multiplier and constraint counts;
- Bulletproof backend identifier and source revision.

The verifier MUST use a locally compiled circuit with the expected `circuit_id`. A prover MUST NOT supply an arbitrary circuit.

---

## 12. Batched ElGamal/commitment link proof

A generalized Schnorr proof links the same hidden scalar to the Pedersen commitment and ElGamal ciphertext without non-native curve arithmetic in R1CS.

For every slot, prove knowledge of `(v, gamma, r)` satisfying:

```text
V = v*M + gamma*G
R = r*G
S = v*M + r*Y
```

### 12.1 Prover

For each slot `i`, sample random scalars:

```text
v_hat[i], gamma_hat[i], r_hat[i]
```

Compute:

```text
T_V[i] = v_hat[i]*M + gamma_hat[i]*G
T_R[i] = r_hat[i]*G
T_S[i] = v_hat[i]*M + r_hat[i]*Y
```

Append all public statements and all `T` points in slot order to a Merlin transcript. Derive one challenge `e`.

Responses:

```text
z_v[i]     = v_hat[i]     + e*v[i]
z_gamma[i] = gamma_hat[i] + e*gamma[i]
z_r[i]     = r_hat[i]     + e*r[i]
```

### 12.2 Verifier

For every slot, verify:

```text
z_v*M + z_gamma*G == T_V + e*V
z_r*G             == T_R + e*R
z_v*M + z_r*Y     == T_S + e*S
```

The verifier MUST reject noncanonical point/scalar encodings, identity `R`, and identity `V`.

---

## 13. Simultaneous bundle commitment

To prevent either party from choosing its public bundle after seeing the peer’s bundle, use commit-then-open.

### 13.1 Player bundle

```rust
struct SlotPublic {
    hash: [u8; 32],
    value_commitment: [u8; 32],
    ciphertext_r: [u8; 32],
    ciphertext_s: [u8; 32],
}

struct PlayerBundle {
    role: u8,
    slots: [SlotPublic; 9],
    hash_length_proof: Vec<u8>,
    encryption_link_proof: EncryptionLinkProof,
    circuit_id: [u8; 32],
}
```

### 13.2 Bundle commitment

Each party samples a fresh 32-byte `bundle_nonce` and sends:

```text
bundle_commitment = TaggedSHA256(
    "BP52/bundle-commit/v1",
    game_id || attempt || role || bundle_nonce || Encode(PlayerBundle)
)
```

Only after both signed commitments are received do the parties exchange `(bundle_nonce, PlayerBundle)`.

### 13.3 Bundle verification

A party MUST verify, in this order:

1. message signature, game ID, attempt, role, sequence, and transcript predecessor;
2. bundle commitment opening;
3. canonical decoding and exact array sizes;
4. expected `circuit_id`;
5. all 18 hashes are globally distinct after both bundles are available;
6. all points are canonical and required nonidentity checks pass;
7. peer key proof;
8. peer Bulletproof hash-length proof;
9. peer batched encryption-link proof.

A failure is a protocol fault, not a normal card collision.

---

## 14. Public homomorphic card sums

After both bundles verify, derive for every slot:

```text
SumCipher[i] = C[A,i] + C[B,i]
```

It encrypts the unreduced integer:

```text
s_i = v[A,i] + v[B,i]
```

where `0 <= s_i <= 102`.

No explicit modulo reduction is required for the uniqueness test.

---

## 15. Uniqueness condition over unreduced sums

For two slots `i < j`, the final cards collide exactly when:

```text
s_i - s_j ∈ {-52, 0, +52}
```

This equivalence is exact because every `s_i` lies in `0..102`.

For every pair `i<j` and every offset `t ∈ {-52,0,+52}`, derive:

```text
D[i,j,t] = SumCipher[i] - SumCipher[j] - Enc_Y(t; 0)
```

`D[i,j,t]` encrypts:

```text
d[i,j,t] = s_i - s_j - t
```

There are:

```text
C(9,2) * 3 = 36 * 3 = 108
```

difference ciphertexts.

The deal is valid exactly when none of the 108 plaintexts is zero.

Canonical test order is:

```text
for i in 0..8:
    for j in (i+1)..8:
        for t in [-52, 0, +52]:
            append (i,j,t)
```

---

## 16. Specialized uniqueness 2PC

### 16.1 Overview

Each difference ciphertext is multiplied by two independently chosen nonzero secret scalars, one from each party, then threshold-decrypted.

For plaintext `d` and nonzero scalars `alpha,beta`:

```text
alpha*beta*d*M == identity  iff  d == 0
```

If `d != 0` and at least one scalar is honestly uniform, the resulting plaintext point is computationally unlinkable to the small value `d` under the DDH assumption and the unknown discrete-log relation between `G` and `M`.

### 16.2 First blinding round

The first blinder is selected deterministically:

```text
first_blinder = low_bit(
    TaggedSHA256("BP52/first-blinder/v1", game_id || attempt)
)
```

`0` denotes Alice; `1` denotes Bob.

For every test index `k`, the first blinder samples independently:

```text
alpha[k] <-$ Z_q^*
Q_alpha[k] = alpha[k]*G
E1[k] = alpha[k] * D[k]
```

The party publishes `Q_alpha[0..107]`, `E1[0..107]`, and a batched scale proof.

### 16.3 Batched scale proof

For every index `k`, prove the same nonzero scalar maps:

```text
G       -> Q_alpha[k]
D[k].R  -> E1[k].R
D[k].S  -> E1[k].S
```

For each `k`, sample `w[k]` and compute:

```text
T_G[k] = w[k]*G
T_R[k] = w[k]*D[k].R
T_S[k] = w[k]*D[k].S
```

Append every public statement and every temporary commitment in canonical order to one Merlin transcript. Derive challenge `e` and publish:

```text
z[k] = w[k] + e*alpha[k]
```

Verify:

```text
z[k]*G      == T_G[k] + e*Q_alpha[k]
z[k]*D[k].R == T_R[k] + e*E1[k].R
z[k]*D[k].S == T_S[k] + e*E1[k].S
```

The verifier MUST reject any identity `Q_alpha[k]`; this enforces `alpha[k] != 0`.

### 16.4 Second blinding round

The other party independently samples `beta[k] ∈ Z_q^*` and computes:

```text
Q_beta[k] = beta[k]*G
E2[k] = beta[k] * E1[k]
```

It publishes the analogous scale proof relative to `E1[k]` and `E2[k]`.

After both rounds:

```text
E2[k] encrypts alpha[k]*beta[k]*d[k]
```

Neither party knows the product `alpha[k]*beta[k]`.

### 16.5 Simultaneous partial-decryption commitment

Each party computes, for all `k`:

```text
Z[P,k] = sk[P] * E2[k].R
```

Before revealing the batch, each party commits to its complete partial-decryption message with a fresh 32-byte nonce using the bundle-commit pattern. The messages are opened only after both commitments are received.

This prevents a party from learning the zero-test outputs before it has irrevocably committed its own decryption shares.

### 16.6 Batched partial-decryption proof

For party `P`, prove that the same key share `sk[P]` satisfies:

```text
PK[P] = sk[P]*G
Z[P,k] = sk[P]*E2[k].R   for every k
```

Sample one random scalar `w` and compute:

```text
T_G = w*G
T[k] = w*E2[k].R
```

Derive challenge `e` from a Merlin transcript containing all statements and commitments, then publish:

```text
z = w + e*sk[P]
```

Verify:

```text
z*G       == T_G + e*PK[P]
z*E2[k].R == T[k] + e*Z[P,k]   for every k
```

### 16.7 Final zero tests

After both partial-decryption batches and proofs verify, compute:

```text
Plain[k] = E2[k].S - Z[A,k] - Z[B,k]
```

Then:

```text
valid = true
for k in 0..107:
    if Plain[k] == identity:
        valid = false
```

- `valid=true` is an accepted uniqueness result.
- `valid=false` is a normal random collision and triggers a fresh attempt.
- An invalid scale proof, invalid decryption proof, malformed message, or timeout is a protocol fault attributable to the sender.

### 16.8 Why `M` must differ from `G`

The blinding proofs publish points such as `alpha*G`. If plaintexts were encoded as `d*G`, a party knowing the other blinding scalar could test the small candidate values by comparing scalar multiples of `alpha*G` against the decrypted blinded point. Encoding plaintexts with independently derived `M` prevents this test under DDH.

---

## 17. Attempt lifecycle

### 17.1 State machine

```text
INIT
  -> KEY_COMMIT / KEY_OPEN / KEY_VERIFY
  -> BUNDLE_COMMIT
  -> BUNDLE_OPEN_AND_VERIFY
  -> DERIVE_SUMS_AND_TESTS
  -> FIRST_BLIND
  -> SECOND_BLIND
  -> DECRYPTION_COMMIT
  -> DECRYPTION_OPEN_AND_VERIFY
  -> ACCEPTED or COLLISION_RETRY or PROTOCOL_FAULT
```

Every transition consumes exactly one expected signed message from the peer. Unexpected, repeated, stale, or out-of-order messages MUST be rejected.

### 17.2 Retry

On `COLLISION_RETRY`:

- increment `attempt`;
- erase all attempt secrets;
- generate a fresh threshold key;
- generate fresh values, preimages, encryption randomness, proof randomness, and bundle nonce;
- never reuse any hash or ciphertext.

For uniformly random contributions, a nine-card attempt succeeds with probability:

```text
(52*51*50*49*48*47*46*45*44) / 52^9
≈ 0.4802547054
```

The expected number of attempts is approximately `2.08223`.

### 17.3 Acceptance

On `ACCEPTED`, both parties compute:

```text
verification_transcript_root = final protocol transcript hash
```

They then sign the canonical `AcceptedDeal` body with their long-term BIP340 Bitcoin identity keys.

A party MUST NOT sign the accepted deal before all proofs and all 108 zero tests have verified.

---

## 18. Transcript and message authentication

### 18.1 Game identifier

Roles are assigned canonically: Alice is the party with the lexicographically smaller 32-byte x-only Bitcoin identity key.

```text
game_id = TaggedSHA256(
    "BP52/game/v1",
    network_id || funding_outpoint || alice_xonly_pk || bob_xonly_pk || session_nonce
)
```

`session_nonce` is 32 random bytes agreed by commit-reveal or supplied by the surrounding funding protocol.

### 18.2 Message envelope

Every message uses the following logical envelope:

```rust
struct Envelope {
    protocol_version: u16,
    game_id: [u8; 32],
    attempt: u32,
    round: u16,
    sender_role: u8,
    sequence: u32,
    previous_message_hash: [u8; 32],
    payload_type: u16,
    payload: Vec<u8>,
    signature: [u8; 64],
}
```

The signature is BIP340 over a tagged SHA-256 hash of every field except `signature`.

### 18.3 Transcript hash chain

```text
T_0 = TaggedSHA256("BP52/transcript-start/v1", game_id || attempt)
T_n = TaggedSHA256("BP52/transcript-msg/v1", T_(n-1) || Encode(envelope_n))
```

All proof transcripts additionally bind to the appropriate `T_n` pre-state.

### 18.4 Merlin domain separation

Use exact transcript labels:

```text
BP52/key-pop/v1
BP52/hash-length/v1
BP52/encryption-link/v1
BP52/scale-first/v1
BP52/scale-second/v1
BP52/partial-decrypt-A/v1
BP52/partial-decrypt-B/v1
```

Proof verifiers MUST append fields in the exact order defined by the reference implementation and MUST reject trailing or omitted data.

---

## 19. Canonical binary encoding

Do not use `bincode`, JSON, or unconstrained Serde output as the protocol encoding.

### 19.1 Primitive encodings

```text
u8, u16, u32, u64: unsigned little-endian
Hash32:             32 raw bytes
Point32:            canonical compressed Ristretto encoding
Scalar32:           canonical little-endian scalar encoding
Signature64:        64 raw BIP340 bytes
ByteVector:         u32 byte length followed by exactly that many bytes
Fixed array:        elements concatenated without a count
```

### 19.2 Decoder requirements

The decoder MUST:

- reject noncanonical scalars;
- reject point decompression failures;
- reject duplicate map fields; no map encoding is used in v1;
- reject incorrect fixed-array lengths;
- reject integer overflows;
- reject trailing bytes;
- apply strict maximum message sizes before allocation.

### 19.3 Maximums

```text
maximum preimage opening = 67 bytes
maximum slot count       = exactly 9
maximum zero-test count  = exactly 108
maximum proof/message sizes are compile-time constants derived from v1 formats
```

---

## 20. Secret handling

The implementation MUST zeroize:

- threshold secret-key shares;
- ElGamal randomness;
- Pedersen blindings;
- Bulletproof witness buffers;
- scale factors and proof nonces;
- rejected-attempt preimages;
- temporary SHA-256 circuit witnesses.

After a deal is accepted, each party SHOULD retain only:

- its nine raw preimages;
- the accepted deal descriptor;
- the full public verification transcript;
- any data required by the external penalty protocol.

The per-attempt threshold key shares and all encryption/proof randomness SHOULD be erased immediately after acceptance signatures are complete.

Preimages MUST be encrypted at rest.

---

## 21. Reference implementation language and libraries

### 21.1 Language

Use Rust with:

- stable Rust for all production modules;
- a separately isolated proof-backend crate if the selected Bulletproof R1CS implementation requires nightly Rust;
- `#![forbid(unsafe_code)]` in protocol, codec, state-machine, and proof-composition crates;
- any unavoidable `unsafe` confined to audited upstream cryptographic dependencies.

### 21.2 Cryptographic libraries

Use the following stack:

1. **Ristretto arithmetic:** `curve25519-dalek`, version compatible with the selected Bulletproof backend, with `digest`, `rand_core`, and `zeroize` features;
2. **Bulletproof backend:** a vendored, commit-pinned fork of `zkcrypto/bulletproofs`/Dalek Bulletproofs with the R1CS feature enabled;
3. **Fiat-Shamir transcripts:** `merlin` 3.x;
4. **SHA-256/SHA-512 reference hashing:** RustCrypto `sha2` and `bitcoin_hashes` for differential tests;
5. **Bitcoin types, BIP340 signatures, and regtest scripts:** `rust-bitcoin` and its `secp256k1` dependency;
6. **secret erasure:** `zeroize` and `Zeroizing<T>`;
7. **constant-time equality/conditionals:** `subtle`;
8. **OS randomness:** `rand_core::OsRng` or the backend’s direct `getrandom` integration.

Do not use OpenSSL for protocol cryptography.

### 21.3 Important Bulletproof implementation warning

The public Dalek/zkcrypto Bulletproof crate describes its generic R1CS feature as unstable and unsuitable for deployment. Therefore:

- the implementation agent MAY use it for the first interoperable prototype;
- the exact source revision MUST be vendored and pinned;
- the protocol MUST NOT be deployed with real funds until the R1CS backend, SHA-256 gadget, transcript composition, and serialization have received an independent audit;
- the audit MUST evaluate the refined security analysis for Bulletproof R1CS and confirm that the chosen backend proves exactly the relation specified here.

The abstract protocol is not tied to one proof serialization forever. Replacing the proof backend requires a new protocol version and new `circuit_id`.

### 21.4 Development tools

Use:

- `cargo test` for unit/integration tests;
- `proptest` for algebraic and serialization properties;
- `cargo-fuzz`/libFuzzer for decoders and proof parsers;
- `criterion` for proof and uniqueness benchmarks;
- `cargo-audit` and `cargo-deny` in CI;
- Bitcoin Core regtest for card-opening script tests;
- reproducible release builds with committed `Cargo.lock`.

---

## 22. Recommended workspace layout

```text
bp52/
  Cargo.toml
  Cargo.lock
  crates/
    bp52-codec/
      src/lib.rs
    bp52-group/
      src/generators.rs
      src/elgamal.rs
    bp52-sigma/
      src/schnorr.rs
      src/encryption_link.rs
      src/scale.rs
      src/partial_decrypt.rs
    bp52-circuit/
      src/boolean.rs
      src/sha256.rs
      src/hash_length.rs
    bp52-proof-backend/
      src/lib.rs
    bp52-uniqueness/
      src/lib.rs
    bp52-protocol/
      src/messages.rs
      src/state.rs
      src/transcript.rs
    bp52-bitcoin/
      src/opening.rs
      src/scripts.rs
    bp52-cli/
      src/main.rs
  fuzz/
  test-vectors/
  docs/
```

---

## 23. Required Rust API surface

```rust
pub const N_SLOTS: usize = 9;
pub const DECK_SIZE: u8 = 52;
pub const PREIMAGE_BASE_LEN: usize = 16;
pub const PREIMAGE_MAX_LEN: usize = 67;
pub const ZERO_TEST_COUNT: usize = 108;

pub enum Role { Alice, Bob }

pub struct Ciphertext {
    pub r: [u8; 32],
    pub s: [u8; 32],
}

pub struct SlotPublic {
    pub hash: [u8; 32],
    pub value_commitment: [u8; 32],
    pub ciphertext: Ciphertext,
}

pub struct PlayerBundle {
    pub role: Role,
    pub slots: [SlotPublic; N_SLOTS],
    pub circuit_id: [u8; 32],
    pub hash_length_proof: Vec<u8>,
    pub encryption_link_proof: Vec<u8>,
}

pub struct SecretContribution {
    // All fields zeroize on drop.
    pub preimages: [Vec<u8>; N_SLOTS],
    pub values: [u8; N_SLOTS],
    pub encryption_randomness: [Scalar; N_SLOTS],
    pub commitment_blindings: [Scalar; N_SLOTS],
}

pub fn generate_player_bundle<R: CryptoRng + RngCore>(
    params: &ProtocolParams,
    context: &AttemptContext,
    role: Role,
    joint_key: &RistrettoPoint,
    rng: &mut R,
) -> Result<(PlayerBundle, SecretContribution), ProtocolError>;

pub fn verify_player_bundle(
    params: &ProtocolParams,
    context: &AttemptContext,
    joint_key: &RistrettoPoint,
    bundle: &PlayerBundle,
) -> Result<(), ProtocolError>;

pub fn derive_zero_test_ciphertexts(
    bundle_a: &PlayerBundle,
    bundle_b: &PlayerBundle,
) -> Result<[Ciphertext; ZERO_TEST_COUNT], ProtocolError>;

pub fn verify_uniqueness_transcript(
    context: &AttemptContext,
    key_setup: &JointKeyPublic,
    bundle_a: &PlayerBundle,
    bundle_b: &PlayerBundle,
    transcript: &UniquenessTranscript,
) -> Result<bool, ProtocolError>;

pub fn verify_share_opening(
    expected_hash: &[u8; 32],
    preimage: &[u8],
) -> Result<u8, OpeningError>;

pub fn verify_card_opening(
    expected_hash_a: &[u8; 32],
    preimage_a: &[u8],
    expected_hash_b: &[u8; 32],
    preimage_b: &[u8],
    claimed_card: u8,
) -> Result<(), OpeningError>;
```

No API may accept a caller-supplied generator, deck size, slot count, base length, or circuit shape under protocol version 1.

---

## 24. Error taxonomy

```rust
enum ProtocolError {
    MalformedEncoding,
    NonCanonicalPoint,
    NonCanonicalScalar,
    WrongProtocolVersion,
    WrongGame,
    WrongAttempt,
    WrongRound,
    InvalidSignature,
    TranscriptMismatch,
    BundleCommitmentMismatch,
    DuplicateHash,
    InvalidKeyProof,
    InvalidHashLengthProof,
    InvalidEncryptionLinkProof,
    InvalidScaleProof,
    ZeroScaleFactor,
    InvalidPartialDecryptionProof,
    UnexpectedIdentity,
    MessageTooLarge,
    Timeout,             // supplied by outer protocol
}

enum AttemptOutcome {
    Accepted(AcceptedDeal),
    CollisionRetry { collision_bitmap: [bool; 108] },
    Fault { blamed_role: Role, error: ProtocolError },
}
```

Normal collisions MUST NOT be classified as cheating.

---

## 25. Mandatory tests

### 25.1 SHA-256 circuit tests

For every length `L=16..67`:

- generate at least 100 random messages;
- prove and verify the relation;
- compare the circuit digest with RustCrypto SHA-256 and Bitcoin Core/regtest behavior;
- mutate every public hash byte and require proof failure;
- mutate `V` and require proof failure;
- verify proof size is identical for every `L`.

### 25.2 Complete length/card matrix

For all `a,b ∈ 0..51`:

```text
lenA = 16+a
lenB = 16+b
expected = (a+b) mod 52
```

Verify that `VerifyCardOpening` accepts exactly `expected` and rejects all other card identifiers.

### 25.3 Encryption-link tests

For each equation independently:

- valid witness passes;
- altered `V`, `R`, `S`, `Y`, role, slot, game ID, or attempt fails;
- reused proof under another slot or game fails;
- noncanonical and identity points are rejected as specified.

### 25.4 Uniqueness tests

Test at least:

- nine distinct cards: accept;
- raw-sum difference `0`: reject;
- raw-sum difference `+52`: reject;
- raw-sum difference `-52`: reject;
- every noncollision difference in `[-102,102]`: no false identity;
- zero blinding scalar: reject;
- incorrect component scaling: reject;
- incorrect partial decryption: reject;
- reordered test vector: reject;
- missing test: reject;
- repeated test: reject.

### 25.5 Adversarial parser tests

Fuzz:

- every message decoder;
- point/scalar parsers;
- proof parsers;
- length prefixes;
- duplicate/trailing data;
- maximum-size boundaries;
- transcript round and sequence logic.

### 25.6 Distribution tests

With one party fixed adversarially and the other sampling honestly:

- simulate a large number of attempts;
- confirm accepted ordered card tuples are consistent with a uniform without-replacement deal;
- confirm invalid attempts are never reused.

Statistical tests support implementation validation but are not a cryptographic proof.

### 25.7 Bitcoin regtest tests

For each card ID and representative preimage lengths:

- valid preimages satisfy the intended Taproot/script leaf;
- wrong hash fails;
- wrong length/card claim fails;
- `s=card` and `s=card+52` paths both work;
- no modulo opcode is required;
- witness elements stay below Bitcoin’s stack-element limit.

---

## 26. Performance requirements

The implementation MUST expose benchmarks for:

- one-player nine-slot Bulletproof generation;
- one-player Bulletproof verification;
- nine-slot encryption-link proof generation/verification;
- 108-test first and second blinding rounds;
- two partial-decryption batches;
- complete attempt bandwidth and latency;
- peak resident memory during proving.

The SHA-256 Bulletproof is expected to dominate CPU and memory. The uniqueness 2PC is intentionally limited to fixed-size Ristretto operations and small Sigma proofs.

No performance optimization may:

- make circuit shape witness-dependent;
- reuse proof nonces or blinding scalars;
- replace independent per-test uniqueness scalars with one shared scalar;
- skip canonical decoding;
- use `M=G`;
- batch equations with an unreviewed ad-hoc random-linear-combination argument.

---

## 27. Security invariants for code review

A review MUST confirm all of the following:

1. `M` is independently hash-derived and never caller-controlled.
2. Every original contribution value is proven in `0..51`.
3. Every SHA-256 proof uses the exact variable input length, not a fixed 67-byte hash with zero suffixes.
4. The same `V` is consumed by the hash-length proof and encryption-link proof.
5. The same `C` is consumed by the encryption-link proof and uniqueness protocol.
6. Every one of the 108 test ciphertexts is derived locally in canonical order.
7. Both blinding layers use independent nonzero scalars for every test.
8. Every scaling relation covers both ciphertext components.
9. Every partial decryption is covered by a same-key DLEQ proof.
10. Decryption batches are commit-opened simultaneously.
11. All 18 hashes are globally distinct.
12. A rejected attempt never reuses any secret or public commitment.
13. Accepted-deal signatures occur only after successful uniqueness verification.
14. Key shares are erased after acceptance.
15. Proof transcripts bind protocol version, game ID, attempt, role, slot ordering, joint key, circuit ID, and prior transcript state.

---

## 28. Security rationale

### 28.1 Correct deck distribution

Fix any contribution vector selected by a malicious party. If the honest party independently samples each of its nine values uniformly from `Z_52`, then each resulting card is uniformly distributed in `Z_52`, and the ordered nine-card vector is uniform over `Z_52^9`. Conditioning on the uniqueness test accepting produces a uniform ordered sample of nine distinct cards — exactly a deal without replacement.

### 28.2 No party knows a hole card alone

Before selective reveal, each party knows only its own additive contribution. Threshold ElGamal and the accepted uniqueness transcript do not reveal the peer contribution. A hole card becomes known to its owner only when the opponent supplies the corresponding preimage share.

### 28.3 Binding to Bitcoin hashes

The Bulletproof relation binds a Pedersen-committed scalar to the exact length of a SHA-256 preimage. The Schnorr relation binds the same Pedersen commitment to the ElGamal plaintext. Therefore the uniqueness result applies to the same values that later appear as Bitcoin-visible preimage lengths.

### 28.4 Why homomorphism helps

Ciphertext addition creates encryptions of the unreduced paired sums without either party exposing a share. The MPC then performs only scalar multiplication, proof of correct scaling, threshold partial decryption, and identity tests. SHA-256 is evaluated only in the independent proofs, never in the two-party uniqueness protocol.

### 28.5 Public verifiability off-chain

Given the full transcript, any external verifier can verify the key proofs, both players’ hash-length and encryption-link proofs, both blinding proofs, both partial-decryption proofs, and the final nonidentity checks. Bitcoin itself consumes only the accepted hash arrays and opening preimages.

---

## 29. Production-readiness gates

Real-funds deployment is forbidden until all of the following are complete:

1. independent cryptographic review of this protocol;
2. audit of the exact Bulletproof R1CS backend revision;
3. audit and differential verification of the SHA-256 gadget;
4. audit of every generalized Schnorr/DLEQ transcript;
5. independent implementation or cross-implementation test vectors;
6. parser and state-machine fuzzing with no unresolved findings;
7. constant-time and secret-erasure review;
8. Bitcoin regtest and signet integration tests for every opening path;
9. reproducible builds and dependency review;
10. a written analysis of the surrounding timeout/penalty graph.

---

## 30. Implementation milestones

### Milestone 1 — deterministic core

- canonical codec;
- game/transcript identifiers;
- Ristretto generators;
- exponential ElGamal;
- key proof and partial-decryption proof;
- exhaustive unit tests.

### Milestone 2 — uniqueness protocol

- derive all 108 tests;
- implement scale proofs;
- implement commit-open partial decryptions;
- public transcript verifier;
- malicious-deviation tests.

### Milestone 3 — independent player proofs

- fixed SHA-256 compression gadget;
- variable-length padding gadget;
- one-hot length selection;
- one-player nine-slot Bulletproof;
- encryption-link proof;
- circuit manifest and ID.

### Milestone 4 — complete state machine

- bundle commit/open;
- signed envelopes;
- retries and erasure;
- accepted-deal signatures;
- deterministic transcript archive.

### Milestone 5 — Bitcoin interface

- share/card opening functions;
- Taproot/script templates or transaction-graph hooks;
- regtest vectors;
- showdown and community-card reveal API.

### Milestone 6 — hardening

- fuzzing;
- benchmarks;
- cross-platform test vectors;
- dependency pinning;
- independent audit.

---

## 31. Final protocol result

A successful execution produces exactly the desired Bitcoin-facing object:

```text
Alice: h[A,0], ..., h[A,8]
Bob:   h[B,0], ..., h[B,8]
```

with secret preimages:

```text
x[A,0], ..., x[A,8]
x[B,0], ..., x[B,8]
```

such that:

```text
SHA256(x[P,i]) = h[P,i]
16 <= len(x[P,i]) <= 67
card[i] = (len(x[A,i]) + len(x[B,i]) - 32) mod 52
card[0], ..., card[8] are pairwise distinct
```

No complete card is revealed by the setup. Later, any card can be selectively learned or publicly proven by revealing the appropriate pair of SHA-256 preimages.
