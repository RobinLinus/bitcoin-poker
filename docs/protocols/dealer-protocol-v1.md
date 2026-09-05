# DLOG52-DEAL-v1
## Agent implementation specification: algebraic two-party dealing with Bitcoin signature openings

**Status:** Proposed research implementation profile. Not an audited protocol, a security proof, or authorization to use real funds.

**Protocol identifier:** `DLOG52-DEAL-v1`  
**Wire version:** `1`, within this new protocol namespace  
**Document revision:** `draft-1`, 2026-09-04  
**Implementation target:** Rust core, independent public certificate verifier, browser/WebAssembly client, Bitcoin Core regtest demonstration.

## 0. Instructions to the implementation agent

Implement the protocol defined here, not the old SHA-256/preimage-length interface. Deliver a reproducible workspace, executable tests, deterministic interoperability vectors, a two-client browser demonstration, and measured performance. Do not replace specified proof relations with placeholders or with an unspecified “range-proof library.” Do not infer that a valid setup certificate is permission to fund a game.

The baseline deliberately uses **no Bulletproof, no R1CS, no secret SHA-256 circuit, no garbled circuit, and no trusted setup**. Ordinary hashing remains in transcripts, commitments to messages, generator derivation, and Bitcoin signing.

Implement the exact proof profile below before considering proof compression or alternate range proofs. The bitwise range construction and the transaction demonstration are explicit choices made for this new specification; they were not present in the supplied BP52 document. Treat their composition as subject to independent review.

Do not silently improvise around an inconsistency. Record a proposed specification amendment, a minimal failing test, and its security impact. Work may continue on independent components, but affected components must fail closed rather than silently weaken the relation.

## 1. Source basis, changes, and limits

### 1.1 Inherited structure

The supplied `BP52-DEAL-v1` document is the source for additive contributions modulo 52, the nine-slot order, Pedersen/ElGamal representation links, the 108 encrypted difference tests, two independent scaling rounds, simultaneous decryption commitments, selective reveals, and public off-chain verification. Its relevant sections are 4, 6, 12–18, and 28. [S0]

### 1.2 New decisions

This specification replaces Ristretto255 with secp256k1; removes preimages and their hashes; defines an exact `Range52-BitOR-v1` proof; derives card-specific Bitcoin signing keys from commitment sums; defines a new wire format and frozen-stage transcripts; and adds a narrowly scoped regtest transaction profile.

It also adds explicit checks for exceptional public key/ciphertext degeneracies and distinguishes attributable signed faults from network timeouts. These are changes, not claims about what BP52 already specified.

### 1.3 Explicit source erratum

Retain the source's formula `card_id = 4 * rank_index + suit_index`, not its inconsistent examples. Under that formula, Jack of Clubs is **36**, and Ace of Hearts is **50**. The source's example values 9 and 38 do not match its formula. This implementation MUST use the formula and the corrected examples. [S0 §4.3]

### 1.4 Scope boundary

This specification covers setup, verification, share delivery, derived signing keys, and a single-slot Bitcoin gate demonstration. It does **not** define a complete poker settlement, refund, timeout, penalty, fair-exchange, or multi-card hand-evaluation transaction graph. It does not establish guaranteed output delivery or fair treatment of aborts.

An ordinary Schnorr signature does not release its private scalar. Therefore this construction MUST NOT be substituted for a hashlock when another transaction depends on that hash preimage becoming public. A surrounding contract requires a separate written specification and audit.

## 2. Security model and intended properties

There are two authenticated parties, A and B; at most one is malicious. The network may observe, delay, duplicate, reorder, modify, or drop traffic. Both parties possess BIP340 identity keys. The application must provide confidential, authenticated delivery for private openings, in addition to message authentication.

Intended properties, subject to review of the full composition:

- Every accepted commitment contains a contribution in `0..51`, and the linked ciphertext encrypts that same contribution.
- The nine resulting card identifiers are distinct.
- Before an authorized opening, neither party learns the peer contribution or a complete card, apart from permitted leakage and its own inputs.
- Possession of the valid openings for a slot supplies a signing key for the correct raw-sum candidate. Deriving another candidate's scalar would contradict the intended discrete-log binding argument; signature-based enforcement also relies on BIP340 unforgeability in this composed setting.
- An independent verifier can check a complete public setup certificate without any secret witnesses.

Assumptions include discrete-log hardness, the unknown discrete-log relationship of the two generators, DDH for the inherited ElGamal uniqueness privacy argument, and random-oracle assumptions for Fiat–Shamir. “Dlog-based” does not mean every property follows from the discrete-log assumption alone. [S0 §16; S2–S4]

Accepted attempts disclose validity, public protocol objects, and completion timing. Collision attempts disclose a 108-bit zero-test pattern, identifying colliding slot pairs and raw-sum offsets. Exceptional rejected attempts may also disclose algebraic relations among their discarded inputs. No rejected input may be reused.

The uniform-deal statement applies with independently uniform honest contributions and acceptance conditioned on the uniqueness predicate, up to negligible cryptographic/exceptional events. It is not a blanket fairness guarantee against selective abort, malicious randomness in both clients, compromised endpoints, or later selective completion of games.

## 3. Fixed constants and card layout

```text
DECK_SIZE             = 52
N_SLOTS               = 9
MAX_CONTRIBUTION       = 51
MAX_RAW_SUM            = 102
RAW_SUM_CANDIDATES     = 103
ZERO_TEST_COUNT        = 108
RANGE_BITS             = 6
RANGE_SIDES            = 2
RANGE_BIT_RECORDS      = 9 * 2 * 6 = 108 per player
POINT_BYTES           = 33
SCALAR_BYTES          = 32
MAX_ENVELOPE_BYTES    = 32768
MAX_SETUP_CERT_BYTES  = 131072
```

No caller-supplied deck size, generator, slot order, proof profile, or encoding is accepted under this protocol identifier.

For slot `i`:

```text
v[A,i], v[B,i] in 0..51
s[i] = v[A,i] + v[B,i]           # ordinary integer, 0..102
card[i] = s[i] mod 52
```

Card mapping:

```text
rank_index = card_id / 4        # floor division
suit_index = card_id % 4
ranks = [2,3,4,5,6,7,8,9,10,J,Q,K,A]
suits = [Clubs,Diamonds,Hearts,Spades]
```

Slot order:

```text
0 Alice hole 1     1 Bob hole 1
2 Alice hole 2     3 Bob hole 2
4 flop 1          5 flop 2          6 flop 3
7 turn            8 river
```

## 4. Group, generators, and scalar conventions

### 4.1 Group

All off-chain algebra uses full, sign-aware secp256k1 points. Let `O` be the identity, `G` the standard generator, and `q` the prime group order:

```text
q = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

Scalar arithmetic is modulo `q`. Card arithmetic is integer arithmetic modulo 52. They are different domains. Negative public offsets are mapped into the scalar field explicitly, never by an accidental unsigned cast. Standard curve and BIP340 definitions are imported from the primary specifications. [S1, S2]

### 4.2 Message generator

Define `M` by RFC 9380 `hash_to_curve`, using exactly:

```text
suite = secp256k1_XMD:SHA-256_SSWU_RO_
DST   = raw_ascii("DLOG52-DEAL-v1/message-generator/secp256k1_XMD:SHA-256_SSWU_RO_")
msg   = raw_ascii("DLOG52-DEAL-v1/message-generator")
```

Do not append a NUL or newline. Do not substitute the `NU` suite, try-and-increment, or `hash_to_scalar(msg) * G`. Verify `M != O`, `M != G`, and `M != -G`. An unexpected failure is a local parameter error, not permission to negotiate a new generator. Use RFC 9380 test vectors before emitting the protocol's generator vector. [S1 §8.7, §J.8.1]

Generate and commit `M`'s compressed encoding, the parameter manifest bytes, and `params_id` to the test-vector directory. Derive them independently with a second implementation before declaring interoperability complete. No invented hexadecimal constants are supplied by this draft.

### 4.3 Randomness

`RandomScalar()` samples a 32-byte CSPRNG string, interprets it as big-endian, and rejects integers `>= q`; zero is permitted. `RandomNonzeroScalar()` additionally rejects zero. Sample contribution bytes until `<208`, then reduce modulo 52. Never use `Math.random`, timestamps, a browser fingerprint, or public session data as secret entropy.

Use fresh independent randomness for every slot, proof, test, and attempt unless a single shared nonce is explicitly specified within one same-secret DLEQ proof. A reused proof nonce under different challenges can disclose the witness.

## 5. Canonical codec and parameter identity

### 5.1 Primitive encoding

```text
U8:        one byte
U16/U32:   unsigned little-endian
Scalar32:  canonical 32-byte BIG-ENDIAN integer, strictly less than q
Point33:   02||x32 or 03||x32 for a finite SEC1 compressed point;
           00 repeated 33 times for O, only where semantically allowed
Hash32:    32 raw bytes
XOnly32:   32-byte BIP340 public key, validated using lift_x
Sig64:     64-byte BIP340 signature
Bytes:     U32(byte_length) || exactly those bytes
AsciiString: Bytes encoding of the exact ASCII bytes
Array[N]:  N elements in the specified order, without a count
```

`raw_ascii(s)` means the unprefixed ASCII bytes of a literal. `AsciiString(s)` means `Bytes(raw_ascii(s))`, including the four-byte length. Use the former for hash tags and hash-to-curve inputs, and the latter only where the codec explicitly calls for it.

The all-zero 33-byte identity is a **protocol-specific extension**, not a standard Bitcoin public-key encoding. Only the group codec handles it. Reject every other prefix-zero representation, uncompressed/hybrid encodings, failed curve decompression, noncanonical scalars, incorrect lengths, integer overflows, unknown enum values, and trailing data. Do not reduce received scalars modulo `q`.

All protocol structs below encode fields in listed order. Fixed proof arrays have no length prefixes. JSON and Serde are allowed for human-readable test fixtures, never as the wire format.

### 5.2 Parameter manifest

Encode this ordered struct:

```text
AsciiString("DLOG52-DEAL-v1")
U16(1)
AsciiString("secp256k1")
AsciiString(suite from §4.2)
AsciiString(DST from §4.2)
AsciiString(msg from §4.2)
Point33(G), Point33(M)
U8(52), U8(9), U8(6), U16(108), U8(102)
U16(1) # Range52-BitOR profile
U16(1) # codec profile
U16(1) # Fiat–Shamir profile
U16(1) # state-machine profile
U16(1) # catalogue profile
U16(1) # card-mapping profile
U16(1) # slot-mapping profile
```

Define `params_id = TH("DLOG52/params/v1", manifest_bytes)`.

These profile IDs refer to the exact definitions in this document. A relation, encoding, transcript, or ordering change requires a new compatible specification/version, not silent negotiation. Library revisions live in a separate reproducible-build manifest; interchangeable backends must produce the same mathematical objects and wire bytes.

## 6. Hash functions, game identity, and proof contexts

### 6.1 Tagged hash

```text
TH(tag, data) = SHA256(SHA256(raw_ascii(tag)) || SHA256(raw_ascii(tag)) || data)
```

No implicit length prefixes are added by `TH`. Callers use the specified canonical encoding.

Define `HScalar(label, body)` by trying counter values `0,1,...`:

```text
digest = TH("DLOG52/challenge/v1", AsciiString(label) || Bytes(body) || U32(counter))
e = big_endian_integer(digest)
accept the FIRST value with 0 < e < q
```

Counter exhaustion is a fatal local error. Counters are not sent. A verifier repeats the deterministic process. This uses exact rejection sampling, not noncanonical scalar reduction.

### 6.2 Game configuration

```rust
struct GameConfig {
    network_genesis: Hash32,
    session_anchor: Hash32,
    identity_a: XOnly32,
    identity_b: XOnly32,
    session_nonce: Hash32,
    rules_hash: Hash32,
}
```

The genesis hash uses the selected Bitcoin library's consensus-serialized hash bytes, not display-hex text. Supply vectors distinguishing display and wire byte order. `session_anchor` is an opaque 32-byte application session identifier agreed before the deal, not a funding transaction ID that depends on this deal's future output scripts. This avoids a circular game-ID dependency.

Identity A is the lexicographically smaller x-only identity key; reject equal or invalid keys. Both parties must agree to the complete configuration. The session nonce is fresh for the application session; it is not a secret or a source of card entropy.

```text
game_id = TH("DLOG52/game/v1", params_id || Encode(GameConfig))
```

`rules_hash` identifies the external game/reveal policy. For the demonstration, use a separately documented test policy. It does not turn an unspecified settlement into a specified one.

### 6.3 Proof context

```text
ProofContext =
    params_id || game_id || U32(attempt) || U16(proof_stage) ||
    U8(prover_role) || frozen_anchor
```

A context is constructed by the state machine, never accepted from an arbitrary prover callback. For key proofs, the anchor is the transcript before KEY_COMMIT. For bundle proofs it is the transcript before BUNDLE_COMMIT. For decryption proofs it is the transcript before DECRYPT_COMMIT. Opening a committed payload does not change the proof's frozen context.

Define `JointPublic = PK_A || PK_B || Y`, with all three encoded as `Point33`.

Exact Fiat–Shamir labels are:

```text
DLOG52/key-pop/v1
DLOG52/range52-bitor/v1
DLOG52/encryption-link/v1
DLOG52/scale-first/v1
DLOG52/scale-second/v1
DLOG52/partial-decrypt/v1
```

## 7. Threshold key setup

Each party samples `sk_P = RandomNonzeroScalar()` and computes `PK_P = sk_P * G`. These keys are per-attempt secrets and MUST NOT be derived from identity or wallet keys.

Schnorr proof of possession:

```text
w = RandomNonzeroScalar()
T = w*G
e = HScalar("DLOG52/key-pop/v1", ProofContext || PK_P || T)
z = w + e*sk_P
verify: z*G == T + e*PK_P
```

Proof serialization is `(T: Point33, z: Scalar32)`. Reject identity public keys and identity `T` for this proof. Commit to the complete key-open body before revealing it, as specified in §15.

After both proofs verify, compute `Y = PK_A + PK_B`. If `Y == O`, end the attempt as `DegenerateRetry(JointKeyIdentity)`. Do not assign blame solely from that combined condition.

## 8. Contributions, commitments, and ElGamal

For each party and slot:

```text
v       = uniform integer in 0..51
gamma   = RandomScalar()
V       = v*M + gamma*G
r       = RandomNonzeroScalar()
R       = r*G
S       = v*M + r*Y
C       = (R,S)
```

Resample local `gamma` if `V == O`. Store `(v,gamma)` as the long-lived opening secret. Store `r` only for setup. Do not publish `gamma*G`: it would permit enumeration of `v`.

```rust
struct Ciphertext { r: Point33, s: Point33 }
struct SlotPublic { commitment: Point33, ciphertext: Ciphertext }
```

Ciphertext operations are componentwise. For a signed public integer `t`, `Enc(t;0) = (O, [t]_q*M)`. Never decrypt an original contribution ciphertext or an unblinded card sum. [S0 §6]

## 9. Exact range proof: Range52-BitOR-v1

### 9.1 Statement

For the nine commitments in one player's bundle, prove knowledge of openings with each `v_i` in `0..51`. The proof MUST refer to the exact `V_i` also used in the encryption link and candidate-key derivation.

This is a specified construction using Pedersen bit commitments and Schnorr OR proofs. It uses the classical OR/AND proof-composition idea, but the exact profile and its integration here require review; the cited work does not certify this implementation. [S4]

### 9.2 Commit to bits of the value and its complement

For every slot `i`, define two six-bit integers:

```text
u[i,0] = v[i]
u[i,1] = 51-v[i]
target[i,0] = V[i]
target[i,1] = 51*M - V[i]
opening_blinder[i,0] = gamma[i]
opening_blinder[i,1] = -gamma[i]
```

For each side `h` and bit index `j=0..5`, let `b[i,h,j]` be the bit of `u[i,h]`. Sample five blinders `rho[0..4]` uniformly. Set:

```text
rho[5] = (opening_blinder - sum(j=0..4, 2^j * rho[j])) / 32 mod q
B[i,h,j] = b[i,h,j]*M + rho[i,h,j]*G
```

The verifier checks, as point equalities:

```text
sum(j=0..5, 2^j * B[i,0,j]) == V[i]
sum(j=0..5, 2^j * B[i,1,j]) == 51*M - V[i]
```

The value and complement both lie in `0..63` if all bit proofs hold. Computational binding to the same commitment, with `q > 126`, establishes the intended `0..51` interval. A bare six-bit proof of `v` alone is insufficient.

### 9.3 Two-branch OR proof for each bit

For each bit commitment `B`, define:

```text
P0 = B
P1 = B-M
```

The prover knows the discrete logarithm `rho` of `P_b` to base `G`, for bit `b`.

For every one of the 108 bit records:

```text
w             = RandomScalar()
c_fake,z_fake = independent RandomScalar() values
T_real        = w*G
T_fake        = z_fake*G - c_fake*P_(1-b)
place T_real and T_fake in branch order T0,T1
```

Use constant-time selection; do not expose which branch is real through array accesses, branches, timing, or log messages.

Canonical bit order is `(slot i=0..8, side h=0..1, bit j=0..5)`. Define:

```text
BundleStatement = ProofContext || JointPublic || SlotPublic[9]
RangeStatement = BundleStatement || B[108]
e = HScalar("DLOG52/range52-bitor/v1", RangeStatement || (T0,T1)[108])
```

All records share this one challenge. For each record:

```text
c_real = e - c_fake
z_real = w + c_real*rho
```

This is an AND of explicit two-branch OR relations, not randomized equation batching. No relation may be skipped.

### 9.4 Serialization and verification

```rust
struct BitOrResponse { c0: Scalar32, z0: Scalar32, z1: Scalar32 }
struct Range52Proof {
    bit_commitments: [Point33; 108],
    challenge: Scalar32,                 // e, MUST be nonzero
    responses: [BitOrResponse; 108],
}
```

For each record the verifier computes:

```text
c1 = e-c0
T0 = z0*G - c0*P0
T1 = z1*G - c1*P1
```

Then it recomputes `e` from the full statement and all reconstructed `T` values, checks challenge equality, and checks both weighted-sum equations for every slot. Zero branch challenges/responses and identity bit/temporary points are permitted; the global challenge must be nonzero.

Proof length is exactly:

```text
108*33 + 32 + 108*3*32 = 13,964 bytes per player
```

The proof shape, message length, and allocation pattern are independent of all contributions. Zeroize all bit blinders and OR proof nonces after use.

## 10. Encryption-link proof

For all nine slots, prove knowledge of `(v,gamma,r)` satisfying:

```text
V = v*M + gamma*G
R = r*G
S = v*M + r*Y
```

For each slot sample independent uniform `a_v,a_gamma,a_r`, and compute:

```text
T_V = a_v*M + a_gamma*G
T_R = a_r*G
T_S = a_v*M + a_r*Y
```

Define:

```text
range_hash = TH("DLOG52/range-proof-bytes/v1", Encode(Range52Proof))
e = HScalar("DLOG52/encryption-link/v1",
            BundleStatement || range_hash || (T_V,T_R,T_S)[9])
```

Responses per slot:

```text
z_v = a_v + e*v
z_gamma = a_gamma + e*gamma
z_r = a_r + e*r
```

Verify every equation individually:

```text
z_v*M + z_gamma*G == T_V + e*V
z_r*G             == T_R + e*R
z_v*M + z_r*Y     == T_S + e*S
```

Encode nine records `(T_V,T_R,T_S,z_v,z_gamma,z_r)`, 1,755 bytes total. Temporary points may be identity. Original `V` and `R` may not. This retains the source's generalized Schnorr relation in the new group. [S0 §12]

## 11. Player bundles and public consistency checks

```rust
struct PlayerBundle {
    role: U8,
    slots: [SlotPublic; 9],
    range_proof: Range52Proof,
    link_proof: [LinkProofRecord; 9],
}
```

Length is exactly `1 + 9*99 + 13964 + 1755 = 16,611` bytes.

After committed openings, verify envelope authentication and context, commitment openings, fixed lengths, canonical points/scalars, expected role, required nonidentity conditions, the complete range proof, and the complete link proof. No uniqueness message may be processed against an unverified bundle.

Once both bundles verify, derive all subsequent objects locally. Peer-supplied candidate tables, sums, differences, bitmaps, or catalogue hashes are never trusted without recomputation.

## 12. Candidate keys and exceptional-case screening

### 12.1 Derivation

For each slot:

```text
W_i = V_Ai + V_Bi
K_i,0 = W_i
K_i,t+1 = K_i,t - M             # t=0..101
```

Equivalently, `K_i,t = W_i - t*M` for `t=0..102`.

For valid openings define `kappa_i = gamma_Ai + gamma_Bi mod q`. Then:

```text
K_i,s_i = kappa_i*G
```

The key associated with a wrong candidate contains `(s_i-t)*M`. The unknown discrete-log relationship of `M` to `G` is essential. Do not substitute known scalar multiples of `G` for `M`.

### 12.2 Required screening

Before accepting an attempt:

- All 18 original commitments must be distinct up to sign (distinct x coordinates), and nonidentity.
- All 927 candidate keys must be nonidentity and have globally distinct x-only encodings, including across different slots.
- No candidate x-only key may equal either identity key.
- Every original ciphertext `R`, every summed ciphertext `R`, and every pair-difference `R` must be nonidentity.

The original `R`/`V` and key-proof conditions are per-sender validity rules. A failed condition involving both parties' otherwise valid data is `DegenerateRetry`, not automatic proof of cheating. Resample the entire attempt. These screening events should be negligible with honest randomness; unexpected frequency is an operational warning, not license to reuse inputs.

The ciphertext screen avoids accepting cases where zero encryption randomness makes a small plaintext or difference directly enumerable. Such a rejected case can leak data from that discarded attempt; this is included in the exceptional leakage model.

Do not apply a blanket “no identity anywhere” rule. Public-constant ciphertexts, intermediate group computations, bit commitments, and some proof temporary points legitimately support the identity encoding.

### 12.3 Catalogue hash

In increasing `(slot i, candidate t)` order:

```text
entry = U8(i) || U8(t) || U8(t mod 52) || Point33(K_i,t)
catalogue_hash = TH("DLOG52/catalogue/v1",
    params_id || game_id || U32(attempt) || entry[927])
```

The full points bind signs; conversion to x-only occurs only at the signature boundary. The catalogue is derived data and is not transmitted in setup messages.

## 13. Uniqueness test

### 13.1 Derive sums and differences

```text
Sum[i] = C[A,i] + C[B,i]
```

For every `i<j` and offset `t` in `[-52,0,+52]`:

```text
D[i,j,t] = Sum[i] - Sum[j] - (O,[t]_q*M)
```

Canonical order is increasing `i`, then `j`, then the listed offset order. There are exactly 108 tests. `D` encrypts `s_i-s_j-t`, whose integer value lies in `[-154,154]`.

The cards collide exactly when at least one test plaintext is zero. No modulo operation is needed inside the encrypted computation. [S0 §15]

### 13.2 First and second blinding

Select the first role:

```text
first_role = TH("DLOG52/first-blinder/v1", game_id || U32(attempt))[0] & 1
```

Role 0 is A. The first party samples an independent nonzero `alpha[k]` for every test and publishes:

```text
Q[k] = alpha[k]*G
E1[k] = alpha[k]*D[k]
```

The second party independently samples nonzero `beta[k]` and publishes:

```text
Q2[k] = beta[k]*G
E2[k] = beta[k]*E1[k]
```

Using one scaling factor for multiple tests is forbidden: it can preserve useful relations among outputs. Both components of every ciphertext must be scaled and proven.

### 13.3 Exact scale proof

For input ciphertexts `U[k]`, outputs `E[k]`, scalar witnesses `a[k]`, and `Q[k]=a[k]*G`, sample fresh independent `w[k]` and compute:

```text
T_G[k] = w[k]*G
T_R[k] = w[k]*U[k].R
T_S[k] = w[k]*U[k].S
```

Use the first/second label and that round's frozen stage context:

```text
body = ProofContext || JointPublic ||
       (U[k],Q[k],E[k])[108] || (T_G[k],T_R[k],T_S[k])[108]
e = HScalar(label, body)
z[k] = w[k] + e*a[k]
```

For every test verify:

```text
z[k]*G      == T_G[k] + e*Q[k]
z[k]*U[k].R == T_R[k] + e*E[k].R
z[k]*U[k].S == T_S[k] + e*E[k].S
```

Reject identity `Q[k]`. Do not multiply unrelated verification equations together or replace them with an unreviewed random batch.

Payload serialization is 108 records `(Q,E.R,E.S,T_G,T_R,T_S,z)`, exactly 24,840 bytes. The verifier's inputs `U` come from local derivation or the verified prior round, not the message.

### 13.4 Partial decryptions

Each party computes:

```text
Z[P,k] = sk[P]*E2[k].R
```

A single same-secret DLEQ proof covers the batch. Sample one fresh `w`:

```text
T_G = w*G
T[k] = w*E2[k].R
body = ProofContext || JointPublic || E2[108] || Z[P,0..107] || T_G || T[108]
e = HScalar("DLOG52/partial-decrypt/v1", body)
z = w + e*sk[P]
```

Verify:

```text
z*G        == T_G + e*PK[P]
z*E2[k].R == T[k] + e*Z[P,k]      # for all k
```

Encode `(Z[108],T_G,T[108],z)`, exactly 7,193 bytes. The party commits to this entire body, including its proof, before either party opens decryption messages.

### 13.5 Result

After both decryption commitments open and all proofs pass:

```text
Plain[k] = E2[k].S - Z[A,k] - Z[B,k]
collision[k] = (Plain[k] == O)
```

Any true bit yields `CollisionRetry`. All false bits yield provisional setup success. Acceptance still requires the complete checks and signatures below. An invalid proof is not a collision.

## 14. Authenticated messages and stage transcripts

### 14.1 Envelope

```rust
struct Envelope {
    version: U16,
    params_id: Hash32,
    game_id: Hash32,
    attempt: U32,
    stage: U16,
    sender_role: U8,
    sender_sequence: U32,
    previous_stage_root: Hash32,
    payload_type: U16,
    payload: Bytes,
    signature: Sig64,
}
```

Sign `TH("DLOG52/envelope/v1", Encode(all fields except signature))` with the sender's identity key. Envelope overhead is 179 bytes, including the payload's four-byte length and the signature.

Sequence numbers start at zero for each role in each attempt and increase by one per new emitted envelope. Every stage has one permitted payload type and sender set. Unknown or future stages, stale contexts, unexpected senders, and oversized bodies must not advance state.

### 14.2 Frozen stage roots

```text
T0 = TH("DLOG52/attempt-start/v1",
        params_id || game_id || U32(attempt) || previous_attempt_root)
```

For attempt zero, `previous_attempt_root` is all zero. A retry uses the last completed stage root of the discarded attempt. Include this predecessor as public certificate metadata; verifying an accepted attempt does not certify the entire past retry history.

All envelopes in a given stage bind to the same pre-stage root. Advance only after every required envelope and semantic check for the stage succeeds:

```text
T_stage = TH("DLOG52/stage/v1",
    T_previous || U16(stage) || U8(number_of_senders) ||
    Bytes(envelope_A_if_present) || Bytes(envelope_B_if_present))
```

Omit absent roles entirely; present envelopes are always ordered A then B, regardless of network arrival order. `Bytes(envelope)` is the length-prefixed complete signed encoding.

This barrier rule prevents different proof/transcript contexts arising from simultaneous message arrival order.

### 14.3 Retransmission and persistence

A byte-identical replay of an already processed envelope may be acknowledged by transport but MUST NOT be processed twice or extend the transcript. Two differently encoded, correctly signed envelopes for the same `(game,attempt,stage,role,sequence)` are equivocation evidence. An invalid signature is not evidence against its claimed sender.

Persist signed outgoing bytes before handing them to transport. Retransmit those same bytes. Do not regenerate proof commitments or nonces after seeing a challenge/context change. Following uncertain crash recovery, abandon the attempt rather than reconstruct a partially used proof state unsafely. Maintain durable attempt/sequence state against rollback within the supported threat model.

## 15. State machine and commit/open stages

The stage numbers and payload-type codes are identical:

| Stage | Name | Required senders | Payload |
|---|---|---|---|
| 1 | KEY_COMMIT | A, B | Hash32 commitment |
| 2 | KEY_OPEN | A, B | nonce32, PK, key proof |
| 3 | BUNDLE_COMMIT | A, B | Hash32 commitment |
| 4 | BUNDLE_OPEN | A, B | nonce32, PlayerBundle |
| 5 | FIRST_SCALE | selected first role | ScalePayload |
| 6 | SECOND_SCALE | other role | ScalePayload |
| 7 | DECRYPT_COMMIT | A, B | Hash32 commitment |
| 8 | DECRYPT_OPEN | A, B | nonce32, DecryptionBody |
| 9 | ACCEPT_SIGNATURE | A, B | accepted_body_hash32, detached_sig64 |

For a commit stage `j` with opening payload type `j+1`:

```text
commitment = TH("DLOG52/commit/v1",
    ProofContext(j,role,T_before_commit) || U16(j+1) || nonce32 || Encode(open_body))
```

`open_body` excludes the nonce, but includes the entire proof-bearing key/bundle/decryption body. Nonces are independent random 32-byte values. Key, bundle, and decryption proofs are generated against their frozen pre-commit contexts.

An honest party may send an opening only after recording both authenticated commitments. Merely scheduling the local commitment for eventual transmission is insufficient. The state machine must know the committed bytes are durably fixed.

Finalize `T2` after both key openings and proofs verify, then test joint-key degeneracy. Finalize `T4` after both bundle openings and proofs verify, then perform catalogue/ciphertext screening and derive tests before stage 5. Finalize `T8` after both decryption openings and proofs verify, then compute the collision bitmap. A valid proof-bearing stage is complete even when its subsequent combined-data screen or zero-test result causes a retry. This fixes the predecessor root used by the next attempt. A failed message/proof does not complete its stage. Retry or fault ends this attempt; no stage 9 is emitted for that attempt.

## 16. Accepted deal and public certificate

```rust
struct AcceptedDealBody {
    version: U16,
    params_id: Hash32,
    game_id: Hash32,
    attempt: U32,
    commitments_a: [Point33; 9],
    commitments_b: [Point33; 9],
    catalogue_hash: Hash32,
    verification_root: Hash32,         // T8, BEFORE acceptance signatures
}
struct AcceptedDeal {
    body: AcceptedDealBody,
    signature_a: Sig64,
    signature_b: Sig64,
}
```

Body size is 728 bytes; accepted descriptor size is 856 bytes.

```text
accepted_body_hash = TH("DLOG52/accepted/v1", Encode(AcceptedDealBody))
deal_id = accepted_body_hash
```

Both identities sign this same hash. Stage 9 carries the hash and each detached signature inside its authenticated envelope. No signature is included in the body being signed, and `verification_root` is `T8`, not a root including stage 9. This avoids a signature/root cycle.

The public certificate wire format is:

```rust
struct SetupCertificate {
    certificate_version: U16,          // exactly 1
    game_config: GameConfig,           // 192 bytes
    previous_attempt_root: Hash32,
    envelopes: [Bytes; 16],            // complete signed Envelope encodings
    accepted_deal: AcceptedDeal,
}
```

The 16 envelopes are in canonical stage/role order. Version/parameters identify local fixed manifests; do not accept arbitrary parameter bytes from the certificate. With the specified payloads, a successful certificate is exactly 102,070 bytes, including the 16 nested length prefixes. The certificate decoder must still enforce the 131,072-byte input cap before allocation.

Its verifier must reconstruct the full successful attempt, verify all message commitments/proofs/signatures, reproduce `T8`, recompute the catalogue, and require exact equality between descriptor commitments and verified bundle commitments. The two detached signatures alone are insufficient evidence of valid setup.

`VerifiedAcceptedDeal` should be a sealed type only this complete verifier and the equivalent live state machine can construct.

## 17. Retry, failure, and attribution

```rust
enum AttemptOutcome {
    Accepted(VerifiedAcceptedDeal),
    CollisionRetry { collision_bitmap: [bool; 108] },
    DegenerateRetry { reason: DegenerateReason },
    PeerFault { evidence: SignedFaultEvidence },
    TransportFailure,
    LocalFailure,
    RetryLimitExceeded,
}
```

On either retry: increment the checked attempt counter, erase all attempt secrets, and generate fresh threshold keys, contributions, commitment blinders, encryption randomness, proof nonces, scale factors, and commit nonces. Do not retain “good” slots from a rejected attempt. Do not change contributions within an already committed attempt.

A local resource/retry limit may stop the session; it must not accept duplicate cards. Normal collision is not cheating. Do not infer peer fault from a dropped connection, missing message, invalid transport authentication, or an unverified asserted sender. Timeouts are handled by the outer application's evidence rules, which are outside this specification.

Suggested error codes include invalid encoding/signature/context, commit mismatch, invalid key/range/link/scale/decryption proof, zero scale, unexpected identity, duplicate catalogue key, authorization-key overlap, missing stage, equivocation, resource limit, and storage/RNG failure. Keep local failures distinct from attributable signed peer messages.

## 18. Share openings and private delivery

```rust
struct ShareOpening {
    value: U8,            // 0..51
    blinding: Scalar32,
}
```

Core predicate:

```text
VerifyShare(V,(v,gamma)):
    require v <= 51
    require canonical gamma
    require V == v*M + gamma*G
    return v
```

Card predicate verifies both shares against the accepted slot commitments and returns the ordinary integer sum and `sum % 52`. A claimed card is valid exactly when it matches that result.

For slots 0 and 2, B privately delivers only B's opening to A. For slots 1 and 3, A privately delivers only A's opening to B. Community/share-showdown releases follow the externally authorized game stage. This retains the source's slot-level selective-delivery pattern with new opening objects. [S0 §8.3]

The separate opening-message profile is:

```rust
struct ShareRevealBody {
    version: U16,                     // exactly 1
    params_id: Hash32,
    game_id: Hash32,
    deal_id: Hash32,
    sender_role: U8,                  // 0 or 1; must own this share
    recipient: U8,                    // 0=A, 1=B, 255=public
    slot: U8,                         // 0..8
    reveal_stage: U8,                 // 0=hole, 1=flop, 2=turn, 3=river, 4=showdown
    opening: ShareOpening,
}
struct SignedShareReveal { body: ShareRevealBody, signature: Sig64 }
```

Sign `TH("DLOG52/share-reveal/v1", Encode(body))`. The signed message is exactly 199 bytes. It is not a setup envelope and does not extend `T8`. An identical verified reveal is idempotent, not a second game-state transition. Different signed openings for the same committed share are retained as evidence and rejected unless mathematically identical.

Stage 0 applies only to the owner's hole slots and must privately deliver the opponent's share to that owner. Stages 1, 2, and 3 apply only to slots 4..6, 7, and 8 respectively and may release the sender's share publicly. Stage 4 applies only to hole slots and requires the application's showdown authorization. A stage label in a received message is not authority to advance the game.

Send private messages through an authenticated **end-to-end confidential** channel to the peer. TLS to a relay that can read the plaintext is not sufficient. The host must supply a reviewed secure-channel implementation with verified peer-identity binding; a new ad hoc encryption handshake is outside this protocol. Private reveal bodies MUST NOT be appended to the public setup certificate, public telemetry, browser logs, or a public transcript mirror.

The host must provide an explicit reveal-authorization object derived from its agreed game state. A peer's unsolicited request is not sufficient authorization. The demonstration uses explicit user approval and the documented test policy; do not implement automatic production betting rules by inference.

At public showdown, the owner may publish both already verified openings for its authorized slot, including the opening previously received privately. A verifier checks both against the accepted commitments; it does not require the original private sender to change that message's recipient field or sign again. Do not publish openings for any other slot as a side effect.

A blinding scalar alone effectively reveals a contribution by enumeration. Treat `gamma`, `gamma*G`, and `(v,gamma)` as opening-sensitive data. Verified peer openings become as sensitive as local openings until public release is authorized.

## 19. Deriving and using the Bitcoin signing scalar

Given both verified openings for slot `i`:

```text
s = v_A + v_B
kappa = gamma_A + gamma_B mod q
require kappa != 0
require kappa*G == K[i,s]
```

Only derive this capability from a verified accepted descriptor and verified openings. A `CardSigningKey` should be non-exportable by default at the application API boundary and zeroize on drop.

BIP340 uses x-only, even-y public keys. Either pass the original nonzero scalar to a conforming keypair/signing API that handles parity, or explicitly use `kappa` when `kappa*G` has even y and `q-kappa` otherwise. Verify the final x-only key equals `x(K[i,s])`. Do not apply a Taproot output-key tweak to this **embedded tapscript key**. It is distinct from the output's internal/tweaked key. [S2]

Use the library's standard BIP340 nonce/challenge algorithm with fresh auxiliary randomness where supported. Do not implement a simplified related-key Schnorr signature or share proof nonces with signature nonces. Public-key prefixing in BIP340 matters for these algebraically related candidates. [S2]

An opening gives a key for a card claim, not general payment authorization. Once the openings are public, anyone can derive the card key. A transaction must separately constrain who may authorize a spend and what that spend pays.

## 20. Bitcoin integration profile: regtest single-slot gate

### 20.1 Purpose and exclusions

Implement this exact **demonstration profile** to test the commitment-to-signature bridge. It produces nine independent regtest outputs, one per slot, each with 103 candidate leaves. It is not a complete poker contract. Do not claim that nine times 103 leaves settles an arbitrary nine-card hand or supplies refunds/penalties.

Mainnet construction/funding must be disabled in the demonstration API. The production graph interface must remain a typed, unimplemented integration boundary until its own specification is provided. No silent fallback to a card-only spend is permitted.

### 20.2 Authorizer

For the demonstration, use A's identity key as the authorizer for slots 0, 2, and 4..8; use B's identity for slots 1 and 3. This is test authorization policy, not a poker payout rule. Verify the authorizer is a valid x-only key distinct from every candidate key.

### 20.3 Exact leaf template

For slot `i` and candidate raw sum `t`, build:

```text
PUSH32(xonly(K[i,t])) OP_CHECKSIGVERIFY
PUSH32(authorizer[i]) OP_CHECKSIG
```

`PUSH32` is the direct 32-byte push. Slot, raw sum, and card identifier remain in the manifest; the compiler must check the arithmetic and key derivation before committing the leaf. The Taproot internal key commits to the deal and slot, so the leaf does not repeat metadata as push-and-drop operations.

Witness order, bottom to top before script/control-block items:

```text
authorizer_signature
card_signature
script
control_block
```

The card signature is consumed first; the authorizer signature second. Both signatures use the actual transaction's tapscript sighash. Do not sign a generic card message and attempt to feed it to `OP_CHECKSIG`.

Only 32-byte signature public keys are allowed here. Tapscript's unknown-key-type behavior is not ordinary verification; a 33-byte compressed key must never be embedded as the signature key. The template uses leaf version `0xc0`, no `OP_CODESEPARATOR`, no annex, and no `OP_SUCCESS` opcode. [S3]

### 20.4 Canonical tree and unknown-log internal key

For each slot, order leaves by `t=0..102`. Build a balanced binary tree recursively: one element is a leaf; otherwise split into the first `floor(n/2)` leaves and the remaining leaves. Combine child hashes with the BIP341 lexicographically ordered `TapBranch` rule. Do not duplicate leaves to round to a power of two. Use standard `TapLeaf` hashing and control blocks. [S5]

Define the internal point using RFC 9380 with the same curve suite but a distinct domain:

```text
DST = raw_ascii("DLOG52-DEAL-v1/taproot-internal/secp256k1_XMD:SHA-256_SSWU_RO_")
msg = deal_id || U8(i) || authorizer[i]
N = hash_to_curve(msg,DST)
```

Reject `N==O`, `N==G`, `N==-G`, or an x-only overlap of `N` with an identity, authorizer, or candidate key; normalize it to the even-y representative before the standard Taproot tweak. Derive output keys and control blocks using BIP341; reject an invalid tweak or identity output. No client knows this internal point's discrete logarithm by construction, subject to the hash-to-curve assumption. Do not replace it with a wallet key that can bypass the script tree. [S1, S5]

### 20.5 Transaction signatures and validation

The profile uses 64-byte signatures with `SIGHASH_DEFAULT` only: no explicit trailing zero byte, `ANYONECANPAY`, `NONE`, or `SINGLE`. Use the Bitcoin library's Taproot script-spend sighash API with the complete transaction, every required prevout, amount/script data, correct input index, and correct leaf hash. Review all outputs before either signature is produced. [S5, S8]

Run the resulting spends through Bitcoin Core regtest validation. A local signature check alone is insufficient evidence that a witness or control block is correct.

The Bitcoin adapter should produce a manifest with the deal ID, profile ID, slot order, authorizer keys, internal keys, all leaf scripts, Merkle roots, output scripts, and control blocks. Both parties independently rebuild and compare it. This manifest is separate from setup acceptance: accepted commitments do not automatically attest to an arbitrary external transaction graph.

### 20.6 Disclosure semantics

The selected leaf reveals the raw sum `t`, and therefore the card. The signature does not normally reveal `kappa` or either party's blinder. Off-chain opening disclosure and on-chain card-claim verification are distinct operations.

A production graph that needs a secret to unlock another transaction must specify a compatible revelation mechanism separately. Do not silently add adaptor signatures or assume they solve the full graph without an independently reviewed construction.

## 21. Secret lifecycle and browser security

Retain each accepted `(v,gamma)` opening until the game state permits deletion and the recovery policy no longer needs it. This intentionally differs from BP52's post-acceptance erasure of commitment blinders. Retain verified private peer openings with the same protections. [S0 §20]

After both acceptance signatures are durably recorded, erase threshold key shares, ElGamal randomness, bit-proof witnesses, all Sigma nonces, and all scaling factors. Erase discarded-attempt openings immediately. A temporary derived card key is zeroized after the signing operation; deriving it again from retained openings is permitted.

Keep secrets inside a dedicated Rust/WASM worker where practical. Expose handles and explicit reveal/sign actions, not bulk secret arrays. Do not derive `Debug`, ordinary `Serialize`, `Clone`, or `Copy` on secret types without a reviewed purpose. Prevent telemetry, error messages, core dumps, and test fixtures from recording live secrets.

Use authenticated encryption for required persistent storage, with an application key-management/recovery policy. Browser memory erasure is best effort: this specification does not promise secrecy against a compromised origin, malicious extension, debugger, OS compromise, or all JIT/GC copies. A worker is an execution isolation measure, not a cryptographic trust boundary against same-origin malicious code.

Use Web Crypto-backed entropy through a correctly configured browser randomness backend. Verify entropy availability in both the target browser and worker; fail closed rather than falling back. The current `getrandom` documentation describes its web backend and feature requirements; pin the actual selected release and follow that release's build instructions. [S7]

No prover or backend server may receive card witnesses to “accelerate” setup under this two-party trust model.

## 22. Implementation architecture and API

Use stable Rust for production modules. Forbid unsafe code in the protocol, codec, proof-composition, and application crates; any upstream unsafe code must be dependency-reviewed. Candidate arithmetic backend: `k256` with the necessary arithmetic/hash-to-curve capabilities. Use `rust-bitcoin` and its secp256k1 support for Bitcoin interoperability and independent BIP340 checks. Current APIs and actual pinned versions must be validated together; do not assume compatibility from package names. [S6, S8, S9]

The implementation uses the root workspace described in [architecture](../architecture.md).
Cryptographic modules use the `dealer-*` package family; diagnostics live under
`tools/`, and the application lives under `apps/`.

Required semantic API surface (types are illustrative; preserve the validation boundaries):

```rust
fn protocol_parameters() -> &'static ProtocolParameters;
fn generate_key_open(ctx: &KeyContext, rng: &mut impl CryptoRng)
    -> Result<(KeyOpenBody, SecretKeyShare), Error>;
fn generate_player_bundle(ctx: &BundleContext, rng: &mut impl CryptoRng)
    -> Result<(PlayerBundle, SetupSecrets), Error>;
fn verify_player_bundle(ctx: &BundleContext, bundle: &PlayerBundle)
    -> Result<VerifiedBundle, Error>;
fn derive_candidate_keys(a: &VerifiedBundle, b: &VerifiedBundle)
    -> Result<VerifiedCatalogue, Error>;
fn derive_zero_tests(a: &VerifiedBundle, b: &VerifiedBundle)
    -> Result<[Ciphertext; 108], Error>;
fn create_scale_round(ctx: &ScaleContext, input: &[Ciphertext; 108],
                      rng: &mut impl CryptoRng)
    -> Result<ScalePayload, Error>;
fn verify_setup_certificate(bytes: &[u8])
    -> Result<VerifiedAcceptedDeal, Error>;
fn verify_share_opening(deal: &VerifiedAcceptedDeal, role: Role,
                        slot: Slot, opening: &ShareOpening)
    -> Result<VerifiedShareOpening, Error>;
fn derive_card_signing_key(deal: &VerifiedAcceptedDeal, slot: Slot,
                           a: &VerifiedShareOpening, b: &VerifiedShareOpening)
    -> Result<CardSigningKey, Error>;
fn build_regtest_gate(deal: &VerifiedAcceptedDeal)
    -> Result<RegtestGateManifest, Error>;
```

The agent must supply concrete compiling trait bounds appropriate to the pinned RNG/library versions. Do not expose unchecked point bytes as “verified” objects. Do not expose a generic “decrypt ciphertext” operation through the browser API.

State-machine inputs must return explicit outgoing-message, status, collision, signed-fault, local-failure, and authorized-secret-action events. Cryptographic verification is never skipped because a message came from a previously authenticated channel.

## 23. Interoperability artifacts and deterministic vectors

Commit machine-readable fixtures for parameters, codec, hashes, every proof type, complete successful attempts, collision attempts, degenerate attempts, openings, candidate keys, scripts, control blocks, and signed regtest transactions.

Each fixture must include protocol/profile IDs, all public inputs, expected bytes/hashes, expected result, and a clear `TEST ONLY` designation for any included secrets. Deterministic test RNG output must never be selected by a production runtime flag.

For each noninteractive proof, expose a test-only transcript trace: ordered public fields, their encoded bytes, challenge input, rejection counter, and final challenge. A second verifier must reproduce this without access to witnesses or private RNG state.

Vector generation is an implementation deliverable. This document does not claim to supply validated generator/proof/signature hexadecimal vectors or a completed formal security proof.

## 24. Mandatory correctness and adversarial tests

### 24.1 Algebra and encodings

Test canonical round trips and rejection of malformed scalars/points, identity sentinel misuse, wrong endianness, x-only inputs where full points are required, trailing bytes, integer overflow, and maximum-size boundaries. Test RFC hash-to-curve vectors and independent generator agreement.

Exhaust all 2,704 contribution pairs. Verify their raw sums, card IDs, and correct candidate-key equation. Verify that each computed scalar's point differs from wrong full-point candidates and, after catalogue screening, wrong x-only candidates. Test both BIP340 parity cases, including `(kappa,q-kappa)` handling.

### 24.2 Range proof

Exercise every value 0..51 in every slot, both complement boundaries, and multiple random blinders. Test invalid witnesses 52..63, negative/scalar-wrapped attempts, incorrect complement, a weighted-sum mutation, a wrong branch challenge, zero global challenge, reordered bits/sides/slots, a replaced commitment, and a truncated response.

Mutate the game, role, attempt, parameters, frozen anchor, joint key, and bundle ciphertexts; the proof must fail when its bound statement changes. Verify proof length is always 13,964 bytes. Test the constant-time branch-selection implementation separately from a simple reference prover.

### 24.3 Link, scale, and decryption

For every equation independently, test a valid witness and a mutation that only violates that equation. Alter each statement/temporary point and each response type. Test joint-key/role/context substitution and proof reuse across games or stages.

Test zero scale factors, scaling only one ciphertext component, repeated factors in an intentionally faulty prover, wrong decryption shares, omitted/reordered tests, and premature decryption release. A repeated secret factor is a prohibited prover behavior even when ordinary proofs would verify; enforce honest-generation invariants and review privacy separately.

### 24.4 Uniqueness

Test differences at every integer in `[-102,102]` for each of the three offsets. Test raw-sum collisions of `0`, `+52`, and `-52`; all must reject. Distinct modulo-52 card sets must accept. Zero-test outputs must match a cleartext oracle used only in tests.

Include malicious transcript fixtures, not only self-generated honest proofs. Verify a failed proof cannot be classified as a normal random collision.

### 24.5 Candidate-key degeneracies

Test identity candidates, `K`/`-K` x-only collisions, equal keys across slots, commitment reuse, identity-key overlap, authorizer-key overlap, identity summed `R`, and identity difference `R`. Classify combined exceptional cases as specified, erase the attempt, and do not reuse secrets.

A test-only insecure-generator fixture `M=mu*G` must demonstrate why known `mu` permits false-candidate scalar derivation; production parameter construction must make this fixture inaccessible. This test illustrates a failure mode, not evidence that discrete-log hardness has been tested.

### 24.6 State-machine and public verifier

Test both arrival orders at every simultaneous stage, both first-blinder roles, duplicates, stale/future messages, differing signed duplicates, omitted commits, malformed openings, retries, crash/restart boundaries, sequence overflow, and predecessor-root mismatch.

The live client and independent public verifier must agree on every accepted/fault/collision fixture. Acceptance signatures must never occur before all 108 tests and catalogue checks complete. Tampering with descriptor commitments, catalogue hash, or `T8` must invalidate the certificate.

### 24.7 Bitcoin regtest

For all 103 raw-sum candidates, construct representative valid openings and spend the appropriate leaf. Test every one of the 52 card IDs, both possible raw sums where applicable, and card 51's single possible raw sum.

Reject wrong-card signatures, swapped witness signatures, missing authorizer signatures, wrong authorizer, wrong input/transaction/outputs/prevouts, altered metadata, wrong leaf/control block, invalid key parity handling, accidental output-key tweaking of the embedded key, and unexpected sighash encoding.

The compiler must reject 33-byte embedded signature keys; include a negative policy test demonstrating that such a substitution must not be trusted to provide BIP340 checking. Do not write a test that assumes Bitcoin consensus necessarily rejects an unknown-key-type signature check.

Verify no key-path signing scalar is held by either client. Verify all control blocks reproduce the intended output. Demonstrate that publishing a card signature does not itself reveal an opening scalar in the application's data model.

### 24.8 Privacy, distribution, and robustness

Use two separate client instances; neither setup instance may receive the other's witness objects. Confirm private openings never appear in the public transcript or logs. Statistical dealing tests must cover either party fixed while the other samples honestly, collision retries, and no input reuse. Statistical tests are not a security proof.

Fuzz every decoder and state-machine entry point. Add browser entropy failure, worker termination, cancellation, storage corruption, and bounded allocation tests. Dependency audit findings and malformed-message panics must be resolved before the relevant milestone passes.

## 25. Performance model and measurement requirements

### 25.1 Deterministic size accounting

With the exact codec above:

| Object | Bytes |
|---|---:|
| One player's range proof | 13,964 |
| One player's encryption-link proof | 1,755 |
| PlayerBundle | 16,611 |
| Scale round payload | 24,840 |
| Decryption body | 7,193 |
| AcceptedDeal body / signed descriptor | 728 / 856 |
| Complete successful SetupCertificate | 102,070 |
| Signed share reveal | 199 |
| Envelope overhead | 179 |

A successful attempt has 16 envelopes. Payload totals, across both parties:

```text
key commits       2*32                =     64
key opens         2*(32+33+33+32)     =    260
bundle commits    2*32                =     64
bundle opens      2*(32+16611)        = 33,286
scale rounds      2*24840             = 49,680
decrypt commits   2*32                =     64
decrypt opens     2*(32+7193)         = 14,450
accept signatures 2*(32+64)           =    192
payload total                         = 98,060
envelopes         16*179              =  2,864
successful-attempt total              =100,924 bytes
```

These are format-derived counts, not measured traffic. They exclude initial configuration exchange, transport framing/encryption, acknowledgements, retries, application messages, Bitcoin manifests/transactions, and retransmissions. A collision attempt ending at stage 8 is 100,374 bytes under the same assumptions.

For honest independent contributions, the mathematical success probability is:

```text
p = product(i=0..8, (52-i)/52) = approximately 0.480254705388
expected attempts = approximately 2.0822284275
```

Ignoring negligible degeneracies and malicious aborts, expected setup envelope bytes through acceptance are `100924 + (1/p - 1)*100374`, approximately 210 kB across both parties. This is not a phone runtime estimate and is not a bound against repeated malicious aborts.

### 25.2 Benchmarks

Measure key setup; range generation/verification; link generation/verification; each scale and decryption phase; candidate derivation; public-certificate verification; serialization/hashing; cold-start and warm-start complete attempts; and complete accepted deals including actual retry counts.

Report median and tail latency, peak WASM memory, allocation counts where available, transferred bytes, worker responsiveness, and hardware/browser/OS/compiler/library versions. Separate CPU-only from networked results and per-attempt from per-accepted-deal results. Test physical supported iOS and Android devices, not only a desktop browser emulator.

Compare against the original SHA-proof implementation on the same device when it is available. Do not fabricate a speedup or infer end-to-end latency from eliminating one circuit. Make performance thresholds explicit product acceptance criteria after collecting the baseline.

### 25.3 Permitted optimizations

Cache public generator multiples, derive candidate keys by repeated subtraction, keep projective points until batched normalization, and use vetted public-input multiscalar algorithms for verification. Profile before selecting these optimizations. Secret-dependent operations require constant-time implementations; a public verification fast path must not leak into prover code.

Do not reuse secret scalars/nonces, skip proof equations, share uniqueness factors, accept variable proof shapes, outsource witnesses, truncate scalar challenges, weaken canonical parsing, or replace transcript-bound stages with arrival-order hashes to improve a benchmark. Any alternate proof profile requires a separately specified and reviewed version.

## 26. Implementation milestones and acceptance gates

**M0 — specification lock and dependency manifest.** Record the source basis and changes; pin toolchain/dependencies; derive parameter bytes and independent generator vectors; define release features that disable real-funds behavior. Gate: two implementations agree on parameters and codec.

**M1 — algebra and local opening mechanism.** Implement commitments, ElGamal, card mapping, candidate derivation/screening, share predicates, and BIP340 parity handling. Gate: exhaustive contribution matrix and independent signature verification pass.

**M2 — proof system.** Implement all five proof families with byte-level transcript traces. Gate: honest/malicious fixtures and independent verifier agreement; exact proof sizes; no ignored equations or placeholder proofs.

**M3 — authenticated deal protocol.** Implement stages, commit/open barriers, retries, persistence, public certificates, and typed verified objects. Gate: two processes accept the same transcript root and external verification agrees; adversarial scheduling tests pass.

**M4 — browser and regtest integration.** Implement dedicated workers, secure entropy, gated private reveals, all 103 candidate leaves, manifests, and complete transaction/witness tests. Gate: physical-phone demonstration and Core regtest acceptance/rejection matrix.

**M5 — hardening and assessment.** Complete fuzzing, side-channel review, dependency review, cross-implementation vectors, and actual performance report. Gate: no unresolved high-severity findings in the declared scope.

A complete implementation deliverable must include known limitations, remaining cryptographic review questions, and a separate list of unimplemented external settlement requirements. Passing tests is not the production-readiness gate.

## 27. Real-funds prohibition and required independent review

Before real-funds integration, require independent review of the exact bit-OR range proof composition, Fiat–Shamir contexts, commitment/ciphertext linkage, DDH uniqueness privacy including adaptive malicious behavior, candidate-key/BIP340 related-key enforcement, exceptional-case checks, private reveals, secret retention, and the full transaction graph.

Review the actual compiled/deployed dependencies, parsers, state machine, browser origin/security model, persistence/recovery behavior, reproducible builds, and mainnet transaction policy/consensus assumptions. Evaluate denial of service, abort handling, and economic fairness separately from setup soundness.

The full funding/refund/penalty/revelation graph is a mandatory separate deliverable before deployment. Neither this draft nor the supplied BP52 document specifies it. Do not replace this missing contract with an assertion that the card gate is “Bitcoin-enforced poker.”

## 28. Agent completion report

Return the repository and reproducible commands; completed milestone table; test/fuzz results with actual execution status; interoperability vectors; hardware-labelled benchmark results; dependency/build manifest; explicit deviations or proposed amendments; and known limitations.

State separately whether cryptographic tests, browser tests, Core regtest transactions, independent verification, and external audit were actually performed. Never report an unrun test or unaudited component as passed.

## 29. References and provenance

References support imported primitives and the inherited structure. They do not certify this proposed protocol's composition.

**[S0]** User-supplied `BP52-DEAL-v1`, filename `Pasted markdown(20260904-205224).md`. Sections cited inline. A SHA-256 fingerprint of the exact supplied file is recorded in the companion validation report.

**[S1]** RFC 9380, *Hashing to Elliptic Curves*, especially §8.7 and §J.8.1. `https://www.rfc-editor.org/rfc/rfc9380.html`

**[S2]** Bitcoin BIP 340, *Schnorr Signatures for secp256k1*. `https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki`

**[S3]** Bitcoin BIP 342, *Validation of Taproot Scripts*. `https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki`

**[S4]** Cramer, Damgård, Schoenmakers, *Proofs of Partial Knowledge and Simplified Design of Witness Hiding Protocols*, CRYPTO 1994; author-institution record. `https://ir.cwi.nl/pub/1456`

**[S5]** Bitcoin BIP 341, *Taproot: SegWit version 1 spending rules*. `https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki`

**[S6]** RustCrypto `k256` documentation and security notes. `https://docs.rs/k256/latest/k256/`

**[S7]** `getrandom` documentation, WebAssembly support. `https://docs.rs/getrandom/latest/getrandom/`

**[S8]** `rust-bitcoin` `SighashCache` documentation. `https://docs.rs/bitcoin/latest/bitcoin/sighash/struct.SighashCache.html`

**[S9]** Bitcoin Core `libsecp256k1` project. `https://github.com/bitcoin-core/secp256k1`

**[S10]** User-referenced Bitcoin Script primitives library, background only; no contract deployment claim is imported from it. `https://github.com/solving-bitcoin/bitcoin-scripts`

External references were consulted on 2026-09-04. Implementations must pin actual library revisions and retain the reference versions used for interoperability; a moving documentation link is not a dependency lock.
