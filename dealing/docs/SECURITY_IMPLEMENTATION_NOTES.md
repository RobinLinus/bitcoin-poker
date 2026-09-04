# Security implementation notes

This document records fail-closed choices discovered during implementation.
They supplement the research specification and require independent review.

## Mandatory invariants

- `M` is produced only by Dalek's Ristretto hash-to-point API over the exact
  protocol string. Hashing to a known scalar and multiplying `G` is forbidden.
  The compressed `M` golden value is
  `5c08969e2116504cb9a1999ce0347fa822b05add6a6fc7964993024733da6e20`.
- The Bulletproof Pedersen bases are exactly `B=M` and `B_blinding=G`.
- Original public keys, value commitments, and ciphertext `R` points are
  nonidentity. Scale-factor points and the required Sigma nonce commitments
  are also nonidentity. Identities are permitted only where the algebra calls
  for them, such as `Enc(t;0).R` and a collision plaintext.
- The two threshold public-key shares must differ. If they were equal, both
  parties would know the same share scalar and therefore the complete joint
  decryption scalar. Honest equality has negligible probability and causes a
  neutral setup retry.
- If a locally derived sum or difference has identity `R`, the attempt takes a
  neutral fresh retry. Accepting it would expose the small plaintext by brute
  force.
- Every Sigma proof mask and uniqueness scale factor is independently sampled
  from the nonzero field elements using a bounded rejection loop. Merlin nonce
  derivation rekeys with the witness and fresh external CSPRNG entropy.
- All proof challenges bind the full common attempt frame and every indexed
  public statement before any temporary commitment. Challenges use 64 Merlin
  bytes reduced modulo the scalar field; zero is rejected.
- The 108-test order exists once in code and is shared by derivation and proof
  verification. Every scale proof checks both ciphertext components.
- Both committed partial-decryption batches and their proofs are verified
  before any plaintext identity is inspected. All 108 results are computed;
  collision checking does not return early.
- Secret-owning types have private fields, zeroize on drop, and do not derive
  `Clone`, `Copy`, `Debug`, or serialization traits.
- Accepted preimages have no plaintext persistence codec. Their only storage
  format is a bounded, versioned XChaCha20-Poly1305 envelope whose associated
  data binds the game, attempt, local role, and accepted-deal body digest.
  Sealing validates all nine hash locks and erases the in-memory owner only
  after encryption succeeds; opening consumes the ciphertext owner and checks
  every hash lock again before returning live secret material.
- `PreimageStorageKey` is non-cloneable, redacts diagnostics, zeroizes on drop,
  and refuses a nonce collision observed by its active sealing instance.
  Durable storage-key custody and single-writer coordination remain the
  responsibility of the embedding OS keyring/HSM layer.
- No secret scalar may reach a variable-time group operation.
- The pinned Bulletproof source carries `bp52-hardening-2`: R1CS committed
  values/blindings and inner-product witness vectors are erased item-by-item,
  and prover MSMs involving witness-derived scalars use the constant-time
  Dalek path. Parallel MSM work is partitioned only by public vector length;
  public generator folds use public transcript challenges exclusively. This
  local patch is committed into the backend identity and circuit manifest.

## Authenticated lifecycle and replay

- The production transport entry point is the cumulative
  `PublicAttemptHistory`/`TrackedAttempt` lifecycle. It owns the semantic
  verifier and the concrete local secret container; downstream code cannot
  directly construct or advance the lower-level verifier.
- A bounded envelope is authenticated before sender-owned malformed fields are
  interpreted. If its raw role byte is invalid, both canonical identity keys
  are tried so a unique signer can still be blamed.
- Authenticated traffic for another protocol version, game, attempt, sequence,
  or predecessor is an out-of-context routing result. It cannot poison the
  current attempt or blame its signer. Only an authenticated violation at the
  exact current cursor is terminal.
- Every accepted envelope contributes component-tagged public fingerprints to
  the live freshness inventory before transcript advancement. Pure multiples
  of `G` also share a cross-kind fingerprint, preventing one rejected
  attempt's scalar from being reused as a key share, ElGamal nonce, scale
  factor, or proof nonce under a different semantic label.
- Retry and ready-to-sign evidence is private, linear, and produced only by the
  integrated verifier. A live or pending object that is abandoned faults the
  history; the same game/attempt cannot be restarted through this API.
- `verification_transcript_root` is exactly `T_16`. Accepted signatures remain
  outside that root to avoid a hash/signature cycle. Public acceptance requires
  replaying the exact 16-envelope archive and comparing the reconstructed body
  before checking both certificate signatures.

## Secret-erasure boundary

The implementation wipes the private, non-`Clone` secret containers that it
owns, including retained contribution material, Sigma masks, R1CS witness
vectors, committed values/blindings, and inner-product witness vectors. Old
attempt secrets are wiped before a fresh-attempt boundary is returned.

Rust cannot guarantee erasure of compiler-created register copies, stack
temporaries, allocator metadata, or copies made by a caller before ownership is
transferred. The erasure claim applies only to the concrete instances owned by
this implementation; it is not a whole-process memory-sanitization guarantee.

The vendored prover still has two concrete erasure-audit items before it can
claim complete section 20 compliance: witness-derived `c_L`/`c_R` stack
scalars in its inner-product and linear-proof provers are not explicitly
wiped, and the R1CS prover's evaluated `l_vec`/`r_vec` have a narrow
panic/unwind window before ownership moves into their erasing guard. Neither
path uses variable-time arithmetic, but both remain production-qualification
blockers.

## Bitcoin boundary

Reveal APIs and the safe card-opening template accept only an opaque
`VerifiedAcceptedDeal`. The default Taproot template binds the selected slot's
two hashes and uses the reviewed BIP341 NUMS internal key so there is no known
key-path bypass. A constructor accepting a caller key is explicitly named and
documented as enabling a key-path bypass.

## Deviations needing specification ratification

The implementation resamples a zero Pedersen blinding, even when its resulting
commitment would be nonidentity. A zero blinding exposes the small committed
value. This event is negligible under an honest RNG but must not be admitted by
an accepted transcript.

Derived-`R` cancellation causes an unattributed `DegenerateRetry`, distinct
from a card collision and from cheating. The base specification does not
currently describe this outcome.

The reference implementation uses the 16-message linear schedule and
transcript cutoffs in `ADR-0001-wire-transcript-profile.md`. These choices are
interoperability-critical and must move into a ratified protocol revision.

## Deployment status

The vendored Bulletproof R1CS backend is experimental. Its exact revision, the
SHA-256 gadget, circuit composition, manual Sigma transcripts, parsers, secret
lifecycle, and surrounding Bitcoin penalty graph all require independent audit
before real-funds use.

The local serialized-tapscript interpreter and exhaustive share/card matrix do
not replace execution against the pinned Bitcoin Core regtest version. The
full 100-random-message-per-length proof matrix is also intentionally too
expensive for the ordinary CI gate and must be run as a release qualification
campaign.
