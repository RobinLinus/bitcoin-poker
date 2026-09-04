# BP52-DEAL-v1 reference implementation

This workspace implements the research protocol in
[`BP52_DEAL_v1_SPEC.md`](BP52_DEAL_v1_SPEC.md) using Rust and the Dalek
Ristretto ecosystem.

See the [implementation plan](docs/IMPLEMENTATION_PLAN.md), the proposed
[wire/transcript profile](docs/ADR-0001-wire-transcript-profile.md), and the
[security implementation notes](docs/SECURITY_IMPLEMENTATION_NOTES.md).

> **Warning:** this software is under development, has not received an
> independent cryptographic audit, and must not be used with real funds.

The public Bitcoin-facing result is two ordered arrays of nine SHA-256 hashes.
The off-chain protocol proves that the preimage lengths encode nine distinct
cards without revealing the cards during setup.

## Workspace

- `bp52-codec`: canonical, bounded wire encoding
- `bp52-group`: generators and threshold exponential ElGamal
- `bp52-sigma`: Schnorr and DLEQ proof composition
- `bp52-uniqueness`: the 108 blinded zero tests
- `bp52-proof-backend`: pinned Bulletproof R1CS adapter
- `bp52-circuit`: fixed-shape SHA-256/preimage-length relation
- `bp52-protocol`: authenticated attempt state machine
- `bp52-bitcoin`: share/card opening and script integration
- `bp52-cli`: development and test-vector tooling

## Safe integration path

Live transports enter through `PublicAttemptHistory::start_attempt` and feed
bounded wire bytes only to `TrackedAttempt::accept_bytes`. That path owns the
semantic verifier, enforces cross-attempt public-material freshness, and makes
retry and acceptance terminal capabilities non-forgeable. The lower-level
attempt verifier cannot be constructed or advanced by downstream crates.

An observer validates an accepted certificate with `verify_accepted_archive`,
which replays all 16 signed envelopes and returns an opaque
`VerifiedAcceptedDeal`. Bitcoin reveal and script-path constructors require
that verified token. Signature-only certificate checking is deliberately not
an authorization boundary.

After acceptance, `RetainedPreimages::seal_at_rest` is the supported
persistence boundary for the nine local preimages. It validates them against
the accepted deal and writes only a versioned XChaCha20-Poly1305 ciphertext
envelope; the live owner is erased only after encryption succeeds. The
non-cloneable `PreimageStorageKey` accepts key material supplied by the caller.
Durable custody, backup, and access control for that key belong in an OS
keyring, HSM, or an equivalent application-managed facility.

Run the ordinary workspace gates with:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --no-deps --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo test --workspace --all-targets --locked
```

Four resource-intensive Bulletproof/end-to-end tests are ignored by the ordinary gate
because they allocate a 2^19-generator backend and take minutes. Run them in
release mode before a candidate release:

```sh
cargo test --release --workspace -- --ignored --nocapture
```

The [fuzz harness](fuzz/README.md) exercises bounded wire decoders, point and
scalar parsing, every proof parser, and schedule validation. The
[performance harness](benchmarks/README.md) exposes all section 26 generation,
verification, bandwidth, latency, and peak-memory measurements. Both have
their own committed lockfiles and are kept outside the production workspace.

The exhaustive local tapscript interpreter is not a substitute for the
Bitcoin Core regtest matrix required by the specification. That external gate,
independent cryptographic review, and cross-implementation interoperability
vectors remain mandatory before real-funds use.
