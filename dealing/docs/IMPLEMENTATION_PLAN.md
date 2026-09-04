# BP52-DEAL-v1 implementation plan

This plan translates [`../BP52_DEAL_v1_SPEC.md`](../BP52_DEAL_v1_SPEC.md) into
the Rust workspace. Interoperability choices omitted or ambiguous in the base
specification are frozen separately in
[`ADR-0001-wire-transcript-profile.md`](ADR-0001-wire-transcript-profile.md).

## Architecture and status

| Phase | Deliverable | Crate(s) | Status |
|---|---|---|---|
| 1 | Bounded canonical little-endian codec and exact wire sizes | `bp52-codec`, `bp52-protocol::messages` | Complete |
| 2 | Fixed Ristretto generators, commitments, threshold exponential ElGamal, nonzero secret types | `bp52-group` | Complete |
| 3 | Key possession, encryption-link, scale, and partial-decryption Sigma proofs with fixed Merlin frames | `bp52-sigma` | Complete |
| 4 | Fixed-shape two-block SHA-256 R1CS relation, manifest, circuit ID, and pinned backend | `bp52-circuit`, `bp52-proof-backend` | Complete |
| 5 | Canonical 108-test derivation, two blinding rounds, committed dual decryption, collision bitmap | `bp52-uniqueness` | Complete |
| 6 | Contribution/bundle generation, BIP340 envelopes, 16-message semantic state machine | `bp52-protocol` | Complete |
| 7 | Linear retry history, public-material freshness, secret erasure, exactly-once acceptance | `bp52-protocol::history` | Complete |
| 8 | Full accepted-archive replay and opaque verified certificate | `bp52-protocol::archive` | Complete |
| 9 | Native openings, selective reveal policy, and script-path-only Taproot template | `bp52-bitcoin` | Complete |
| 10 | Spec-compatible fixed-parameter facade, CLI vectors, fuzzing, benchmarks, CI, and security documentation | workspace | Complete |

## Required integration flow

1. Canonically assign Bitcoin identity keys and obtain fixed v1 parameters
   through `ProtocolParams::new`. The first successful construction initializes
   the generator vectors; every later protocol context in the process shares
   that immutable allocation.
2. Start attempt zero through `PublicAttemptHistory`, borrowing
   `ProtocolParams::hash_length_parameters`; move the fresh local key share
   into the returned `TrackedAttempt`.
3. Exchange only canonical envelope bytes through
   `TrackedAttempt::accept_bytes`. Generate outgoing proofs from the typed
   phase snapshots exposed by its read-only verifier view.
4. On opaque collision/degenerate progress, consume `retry`; the API wipes the
   owned attempt secrets before returning the only successor boundary.
5. On ready progress, consume `into_pending_acceptance`, collect exactly one
   verified signature per role, and finalize once.
6. Independent observers call `verify_accepted_archive` over the certificate
   and all 16 envelopes. Bitcoin reveal/script APIs accept only its opaque
   `VerifiedAcceptedDeal` result.

## Release gates

Ordinary formatting, lint, documentation, MSRV, unit/integration, parser-fuzz,
and backend-fork tests are automated. A candidate release additionally needs:

- the ignored release-mode 2^19-generator proof and end-to-end archive tests;
- the full 52 lengths × 100 random-message proof qualification campaign;
- Bitcoin Core regtest execution of every opening branch;
- immutable cross-implementation wire/proof vectors;
- constant-time and memory-erasure review of the pinned backend fork;
- independent cryptographic and Bitcoin-script audits.

Until every release gate passes, the workspace remains a research prototype
and must not handle real funds.
