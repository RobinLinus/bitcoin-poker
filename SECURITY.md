# Security policy

The repository contains three research workspaces:

- [`dealing/`](dealing/) implements BP52-DEAL-v1.
- [`chain/`](chain/) implements BP52-CHAIN-v1 and consumes an accepted deal.
- [`client/`](client/) contains prototype storage and external-chain adapters.

None of these workspaces is production-ready. Do not use them with real funds
until every production-readiness gate in section 29 of the
[dealing specification](dealing/BP52_DEAL_v1_SPEC.md) and section 39 of the
[chain specification](chain/BP52-CHAIN-v1-agent-implementation-spec.md) has
been completed. See the
[dealing implementation security notes](dealing/docs/SECURITY_IMPLEMENTATION_NOTES.md)
and the [chain compiler ADR](chain/docs/ADR-0001-reference-encoding-and-compiler-profile.md)
for design details and the current review boundaries.

Security-sensitive findings should be reported privately to the maintainers.
Do not include live keys, preimages, wallet data, or funding transaction secrets
in a report.

## Dealing retry and fault handling

The reviewed DEAL transport boundary is `PublicAttemptHistory::start_attempt`
followed by `TrackedAttempt::accept_bytes`. It owns the semantic verifier and
local secret state, rejects cross-attempt reuse before transcript advancement,
and allows a retry only when the verifier returns opaque collision or
degenerate evidence. Old attempt secrets are wiped before a next-attempt
boundary exists.

Authenticated traffic for another protocol version, game, attempt, sequence,
or predecessor is treated as out-of-context and cannot poison the live attempt.
A validly signed malformed message at the exact live cursor faults its signer;
a recorded timeout faults the scheduled sender. Joint-key identity and
cross-party duplicate hashes remain unattributable setup failures.

## Acceptance boundary

Checking only the two final BIP340 signatures does not prove that an attempt was
valid. Public observers must call `verify_accepted_archive`, which replays all
16 authenticated envelopes, verifies the proofs and zero tests, reconstructs
`T_16`, compares the accepted body, and then checks both signatures. Bitcoin
reveal and safe script constructors require its opaque `VerifiedAcceptedDeal`.

The browser does not make each long-lived Worker repeat that heavyweight
archive verification. Its disposable DEAL Worker incrementally authenticates
and verifies the same 16-envelope attempt, then issues a compact local
identity-signed attestation bound to the configuration, session, game, attempt,
`T_16`, and result. GAME and CHAIN validate that attestation, the accepted
certificate, and both identity signatures to obtain the same trusted boundary.
They reject a certificate without the context-bound attestation and never
accept the final signatures alone. Independent observers that did not witness
and verify the live attempt still need the full archive path above.

## Remaining production gates

The implementation and vendored proof backend require independent
cryptographic review, release-mode execution of the expensive Bulletproof
matrix, cross-implementation vectors, and Bitcoin Core regtest coverage before
real-funds deployment. Zeroization covers concrete secret owners and guarded
heap allocations; it cannot guarantee removal of compiler-created register or
stack copies, allocator metadata, or copies retained by an application.
The vendored prover also retains documented narrow erasure gaps for
witness-derived stack scalars and an unwind window before two evaluated witness
vectors enter their erasing owner. These are release blockers even though the
affected arithmetic is constant-time.

The chain implementation additionally keeps mainnet execution disabled until
the exact Taproot construction and five-card Script evaluator have received an
independent audit, deterministic graph roots agree with another
implementation, Bitcoin Core regtest and signet paths pass, and fee bumping,
pinning, timeout economics, crash recovery, mempool races, and reorg handling
have been reviewed. Unit tests and an in-process Script model do not substitute
for Bitcoin Core consensus and policy testing.

The browser client now exercises the complete research flow on a configured
non-mainnet deployment: two exact staging deposits, a jointly authorized
origin with a pre-signed CSV refund, the 16-flight private deal, streaming
graph audit and peer-only preauthorization storage, activation, gameplay,
showdown, and terminal payout. Setup advances automatically after both
deposits confirm. This is test-harness coverage, not a production-custody
claim.

In particular, the staging/identity private key is still plaintext in
same-origin browser storage. Secret CHAIN checkpoints are authenticated and
encrypted, but the wrapping material, counter, and ciphertext live in the same
rollbackable browser database; there is no external monotonic rollback anchor.
The current terminal path durably marks the selected one-time Lamport key as
erased in the compact state bitmap and rejects reuse; it does not erase every
identity, retained-preimage, unselected-branch, or resume secret.

The configured Esplora genesis and checkpoint are trusted inputs. Transaction
bytes are parsed and transaction IDs are recomputed in rust-bitcoin Wasm, but
the client does not validate a header chain or Merkle proofs. The service can
censor, delay, or equivocate, and the current monitor cannot safely recover
from a same-or-higher-height reorganization after one-time secrets have been
erased. The fixed pre-signed fee schedule also has no fee-bump path. A public
relay additionally requires TLS termination and IP-aware rate limiting at an
edge proxy. Finally, the full Bulletproof verifier has a browser-Wasm
high-water allocation of roughly 1.4 GiB per heavyweight Worker. These are
production blockers; mainnet construction and broadcast remain disabled.
