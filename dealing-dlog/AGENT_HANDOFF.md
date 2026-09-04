# Implementation handoff

Read `DLOG52-DEAL-v1-implementation-spec.md` completely before writing cryptographic protocol code. It is the normative draft for this assignment. The original BP52 document is background, not the new wire protocol.

## Assignment

Build DLOG52-DEAL-v1 as a Rust workspace with a public verifier, a browser/WASM worker interface, and the specified Bitcoin Core regtest single-slot gate demonstration. The setup must use the exact bit-OR range proof and retained ElGamal uniqueness construction. Do not implement the SHA-256/preimage-length Bulletproof or substitute the separate garbled-circuit proposal.

Treat the protocol as research code until independent review. Do not enable real-funds construction, signing, or funding. A passing single-slot script test is not a completed poker settlement.

## Execution order

1. Lock parameters, codec, transcript rules, toolchain, and actual dependency revisions. Produce independent hash-to-curve and parameter vectors.
2. Implement commitments, ElGamal, exact card mapping, candidate keys, degeneration checks, and share verification. Pass exhaustive contribution arithmetic and BIP340 parity tests.
3. Implement the range, link, key-possession, scaling, and partial-decryption proofs. Add transcript traces and adversarial fixtures, not just happy-path tests.
4. Implement frozen-stage messages, commit/open barriers, retry erasure, public certificates, and an independent verifier. Persist outgoing signed bytes before transmitting them.
5. Implement the worker UI boundary, private-opening authorization, and end-to-end confidential-channel integration. Do not let a relay or prover service receive witnesses.
6. Implement the exact 103-leaf-per-slot regtest profile, its independent compiler verification, transaction sighashes, manifests, and Core validation tests.
7. Run physical-device benchmarks, fuzzing, differential verification, and dependency review. Report actual results and unresolved issues.

## Non-negotiable review points

- Fixed RFC 9380 generator; no public `hash_to_scalar()*G` substitute.
- Full signed points off-chain; x-only keys only at the Bitcoin signature boundary.
- Exact range 0..51, not 0..63; same commitments and ciphertexts across all proofs.
- Every one of the 108 uniqueness relations checked; independent nonzero scales per test.
- Range proof shared challenge covers all 108 bit records, with both weighted-sum equations per slot.
- Correct frozen pre-commit proof contexts; no arrival-order transcript fork.
- Accepted root is T8, excluding acceptance signatures; complete certificate verified independently.
- Global x-only candidate-key uniqueness and required identity/ciphertext screening.
- Long-lived accepted commitment blinders retained securely; rejected openings and ephemeral witnesses erased.
- Real tapscript transaction sighash, 32-byte embedded keys, correct witness order, separate authorizer, and no known internal key that bypasses scripts.
- No assumption that an ordinary signature releases a reusable scalar.

## Expected outputs

Return source code and locked dependencies, reproducible build/test/demo commands, deterministic public vectors and explicitly marked test-only witness fixtures, malicious transcript tests, a full public-verifier CLI, regtest transactions, browser demonstration, hardware-labelled benchmark results, and a limitations/security-review report.

The companion `spec_consistency_checks.py` and `spec_consistency_report.json` validate only arithmetic and byte accounting in the draft. They do not implement elliptic-curve arithmetic, the proofs, BIP340, networking, or Bitcoin Script validation. Do not count them as cryptographic implementation tests.

Do not silently resolve an ambiguity by weakening a check. Record the proposed amendment, add a reproducing test, and isolate any affected component while continuing independent work.
