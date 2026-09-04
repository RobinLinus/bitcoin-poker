# Vendored cryptographic dependencies

`bulletproofs/` starts from zkcrypto/bulletproofs commit
`04bce4e66013ff857ed462fd4206210544101461` (source version 5.0.1), enables the
experimental `yoloproofs` R1CS module, and carries the local patch identity
`bp52-hardening-2`.

The local patch makes the following security-critical prover changes:

- every committed value, commitment blinding, and folded witness-scalar vector
  is overwritten before its heap allocation is released;
- inner-product commitments involving secret witness scalars use Dalek's
  constant-time multiscalar multiplication;
- large secret-scalar MSMs are split into fixed, public-sized chunks and run
  in parallel without scalar-dependent task creation or memory access; and
- public inner-product generator folds use an allocation-free signed-window
  implementation. Variable-time multiplication remains only where all
  scalars are public transcript challenges.

These changes are included in the backend identifier and therefore in the
canonical circuit manifest and `circuit_id`.

`bulletproofs/SOURCE_TREE_SHA256` authenticates the complete ordinary source
tree, including untracked-at-upstream patch files such as
`src/accelerated_msm.rs`. Run `scripts/check-source-integrity.sh` from the
repository root before producing a release archive. A release checkout must
contain the backend as ordinary files: nested `.git` metadata and gitlink
entries are rejected because either can silently omit the local hardening.

The upstream R1CS implementation explicitly warns that it is experimental and
unsuitable for deployment. It is included only for the interoperable research
prototype and remains subject to all audit gates in the BP52 specification.
