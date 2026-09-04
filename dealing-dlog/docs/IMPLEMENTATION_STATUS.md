# Implementation status — 2026-09-04

| Milestone | Status | Evidence |
|---|---|---|
| M0 parameters/codec | Partial | Fixed generator/manifest vectors and canonical primitive tests pass; independent second implementation is outstanding. |
| M1 algebra/openings | Partial | Contribution matrix, commitments, ciphertexts, candidates, opening checks, and BIP340 key object are implemented; full parity matrix remains. |
| M2 proof system | Partial | All five proof relations are implemented. Range/link adversarial mutation tests pass; comprehensive fixture/differential coverage remains. |
| M3 authenticated protocol | Not complete | Typed bundle and accepted-body objects exist; persistent envelope state machine and public certificate replay are outstanding. |
| M4 browser/regtest | Not complete | Exact leaf and regtest guard exist; tree, transactions, Core matrix, and browser worker are outstanding. |
| M5 hardening | Not started | No audit, fuzz campaign, physical-device benchmark, or independent security review has been performed. |

No component in this directory is authorized for mainnet or real-funds use.
