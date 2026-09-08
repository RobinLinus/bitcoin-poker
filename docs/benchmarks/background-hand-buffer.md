# Background hand buffer qualification

## Implementation

The browser keeps three future dealer slots and at most eight exact-balance tree candidates. A single candidate per seat performs speculative signing at a time; its two owners use one crypto worker each. Four completed candidate engines remain hot, and other completed candidates reside in encrypted browser storage. Both peers acknowledge completion before an engine is evicted.

Candidates exchange and verify descendant and launch signatures before selection. Native selection checks the actual terminal balances and slot progression. A durable channel frontier prevents conflicting local activation, and native entry/play gates withhold funding authorization and card openings until selection and retirement, respectively. Garbage collection preserves selected or enforceable journals.

Accepted dealer state is immutable and shared within native forks. A newly created candidate browser worker still restores its slot transcript from encrypted storage; cross-worker transcript replay elimination is not implemented. This remains an optimization opportunity.

Cooperative recovery registrations persist locally after the worker's first funding check. The separate browser defense worker observes chain spends and records closure; subsequent registrations honor that local closure marker. Reload performs a fresh funding check.

## Tests

- Native complete cooperative hand, both recovery roots, exact-balance successor selection, hand retirement, checkpoint recovery, and cashout.
- Native future slots reuse accepted dealing while separating candidate score secrets; premature funding entry and play are rejected.
- Native a settled parent can restore its closing state after selecting a candidate, without permitting another selection.
- Browser-side tests cover bounded scheduling, peer completion, warm promotion, cache misses, sit out, cashout, disposal guards, and local cooperative recovery registration.

## Initial browser integration, 2026-09-06

A resumed MutinyNet session completed three hands (24 betting actions), stopped for sitting out, and confirmed cooperative cashout. No move or redeal transaction was broadcast. Funding remained unspent until cashout.

- Initial game: `df7ba29738e96faa9a757ea42f6432b5de4f9973b71f23de827cff11738d2126`.
- Final game: `82d8f55f752a0485afcb5270bcbe8ffebf1c3700fad48005ac66b17c5ece1a85`.
- Cashout: `42cb6b62db75050737638e407f9d719776c7ca74308cc242781e29e9a1dc5e5e`.
- Payout outputs: 21,445 and 22,644 base units; fee 21.
- Eight candidates across three future slots were observed prepared on both seats.
- Terminal-to-successor-ready: 13.08 seconds and 43.25 seconds.

Those timings predate local-only cooperative recovery registration and the larger hot-engine cache. The second transition required further preparation. The run resumed cached work and therefore is not a cold-start throughput benchmark. Both test seats used independent cryptographic workers in the same browser and shared the browser wallet destination.

The sub-two-second warm handover target is not established by this run. A bounded portfolio cannot cover every possible resulting balance, so misses remain possible.

## Fresh browser integration after latency fixes

The updated browser/Wasm completed another three hands, 24 betting actions, automatic redealing, sit out, and confirmed cooperative cashout without errors. Both seats reached eight prepared candidates before play. Subsequent moves pruned the nearest portfolio and replenished it while play continued.

- Initial game: `745ad3de993565884c77caa9f03f7cc7ab0c6fce5f197b4bbe6b3f62eae64fe6`.
- Final game: `1c3909259e11899e8b759cfd7708dab384574e900827a98177f7115cccaf9726`.
- Funding: `bf890769e9ea828f52fbabd08a094ed079913a32a3e6741d560b7fcf22500c30`.
- Cashout: `fe4226d1e51ba0c17bc9093eccf1468dd1a019af71a64b7f38086be02c6bdb8b`.
- Payout outputs: 21,845 and 22,244 base units; fee 21; both seats marked left.
- Only funding and cashout transaction IDs were published. The existing confirmation loops retried these same transactions; no gameplay or redeal transaction was published.
- Initial ready time including funding confirmation: 34.22 seconds.
- Eight-candidate buffer ready at 303.72 seconds after setup started. This is not a prerequisite for normal table play; the qualification harness deliberately waits for it once.
- First handover: 2.20 seconds. Second handover: 5.57 seconds. Both selected previously prepared balance candidates, with the deeper candidate requiring restoration from storage.
- Move acceptance: median 488ms, p95 2,368ms, maximum 5,869ms across 24 samples.
- Wasm: `a0837cf508e926443db85964940c050de516ddcc307891e075860641f09b0a0f`.

These two handovers are insufficient to establish a p95, and neither demonstrates the sub-two-second target. Background throughput and storage restoration remain material costs. The test ran two seats on one local browser alongside other desktop activity, rather than on an isolated benchmark machine.

After this run's build, two small browser changes were unit-tested: idle buffer garbage collection no longer rewrites unchanged table state, and background monitoring deduplicates funding observations across historical hands. The final client includes those changes. All 78 onchain browser-side tests pass; the native channel integration suite passes both tests.
