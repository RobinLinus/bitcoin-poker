# Repository cleanup outcome

The cleanup is implemented. The original staged proposal is retained in Git
history; current architecture and instructions live in:

- [Architecture](architecture.md): crate ownership, dependency direction, state contracts, and compatibility boundaries.
- [Development](development.md): root workspace, application/tool commands, and naming conventions.
- [Testing](testing.md): native, browser, Wasm, Core, and archive qualification.
- [Status](status.md): implemented behavior and remaining funded-browser work.
- [Roadmap](roadmap.md): on-chain Milestone 1 and subsequent cooperative optimization.

## Applied

- One root Cargo workspace, lockfile, toolchain, formatting policy, and CI pipeline.
- Shared libraries under `crates/`, applications under `apps/`, developer tools
  under `tools/`, and authoritative configuration under `deployments/`.
- `dealer-*` names for dealing crates and `poker-*` for product/settlement crates.
- Explicit settlement configuration, graph, preparation, and authorization names.
- Separate graph verification/fees, Taproot program families, state accounting/
  timeouts, relay routes/assets/auth/storage, protocol tests, and Wasm participant/
  benchmark modules.
- One browser tree with explicit practice, dealing, funding, Bitcoin, storage,
  rendering, worker, and Wasm responsibilities; no global funding hook registry.
- Schema-3 practice relay configuration with no funded terms or broadcasting.
- Native funding terms derived from validated budgets; old amounts confined to
  diagnostic fixtures and the explicitly diagnostic funding Wasm bridge.
- Consolidated documentation, strict lint checks, and native/browser/Wasm/Core CI.

## Deliberate decisions

The two codecs retain distinct encoding/error contracts; they were not merged
through a compatibility facade. The two transaction publishing ports likewise
retain their distinct representations and verified-network contracts. These
boundaries are documented in the architecture rather than hidden by vague names.

Meaningful cryptographic terms, verification-bearing types, binary tags, role
ordering, canonical encodings, and transaction semantics remain intact. The
dealer Wasm artifact/ABI and browser asset paths migrated together. Existing
practice storage keys and protocol message identifiers remain stable.

Local `.bp52/` data was left untouched. Build caches from the old source roots
were retained under ignored `target/pre-cleanup/`. Funded browser integration
and deployment remain the next product milestone, not part of this cleanup.
