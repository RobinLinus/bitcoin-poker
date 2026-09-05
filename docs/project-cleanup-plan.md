# Project cleanup plan

Status: proposed. This document plans the cleanup; it does not implement it.

## Objective

Make the repository easy to navigate and extend around its actual architecture:
dlog dealing, a complete on-chain poker settlement graph, and applications that
consume them. On-chain settlement remains the backbone. Practice play and future
cooperative play have explicit boundaries and cannot imply funded readiness.

The target is one Rust workspace, one web source tree, clear library/application
ownership, consistent names, and a small set of repeatable development commands.
Prefer existing modules and libraries over adding abstraction layers.

## Findings that drive the plan

- Four cross-dependent Rust workspaces duplicate manifests, lockfiles, lint
  settings, release profiles, formatting configuration, and CI jobs. Their
  declared MSRV agrees, but their selected development toolchains differ.
- `client-cli/` contains reusable libraries and no playable CLI. `dlog52-cli`
  contains parameter inspection and benchmarking, not a poker application.
- Browser source is split between `client/browser/` and a Rust relay crate's
  `web/` directory. Product code, diagnostics, fixtures, and generated Wasm
  artifacts are mixed together.
- Several retained names describe removed abstractions: `descriptor.rs`,
  `descriptor_fixture`, `verify_node_against_descriptor`, `new_dlog`, and a
  one-variant `ShowdownOpenings` enum with an always-true `is_dlog()` method.
- `ReadyDlogGame` represents a verified public authorization inventory, not a
  durably recoverable, funded, playable application session.
- The relay's `audited_game_config` still embeds the old funded profile's
  economic values. Deployment copies and documentation still describe the
  removed funded applications. These require explicit correction, not cosmetic
  replacement of names.
- Large files mix separate responsibilities: graph planning and verification,
  Bitcoin scripts and witness assembly, relay routing and persistence, browser
  rendering and sessions, and benchmark and live-participant Wasm exports.

## Target repository layout

```text
bitcoin-poker/
  Cargo.toml                       # All Rust libraries, apps, and developer tools
  Cargo.lock
  rust-toolchain.toml
  rustfmt.toml
  README.md
  SECURITY.md

  crates/                          # Shared Rust libraries; directory = package name
    dlog52-codec/                  # Initially retained; primitive consolidation later
    dlog52-group/
    dlog52-transcript/
    dlog52-proofs/
    dlog52-uniqueness/
    dlog52-protocol/
    dlog52-openings/
    dlog52-bitcoin/
    dlog52-wasm/
    poker-codec/
    poker-eval/
    poker-score-ots/
    poker-settlement-types/
    poker-bitcoin/
    poker-settlement/
    poker-funding/
    poker-client-ports/
    poker-chain-monitor/
    poker-store-sqlite/
    poker-esplora/
    poker-transport-libp2p/
    poker-wallet-wasm/
    poker-funding-wasm/
    poker-transaction-wasm/
    poker-core-test-support/

  apps/
    relay/                         # Rust executable, HTTP service, application DB
      Cargo.toml
      src/
      tests/
    web/                           # All browser application source
      package.json
      index.html
      src/
      public/
        wasm/                      # Published artifacts and generated manifest
      tests/                       # Browser integration tests and their fixtures

  tools/
    deal-tools/                    # Rust parameter inspection and benchmarks
    browser-deal-demo/             # Diagnostic two-participant demo, separate entry
    wasm-benchmark.mjs

  deployments/
    mutinynet/                     # One authoritative environment configuration
    regtest/
  toolchains/
    browser-wasm.Dockerfile
    browser-wasm-artifacts.json     # Build/export contract, not deployment config
  scripts/                         # Root-relative build and qualification commands
  docs/
    architecture.md
    development.md
    testing.md
    status.md
    roadmap.md
    protocols/
      dlog52-deal-v1.md
      onchain-reveal-extension.md
    decisions/                     # Only decisions with durable architectural value
  .github/workflows/
```

Keep Rust unit tests adjacent to their module and integration tests inside the
owning crate. Keep JS unit tests next to their source. Move poker vectors into
`crates/poker-eval/tests/fixtures/` and dealing vectors into their protocol owner.
Do not create a second global test tree that duplicates these owners.

Retire `chain/`, `dealing-dlog/`, `client/`, and `client-cli/` as source roots after
their contents move. Leave local wallet data, checkpoints, and ignored `.bp52/`
directories untouched; document their locations separately from source layout.

## Package and directory renames

Use `poker-*` for application and settlement libraries. Keep `dlog52-*` for the
actual specification-defined cryptographic protocol. `DLOG52` is a useful
protocol identity, not a leftover merely because it contains a versioned name.

| Current package/location | Target |
| --- | --- |
| `dealing-dlog/crates/dlog52-*` libraries | `crates/dlog52-*` |
| `bp52-poker` | `crates/poker-eval` |
| `bp52-chain-types` | `crates/poker-settlement-types` |
| `bp52-chain-bitcoin` | `crates/poker-bitcoin` |
| `bp52-chain-compiler` | `crates/poker-settlement` |
| `bp52-lamport` | `crates/poker-score-ots` |
| `bp52-codec` | `crates/poker-codec` |
| `bp52-core-test-support` | `crates/poker-core-test-support` |
| `bp52-origin` | `crates/poker-funding` |
| `bp52-client-ports` | `crates/poker-client-ports` |
| `bp52-client-core` | `crates/poker-chain-monitor` |
| `bp52-store-sqlite` | `crates/poker-store-sqlite` |
| `bp52-adapter-esplora` | `crates/poker-esplora` |
| `bp52-transport-libp2p` | `crates/poker-transport-libp2p` |
| `bp52-browser-wallet-wasm` | `crates/poker-wallet-wasm` |
| `bp52-browser-origin-wasm` | `crates/poker-funding-wasm` |
| `bp52-browser-transaction-wasm` | `crates/poker-transaction-wasm` |
| `bp52-relay-server` | `apps/relay`, package `poker-relay` |
| `dlog52-cli` | `tools/deal-tools`, descriptive `deal-params` and benchmark binaries |
| `dlog52-client` | Move its regtest-only gate handoff into diagnostic/test support; remove the wrapper crate after checking callers |

Keep settlement types in a neutral lower-level crate. They include canonical
graph records and Bitcoin-related accounting, so calling the whole crate
`poker-rules` would be misleading. Moving those records into the compiler could
also introduce a Bitcoin/compiler dependency cycle.

## Browser directories and filenames

```text
apps/web/src/
  main.js
  practice/
    table-controller.js
    room-session.js
    render-table.js
    signed-move-log.js
  dealing/
    participant.js
    worker.js
  funding/
    client.js
    worker.js
  bitcoin/
    esplora-client.js
    transaction-inspector.js
  storage/
    seat-session-store.js
  config/
    deployment.js
  wasm/
    loader.js
  workers/
    rpc-client.js
    serial-dispatch.js
  ui/
    bitcoin-amount.js
    styles.css
```

`practice/` names the current application honestly. Add `onchain/` when its
implementation exists, with confirmed graph state driving it. Do not create
empty folders, placeholder runtimes, or a generic mode framework now. Future
cooperative play must consume the on-chain settlement contract as an optimization.

| Current browser file | Target |
| --- | --- |
| Relay `web/bootstrap.js` | `src/main.js` |
| Relay `web/dlog52-game.js` | `src/practice/table-controller.js`, then extract room/session and rendering responsibilities |
| `browser/deal/dlog52-runtime.js` | `src/dealing/participant.js` |
| `browser/deal/dlog52-worker.js` | `src/dealing/worker.js` |
| `browser/game/offchain-ratchet.js` | `src/practice/signed-move-log.js` |
| Relay `web/origin-client.js` | `src/funding/client.js`; extract embedded worker code into `worker.js` |
| `browser/chain-adapter/esplora.js` | `src/bitcoin/esplora-client.js` |
| `browser/chain-adapter/transaction-runtime.js` | `src/bitcoin/transaction-inspector.js` |
| `browser/session/resume-store.js` | `src/storage/seat-session-store.js` |
| `browser/config/runtime-config.js` | `src/config/deployment.js` |
| `browser/config/wasm-loader.js` | `src/wasm/loader.js` |
| `browser/game/dlog52-heads-up.js` | `tests/fixtures/scripted-hand.js`; it is a scripted helper, not the application engine |
| `browser/deal/run-dlog52-two-party-e2e.mjs` | `tests/deal-e2e.mjs` |
| Relay `web/dlog52.html` and `dlog52-demo.js` | `tools/browser-deal-demo/index.html` and `main.js` |

Use native ES modules and the existing Node test runner. Consolidate the web
package and add normal test/build scripts; a bundler or framework migration is
not needed for this cleanup. Resolve source imports, worker URLs, relay asset
routes, test discovery, and Wasm packaging together when moving files.

## Rust module and symbol names

| Current name | Proposed name/action |
| --- | --- |
| Compiler `dlog.rs` | `settlement.rs`; separate parameter binding into `config.rs` |
| Compiler `dlog_preparation.rs` | `preparation.rs` |
| `DlogGraph` | `SettlementGraph` |
| `DlogParameters` | `SettlementConfig` |
| `DlogPreparation` | `SettlementPreparation` |
| `DlogAuthorizationRequest` | `AuthorizationRequest` within the settlement crate |
| `ReadyDlogGame` | `PreparedAuthorizations` |
| Preparation `ready()` | `into_prepared_authorizations()` |
| Preparation `missing()` / `accept()` | `missing_count()` / `accept_response()` |
| Preparation `snapshot()` / `restore()` | `encode_snapshot()` / `restore_verified_snapshot()` |
| Compiler `origin_state()` | `build_origin_escrow()` |
| Types `descriptor.rs` | `roles.rs` for `Role`; move reveal order and timeout policy beside their owning rule types |
| Variables/fixtures named `descriptor` for `PokerRules` | `rules` / `rules_fixture` |
| `verify_node_against_descriptor` | `verify_node_against_rules` |
| `verify_transition_against_descriptor` | `verify_transition_against_rules` |
| `TimeoutSpec::descriptor_csv()` | `TimeoutSpec::delay_for()` |
| `new_dlog()` on the sole supported constructors | `new()` |
| One-variant `ShowdownOpenings` / `is_dlog()` | Concrete showdown-opening struct; remove impossible branches |
| Bitcoin `dlog52.rs` mixing gates and showdown | `showdown/witness.rs`; put the diagnostic gate wrapper in regtest support |
| `DlogShowdownWitness` | `ShowdownWitness` within the poker Bitcoin crate |
| `MAX_CONSENSUS_SCRIPT_BYTES` | `MAX_GENERATED_SCRIPT_BYTES` if it is the compiler's profile bound; document the exact scope |
| `OffchainMoveRatchet` | `SignedMoveLog`, with handshake/hash-chain behavior documented |
| `playDlog52HeadsUpGame` | `runScriptedHand` in test fixtures |
| Browser `createResumeStore` | `createSeatSessionStore`; it persists seat credentials, not full game recovery |
| Chain-monitor `ClientError` | `ChainFollowerError` |
| `OriginPackage` / `OriginContext` | `EscrowFundingPackage` / `FundingContext` |
| `StagingInput` | `PlayerFundingInput` |
| Funding's custom `Txid` | `DisplayTxid`, or explicitly convert to `bitcoin::Txid`; preserve byte-order semantics |
| `audited_game_config` | Remove the stale profile construction; replace through a separately reviewed deployment-config change |

These are source/API names. Retain meaningful cryptographic terminology such as
Lamport, adaptor signatures, commitments, certificates, candidate keys, and
verified/unverified distinctions. Do not replace precise security states with
generic names like `Data`, `Context`, or `Manager`.

Split large modules by behavior, not arbitrary line limits:

- Settlement `graph.rs` → `graph/{mod,plan,build,verify,fees}.rs`; keep topology
  planning separate from materialized Bitcoin transactions and authorization collection.
- Bitcoin `taproot.rs` → `taproot/{mod,tree,leaf}.rs`,
  `scripts/{action,reveal,timeout}.rs`, and `showdown/{mod,script,witness}.rs`.
- Relay `lib.rs` → thin assembly plus `routes/`, `assets.rs`, `auth.rs`,
  `config.rs`, and `store.rs`.
- Ports `lib.rs` → `chain.rs`, `wallet.rs`, `session.rs`, `transport.rs`, with
  deployment configuration separated from backend contracts.
- Funding implementation → `escrow.rs`, `deposit.rs`, `refund.rs`, and
  `activation.rs`. Audit cooperative-close helpers and keep any deliberate
  experiment outside the default on-chain path.
- Protocol certificate code → `envelope.rs` and `certificate/{codec,verify}.rs`;
  preserve construction guarantees and canonical framing.
- Dlog Wasm → `abi.rs`, `participant.rs`, and separate benchmark exports/tooling.
  Keep secret ownership in the appropriate module; splitting files must not
  share or duplicate live secret state.

## Naming conventions

- Rust package directories: kebab-case, exactly matching the package name;
  Rust source files/modules: snake_case.
- JS modules: kebab-case `.js`; unit tests: adjacent `<name>.test.mjs`;
  standalone Node commands: descriptive `.mjs` filenames.
- Markdown: lowercase kebab-case except conventional `README.md` and
  `SECURITY.md`. Use subject names, not `AGENT_HANDOFF`, `LIVE_RELEASE_STATE`,
  or generic `implementation` files scattered across workspaces.
- Reserve `main`, `index`, `lib`, and `mod` for entry points. Avoid new
  `utils`, `common`, `misc`, `helpers`, or catch-all `runtime` files.
- Use domain verbs: `build`, `encode`, `decode`, `verify`, `sign`, `observe`,
  `broadcast`, `restore`. Prefer names that state the operation's result.
- Use specific preparation errors for malformed snapshots, missing responses,
  and conflicting duplicates instead of reporting every case as `DealMismatch`.
- Keep `Alice` and `Bob` for canonical cryptographic roles. Distinguish them
  from `local`, `opponent`, button, and seat position.

## Dependency and ownership rules

1. Protocol primitives, codecs, and poker evaluation do not depend on browser,
   networking, persistence, or application crates.
2. Settlement types are shared by Bitcoin construction and graph planning;
   neither introduces a reverse dependency through the types crate.
3. The settlement compiler consumes verified dlog results. It does not perform
   network requests, own a browser, or choose deployment configuration.
4. Ports define backend contracts; Esplora, SQLite, and libp2p implement them.
   Do not force distinct transaction publishing contracts together solely
   because their names are similar. Consolidate them only if identity,
   transaction representation, and error semantics really agree.
5. Wasm crates are bindings to Rust capabilities. The relay delivers assets
   and opaque messages; it does not become the owner of poker correctness.
6. Application modes and diagnostic tools depend on these libraries. Shared
   libraries never depend on a demo or practice application.

Audit unused dependencies after the moves. Compare the two codec crates and
consolidate genuinely identical primitives with byte-equivalence tests; keep
protocol-specific limits and encodings explicit. Avoid merging cryptographic
crates just to reduce the directory count.

## Ordered implementation

### 1. Establish an honest baseline

- Land the already-tested legacy deletion as its own change before structural
  refactoring; retain the external backup of prior uncommitted legacy edits.
- Record the current native, browser, Wasm, and Core qualification results.
- Inventory public exports, browser URLs, protocol identifiers, encoded
  artifacts, storage schemas, and deployment assumptions.
- Correct stale documentation claims and explicitly retire the old funded
  profile. Do not silently copy regtest fee values into MutinyNet configuration.

Done when supported behavior, removed behavior, and unfinished MVP work are
unambiguous, and there is a reproducible comparison baseline.

### 2. Consolidate workspace and build configuration

- Introduce the root workspace using the existing package paths first.
- Merge lockfiles, shared dependency declarations, lints, and release settings;
  preserve dependency versions and inspect feature-unification changes.
- Use the existing qualified build toolchain as the root development pin;
  retain the declared MSRV as a separate check instead of confusing the two.
- Preserve artifact-specific Wasm builds, compiler flags, and the dlog stack
  setting currently scoped under `dealing-dlog/.cargo/config.toml`.
- Remove the four redundant workspace manifests/configurations only after the
  root commands work from a fresh checkout.

Done when one root Cargo invocation addresses every Rust package and each Wasm
artifact still builds through its intended boundary.

### 3. Move directories and rename packages

- Apply the target tree and package map in small, reviewable groups.
- Update manifests, imports, fixture paths, `include_str!`/`include_bytes!`,
  Docker working directories, CI paths, and browser asset packaging together.
- Move diagnostics and scripted examples out of application/library surfaces.
- Keep source moves separate from logic changes; do not leave compatibility
  directory trees, duplicate files, or forwarding crates behind.

Done when every source file has one owner and the old application-based roots
are no longer referenced by builds, docs, or CI.

### 4. Rename APIs and split oversized modules

- Apply the symbol map, then remove single-protocol variant scaffolding.
- Extract coherent modules while keeping public re-exports stable within each
  intermediate change where useful. Remove temporary re-exports afterward.
- Improve documentation of readiness, verification, snapshot durability, and
  witness/profile limits while touching those APIs.

Done when source names describe the current dlog system and module boundaries
make planning, authorization, transactions, and application state easy to find.

### 5. Remove remaining duplication and stale contracts

- Remove unused wrappers/dependencies after checking workspace callers.
- Consolidate shared codec primitives only with unchanged encoding evidence.
- Make deployment config authoritative in one location and derive profile
  responses from the supported Rust contract. Handle economic/profile changes
  separately from the mechanical cleanup.
- Replace hardcoded funding contribution/reserve constants with validated
  `FundingTerms` derived from the selected graph budget in that semantic change.
- Remove dormant funded controls from the practice HTML. Use the shared
  manifest-aware Wasm loader instead of parallel loading paths.
- Put cooperative-close and practice-only behavior behind explicit ownership;
  do not wire it into Milestone 1 as part of a cleanup.

Done when there is one implementation per actual responsibility and no dormant
legacy funded profile masquerades as the current dlog deployment contract.

### 6. Finish documentation and development checks

- Fold handoff/status documents into `docs/status.md`, preserving useful
  protocol specifications, measured evidence, and unresolved questions.
- Rewrite the stale browser boundary document against actual retained modules.
- Provide root commands for formatting, linting/docs, native tests, browser
  tests, artifact checks/builds, and isolated Core qualification.
- Reduce CI duplication to explicit fast, Wasm, and Bitcoin Core lanes, with
  MSRV compatibility checked consistently across the relevant packages.
- Rename `check-source-integrity.sh` to `check-workspace.sh` if it remains a
  dependency-metadata check; retain a separate accurately named archive check.

Done when a new contributor can find the architecture, run the checks, and
locate the correct extension point without reading old handoff narratives.

## Compatibility and validation

This cleanup should preserve current protocol behavior. Package/file/source
names may change; cryptographic domain tags, wire magic, encoded discriminants,
hash inputs, canonical ordering, role assignment, signatures, graph commitments,
and transaction/witness serialization must remain stable unless a separate
versioned change explicitly requires otherwise.

Likewise, treat exported Wasm symbols, worker RPC commands, persisted JSON,
SQLite tables, browser storage keys, and public routes as interfaces. Do not
globally replace `bp52`/`dlog52` strings. Either retain an interface name or make
its migration/reset policy explicit in a separate change. No backward readers
for the deleted hash-based protocol are needed.

Qualification should cover:

- Root formatting, linting, documentation, and the consolidated native suite.
- Existing canonical vectors plus targeted before/after byte comparisons for
  any codec, script, witness, or graph refactor. Preserve the full reference
  topology and accounting invariants, including the 56,132-node fixture.
- Individual Wasm compilation, export/size validation, artifact hashes updated
  only from real builds, and the real two-participant worker test.
- Browser imports, worker URLs, static assets, practice flow, and removed-route
  regression tests after asset moves.
- Core gate/reveal tests, showdown/payout cases, and a fully prepared short-stack
  hand including observed openings, restored authorizations, and timeout checks.
- A fresh-checkout build and no references to removed source paths. Historical
  and protocol identifiers are exempt from a crude string-zero requirement.

Run checks appropriate to each commit. Repeat the complete qualification at
the end; do not invent rename-only tests or repeat expensive campaigns after
documentation-only edits.

The cleanup is complete when this structure is real, names describe their
contracts, duplicate configuration is gone, supported paths remain qualified,
and the next funded on-chain browser milestone has an obvious home. It does
not itself complete or deploy that milestone.
