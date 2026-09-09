# Worker recovery and CPU budget — September 8, 2026

The supplied browser logs show a construction worker failing in Bob's browser
at 22:45:54.427 UTC. Its error was reduced to `Error`. Alice's preparation then
timed out at 22:49:00.985 UTC, and both tables stopped when that failed candidate
was needed. The logs do not preserve the underlying browser worker error, so
they cannot establish whether its cause was a missing module or a runtime crash.

Changes:

- Worker error events retain the script name and browser message. For versioned
  worker URLs, a bounded HEAD probe distinguishes an unavailable app file and
  requests a page reload. No replacement version is loaded into an active
  session, and no schemas or recovery data are migrated.
- A handled child-worker error is canceled at its worker boundary so it cannot
  also bubble into the parent as a second, empty browser error.
- Worker crashes reopen the same encrypted checkpoint with one crypto worker
  per owner. Three consecutive failures pause the retry. Cryptographic and
  protocol validation errors still stop immediately.
- A background candidate that is already retrying remains pending; its parent
  no longer repeatedly reinitializes itself because of that candidate's error.
- Foreground crypto pools share a budget derived from reported logical cores
  minus two, with memory caps. Background pools use half that budget. There are
  always two owner contexts; low-core devices use one worker each. On this host,
  Chrome reports 15 logical cores and 16 GiB: foreground increases from eight to
  twelve workers per player, background from four to six. Recovery reduces that
  to two total. New diagnostics report the selected budget.
- Once successor authorization and its redirect are durable, retired-hand
  compaction runs in the old worker while the successor starts. The old lock is
  retained through cleanup and the worker closes afterward. Interrupted cleanup
  remains eligible for the existing startup retry.

Measurements in two isolated Chrome contexts on the same physical machine:

| Local synthetic setup | Dealer | Preparation | Total |
| --- | ---: | ---: | ---: |
| Existing eight-worker budget | 2.70 s | 6.45 s | 9.15 s |
| Core-scaled budget, trial 1 | 2.44 s | 6.44 s | 8.88 s |
| Core-scaled budget, trial 2 | 4.57 s | 6.22 s | 10.79 s |

The second scaled trial needed three dealer attempts; the other two needed one.
This small sample shows modest preparation improvement, not a large speedup or
a sub-ten-second guarantee. Both simulated players contend for the same physical
CPU. In a subsequent normal three-hand funded run, redeal-to-action took
4.60 / 4.57 seconds and retired-hand cleanup took 17–26 ms. Cleanup therefore
does not explain the multi-minute wait in the supplied logs.

168 browser contract tests passed. A real Chrome check of a missing versioned
worker module returned the explicit reload instruction and terminated its worker.
The normal funded runs completed three hands, preserved retired-hand defenses,
and confirmed the exact saved cashout after disconnect/reconnect.

The deterministic crash test uses a local HTTP/WebSocket proxy because nested
Chromium worker loads bypassed Playwright route interception. Its injected
worker code counts executions in a separate test-only IndexedDB store and fails
the third construction execution once per browser. The test must assert the
injected error was observed, not merely that games finished. Initial attempts
whose injection did not execute are not counted as crash qualifications.

```sh
PLAYWRIGHT_MODULE=/path/to/playwright node tools/playable-e2e.mjs \
  --funded --origin=http://127.0.0.1:3102 --hands=3 --crash-construction \
  --verify-retired-storage --cashout-reconnect \
  --keys-file=/private/path/wallets.keys --output=/private/tmp/worker-recovery-e2e
```

The proxy and injection are test tools only. Profiles, private keys and recovery
packages are retained privately and are never uploaded with this change.

Final qualification: both browsers observed the injected worker crash, recovered
with the reduced worker budget, and completed two hands with zero uncaught
browser errors. Cashout reconnect preserved the exact transaction and confirmed
in 30,957 ms. The final storage enumeration raced deletion of an obsolete
snapshot; that test helper now tolerates deleted rows and rereads current keys.
The remaining assertions were rerun against isolated copies of the completed
profiles: both had confirmed cashout, one compacted parent each, and intact
whole-hand defenses. The separate post-run qualification passed without changing
the original profiles or hiding the original test-helper failure.
