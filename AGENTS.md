# Project preferences

- This software has never been published. Backward compatibility is not required: do not preserve old protocols, saved hands, schemas, or Wasm engines just for compatibility. Replace obsolete paths directly; development sessions can be discarded and recreated.

- Use BIP-177 amounts everywhere in player-facing UI: display integer base units with the Bitcoin symbol, e.g. ₿100 or ₿20,000. Never label amounts “sats” or “satoshis,” and never divide these integers by 100,000,000 for display. Use `apps/web/src/ui/bitcoin-amount.js` for amounts and fee rates. Use “funds” in the player-facing app, with the same copy as mainnet. Do not add test-funds, test-wallet, test-game, faucet, or MutinyNet qualifiers to the lobby, wallet, or table.
- Keep the poker table focused on play. Blinds are secondary information: show them as a small label near the upper-right corner. Put protocol diagnostics in collapsed details, not prominent game messages.
- Keep status copy brief. Do not add redundant explanations or unsolicited reassurance such as “You don’t need to submit it again.” Show a short action status; add detail only when the player needs it to make a decision or take a next step.
- Every user action must give visible feedback immediately, before awaiting polling, storage, cryptography, or network work. Clear busy states on failure and prevent duplicate submissions.
- Always rebuild the client after UI changes. The relay embeds web assets, so run `cargo build -p poker-relay --offline`, restart the running local relay with its existing configuration, and verify the served assets. Rebuild browser Wasm too when its Rust source changes. Do not report changes as live until the running app serves them.

- Use familiar poker visuals instead of explanatory labels: a round D dealer button, chip amounts without “This round,” and seat balances without “Stack.” Do not show routine presence labels such as “At the table.”

- Claim eligible opponent timeouts automatically while the table is running; do not expose a “Claim win” button. Check confirmed activity and pending submissions before attempting a timeout.

- Deal consecutive hands automatically, with a left-side “Sit out next hand” checkbox. Continuously prepare a bounded buffer of future hands in background workers while the current hand is active. Keep future cards hidden. Prepare balance-independent internal transactions and signatures using unique hand/path contexts. Bind exact settled balances into every payout (including folds and timeouts) before releasing funding-root signatures. Short-stack topology changes require exact preparation.

- Keep seats on the rail of a wide, shallow table, with hole cards above each nameplate and wagers in front of their owners. Highlight the active seat, use large centered card ranks and suits without redundant corner labels, and respect reduced motion for chip animations. Show exact supported bet amounts in action buttons; do not offer unsupported bet sizing.

- Chip colors represent denominations, never player identity. Equal amounts must render identical chip stacks for either seat and the pot.

- Give all available poker actions equal visual emphasis. Use the same neutral button styling for Fold, Check, Call, Bet, and Raise; never highlight a wager as the preferred choice.

- Reserve clear felt between the board, wagers, and hole cards at every viewport width. Bet chips, amounts, and pending status must never overlap cards.

- Show poker action buttons only when the local player can act, and only for legal choices. Hide them while waiting or submitting; retain the action area’s dimensions for status overlays and stable layout.

- Consecutive hands continue without a funding confirmation. Generate the player wallet key locally and persist it in localStorage; no backup or key-entry popup. Each player funds their own buy-in, receives change in their wallet, and cashes out to it when leaving. Lock only the stakes and required fee reserve; use transaction-sized fees and keep all other funds in the wallet.

- The center pot displays only collected chips, excluding current-round wagers still in front of players. Do not count optimistic pending wagers against the confirmed pot. Hide an empty center pot.

- Hide the branding/network header during table play and reclaim its vertical space. Keep the header in the lobby.

- Wagers show only chips and amounts. Do not add Sending/Confirming labels beside them; action progress belongs in the action area.

- MutinyNet nodes use minrelaytxfee=0.00000100 BTC/kvB. Use 0.1 ₿/vB for new table and wallet transactions; round the final fee up to an integer, never round the fee rate up to 1.

- Do not show a hand-number or network-status badge in the lobby header.

- Keep the action area for actionable buttons. Routine table activity belongs on seats and cards; use a centered popup for cashout, errors, or required actions.

- The server is a transient opaque message relay. Never persist games or recovery packages on the server, or run server-side recovery monitoring. Browsers persist their own history and recovery data and execute recovery while the app is open; players are responsible for staying online.

- For SSH deployment of the hosted app, follow [deployments/ec2/README.md](deployments/ec2/README.md). It records the server, upload/build/restart procedure, verification, and rollback. Review concurrent changes before uploading; never deploy unrelated work from the shared checkout.

- Outside table play, use the shared `.progress-indicator` component for progress UI. Its only two variants are indeterminate (no `value`) and determinate (`value`/`max`). Do not introduce native unstyled bars or per-screen indicator designs. Table activity follows the seat/card rules below. Respect reduced motion for both variants.

- During table play, show processing with a shared activity ring around the relevant avatar and dealing with a shared shimmer on the specific unrevealed cards. Do not animate an opponent merely for thinking. Keep the previous hand readable for about three seconds after payout during next-hand preparation, then collect its cards. Clear all cards immediately when cashout starts. Routine table loading uses these object-level indicators instead of labels, bars, or overlays; retain text for errors and required actions. Outside table play, retain the shared progress-indicator variants. Respect reduced motion throughout.

- Follow [docs/ui-design.md](docs/ui-design.md) for physical-card/chip behavior, hand transitions, and table feedback.

- Centered loading labels (reconnecting, shuffling, next-hand dealing, cashout) must all use the reconnecting panel design and shared indeterminate progress bar. Reuse its typography, spacing, border, and background; never create phase-specific centered label designs. Errors and required actions do not show fake ongoing progress.
