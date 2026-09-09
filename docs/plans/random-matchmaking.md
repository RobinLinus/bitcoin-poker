# One-click public matchmaking

Status: implemented and deployed to https://poker.bitvm.org/ on September 8, 2026. Verified locally and on the hosted app with isolated wallet/session fixtures.

## Product flow

- Keep nickname and wallet onboarding. Preserve a pending invite or matchmaking
  intent through onboarding, without flashing the lobby.
- Make **Play now** the primary lobby action. Show fixed-limit hold’em and the
  current ₿20,000 buy-in clearly before the click. Keep **Create private table**
  as a secondary action; its invite flow remains available.
- Play now immediately opens the table with the local seat and a centered
  **Finding an opponent…** panel using the shared indeterminate progress bar.
  Keep cards absent and player activity rings off. Provide **Cancel**.
- Atomically join an eligible waiting public table, or create and occupy a new
  public table if none exists. Use the oldest eligible waiting table by default;
  “random” means an unknown opponent, with no skill/rating system for this scope.
- Once paired, show the opponent's name immediately and automatically enter the
  existing setup/dealing flow. No invite popup or additional confirmation.
- Confirmed session policy: the same pair continues playing consecutive hands
  until someone leaves. Do not silently refill a funded table; finish cashout
  and let the remaining player choose Play now again.

## Relay changes

Extend the existing in-memory room store and socket notifications. Matchmaking
adds temporary discovery and seat allocation, not poker logic or persistence.

1. Add a matchmaking module and authenticated operations to enter, read/resume,
   renew and cancel a ticket. A client-generated secret authorizes the ticket;
   retries with the same ticket return the same assignment.
2. Track public/private visibility explicitly. Existing create/invite operations
   create private tables; only matchmaking adds public waiting entries.
3. In one transaction, find a live compatible waiting entry and claim its guest
   seat, or create a waiting room with the caller as host. Bind both seat
   capabilities and the assignment atomically. Never expose a room list or hand
   the guest the host's player token. Return only credentials needed by that seat.
4. Partition eligibility by the exact game terms/protocol configuration. Start
   with the one supported stake level; do not add stake selection in this change.
5. Remove matched rooms from discovery immediately. Push assignment changes using
   the existing socket connection, with an authenticated status fallback for
   missed events or reconnects.
6. Give waiting entries a short renewable lease. Ignore expired/disconnected
   entries; cap queue entries and request rate. Cancellation and matching must
   serialize: an entry cannot be both cancelled and assigned. If cancellation
   arrives after assignment, return the assignment and use the explicit pre-fund
   withdrawal or existing cashout flow as appropriate.

## Browser integration

- Add a small matchmaking client to manage the ticket, lease and socket updates.
  Save its opaque identity locally before sending the first request, so a lost
  response or refresh does not create a second waiting seat.
- Refactor TableSession's create/join initialization into a shared path accepting
  an assigned game ID, role and seat credentials. Public and private tables then
  use the same poker, funding, reconnect, automatic redeal and cashout code.
- Track explicit entry states: onboarding, matching, matched/setup, playing,
  cancelling, and error. Prevent duplicate clicks and coordinate the same ticket
  across tabs. Derive the matchmaking identity from the public wallet script so
  the same wallet cannot occupy both seats, including across browser profiles.
  Separate wallets cannot be identified as the same person without accounts.
- Check wallet availability against the required buy-in and fee reserve, not
  merely a positive balance. Keep funds in the wallet while waiting; start actual
  buy-in funding only after both peers are assigned and ready. Reuse exact fee
  and coin-selection calculations from the existing funding path.
- Resume assigned tables using the existing browser recovery flow. A waiting
  ticket lost on relay restart may re-enter matchmaking only if it was never
  assigned or funded. Do not put a player with an uncertain funded session into
  another table automatically. Reconcile ambiguous assignments before retrying.
- A pre-funding disconnect should release/requeue the surviving willing player
  once the old assignment is invalidated. After funding starts, use existing
  recovery/cashout; never substitute a new opponent into that contract.

## Validation and rollout

- Relay tests: simultaneous callers produce pairs with at most one waiting room;
  no duplicate guest claims; retries return one assignment; private/full/expired
  rooms are excluded; unauthorized ticket access fails; cancel-versus-match,
  lease renewal, reconnect, and restart races are handled.
- Browser checks: one click into an existing room or a new waiting table; prompt
  host notification; no lobby flash, invite popup, undealt cards or player rings
  while matching; cancellation, refresh, duplicate tabs and insufficient funds.
- Verify both public and private paths through multiple hands and cashout using
  isolated test wallets/fixtures. Ensure waiting alone never broadcasts funding.
- Implement relay allocation first, then browser/session integration, then lobby
  presentation. Update architecture, API/deployment notes and the UI design guide.
- Rebuild the client and embedded relay, restart locally with its existing
  configuration, and verify served assets. Review the shared checkout and deploy
  only the intended changes following deployments/ec2/README.md.

## Implemented details

- `POST /api/v1/matchmaking` accepts an opaque ticket, wallet ID, proposed
  room/seat credentials and `enter`, `poll`, or `cancel`. Polling holds the request
  for up to 15 seconds and wakes immediately on relay notifications.
- Waiting seats have 45-second renewable leases. A reserved pair must be
  acknowledged by both browsers before becoming matched. Cancelling a reservation
  expires the other ticket so that browser can seek another match. A committed
  match wins a late cancellation; the browser preserves and opens that assignment.
- Discovery uses only matchmaking entries for the current single supported game
  configuration. Private rooms have no queue entry. Multiple stake pools are not
  exposed by this version.
- Browser ticket storage and the Web Locks API prevent duplicate waiting requests.
  An active public table pointer sends returning players back to that table until
  cashout completes. Nothing is funded while waiting in matchmaking.
- The reserve precheck uses the existing Wasm sizing calculation and the same
  buy-in requirement formula as table funding. Funding still verifies exact peer
  terms and actual inputs before any broadcast.
