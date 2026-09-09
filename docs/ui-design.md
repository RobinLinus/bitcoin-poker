# Poker table UX

The table should behave like physical cards and chips. Players should understand
what is happening from the objects on the table, without protocol explanations.

- Cards belong to one hand. Collect both players’ hole cards and the community
  cards as soon as cashout starts; keep them cleared after cashout completes.
  Show the cashout status prominently in the center of the cleared table. Once
  the payout is confirmed, return automatically to the lobby and
  refresh the wallet balance; do not require a second “Back to lobby” click.
- Between consecutive hands, allow a brief look at the previous hand after the
  pot is distributed. Start preparation in the background without a label over the old hand.
  Collect the old cards after about 3.5 seconds, then show “Dealing next hand…”
  prominently in the center. Keep “Dealing next hand…” throughout preparation;
  do not switch back to a shuffling label. Background preparation can run during
  this review period; it must not reveal future cards or delay a ready hand.
- Keep both seats free of cards while shuffling. Card backs represent cards
  already dealt to a player; they are not placeholders before a hand. Show faces
  only when revealed. Animate only the
  card slots currently being dealt. Stop their loading effect once cards arrive.
- Put processing feedback on the relevant seat. A player thinking about a move
  gets the active-seat highlight, not a processing spinner. Seat spinners only
  indicate player actions being processed. Dealing and next-hand preparation
  belong to the dealer: use card animations or the central progress indicator,
  and leave both player spinners off.
- Chips stay in front of their owner until collected into the pot, and travel
  only to the recipient during payout. Never visually count chips twice.
- Keep names, balances, cards, bets, and the pot readable. Routine progress must
  not cover them. Reserve prominent messages for errors, required actions, and
  cashout; keep poker actions equally emphasized and hide unavailable actions.
- Animations communicate state, not decoration. Loops must be seamless, state
  changes must respond immediately, and reduced-motion preferences must be
  respected. Clear obsolete animation and transition state when a new hand starts.

## Consistency

- Every centered loading status uses the same panel as “Reconnecting…”: shared
  width, background, border, padding, typography, and an indeterminate
  `.progress-indicator` beneath the title. This includes initial shuffling,
  dealing the next hand after the old cards clear, and cashout.
- Change the message, not its visual treatment. Do not add a larger headline,
  bare floating label, different spinner, or phase-specific panel styling.
- Keep labels brief, in sentence case, with the same ellipsis character (…).
  Use the same words for the same state throughout the app.
- Keep card/seat activity during live play separate from centered loading states.
  Errors and required user actions use consistent panel styling, but do not
  imply ongoing work with an indeterminate bar when processing has stopped.

## Public and private tables

- “Play now” is the primary lobby action. Show the buy-in before the click;
  “Create private table” is secondary.
- While matching, show the local seat and “Finding an opponent…” using the shared
  centered progress panel with a Cancel action. Keep cards and seat activity
  rings absent. Never ask a public player to share an invite.
- Show the opponent as soon as the pair is assigned, then continue into the normal
  dealing flow. Matched players stay together across hands until someone leaves.
- Restore matchmaking directly on refresh. Do not briefly show the lobby or
  create another waiting room. Never replace an opponent inside a funded table.

- Never pair two windows using the same wallet. Matchmaking identity follows the
  wallet, not a randomly generated browser or tab identity.
