export function transactionKind(view, action) {
  if (action?.timeoutHeight != null) return "timeout";
  if (!view?.tip) return "activation";
  if (view.betting) return "move";
  if (view.revealing || /Reveal|DealAlice|DealBob|Hole|Flop|Turn|River/i.test(view.phase ?? "")) return "reveal";
  return "showdown";
}
export function dealingTitle(view) {
  const phase = view?.phase ?? "";
  if (/DealAlice|DealBob/.test(phase)) return "Dealing hole cards…";
  if (/Flop/.test(phase)) return "Dealing flop…";
  if (/Turn/.test(phase)) return "Dealing turn card…";
  if (/River/.test(phase)) return "Dealing river card…";
  return "Dealing cards…";
}
export function confirmationTitle(kind, view) {
  return {
    move: "Playing your move…",
    reveal: dealingTitle(view),
    activation: "Starting the hand…",
    timeout: "Finishing the hand…",
    showdown: "Showdown…",
  }[kind] ?? "Updating the table…";
}
export function actionSubmission(view, edge) {
  const action = view?.actions?.find(candidate => candidate.index === edge);
  const roundBets = [...(view?.roundBets ?? [0, 0])];
  if (action?.betAmount) roundBets[view.role] += action.betAmount;
  return { node: view?.node, kind: transactionKind(view, action), roundBets };
}
export function confirmedRoundBets(view, data) {
  if (view?.terminal) return [0, 0];
  // Blinds are already deducted during hole-card delivery, before the
  // engine enters a betting state and exposes street commitments.
  if (view?.tip && /^Some\(Deal(Alice|Bob)\)$/.test(view.phase ?? "") && view.stacks) {
    const starting = data.terms?.stacks ?? [20000, 20000];
    const blinds = starting.map((amount, role) => amount - view.stacks[role]);
    if (blinds.every(amount => amount >= 0) && blinds[0] + blinds[1] === view.pot)
      return blinds;
  }
  return view?.roundBets ?? [0, 0];
}

export function tableFeedback({ data, view, busy, submission }) {
  if (submission?.node !== view?.node) submission = null;
  const pending = data.pending || view?.pendingMove || view?.pending;
  const kind = submission?.kind ?? data.pendingInfo?.kind ?? transactionKind(view);
  const sending = !!submission || (busy && view?.betting && !pending);
  return {
    active: sending || !!pending,
    title: sending ? {
      move: "Sending your move…", reveal: dealingTitle(view),
      activation: "Starting the hand…", timeout: "Finishing the hand…",
      showdown: "Preparing showdown…",
    }[kind] : confirmationTitle(kind, view),
    detail: "",
    roundBets: view?.terminal ? [0, 0] : /^Some\(Deal(Alice|Bob)\)$/.test(view?.phase ?? "") ? confirmedRoundBets(view, data) : submission?.roundBets ?? (pending ? data.pendingInfo?.roundBets : undefined) ?? view?.roundBets ?? [0, 0],
  };
}

// Translate internal session stages at the presentation boundary.
export function idleFeedback({ data, view, stage, progress, busyAction, hasFundingWallet }) {
  if (data.walletNeeded) return {title:data.walletSeparatePayment ? "Send another payment to this wallet" : "Waiting for wallet funds",detail:""};
  if (data.continuation && hasFundingWallet && !data.proposal) return { title: "Starting the next hand…", detail: "" };
  if (busyAction === "next-hand") return { title: "Getting ready…", detail: "Getting ready for the next hand…" };
  if (busyAction === "fund") return { title: "Adding funds…", detail: "" };
  if (data.returned) return { title: "Funds returned", detail: "You can leave the table." };
  if (stage === "Waiting for your opponent’s buy-in") return {title:stage,detail:""};
  if (view?.terminal) return { detail: data.sitOutNext ? "Sitting out" : stage === 'Preparing the next hand' ? 'Dealing next hand…' : stage === 'Shuffling together' ? 'Dealing next hand…' : data.wantsNext ? "Waiting for your opponent…" : "" };
  if (view?.tip && !view.betting) return {
    title: transactionKind(view) === "reveal" ? dealingTitle(view) : "Showdown…",
    detail: "",
  };
  if (view?.betting) return {
    title: view.actor === view.role ? "Your turn" : "Opponent’s turn",
    detail: view.actor === view.role ? "Choose your move below." : "Waiting for your opponent to play.",
  };
  const titles = {
    "Connecting": "Joining the table…",
    "Connecting the next hand": "Starting the next hand…",
    "Preparing table funding": "Adding funds…",
    "Waiting for your opponent": "Waiting for your opponent",
    "Fund the table": "Preparing your buy-in…",
    "Waiting for the host to fund the table": "Waiting for the host to add funds",
    "Saving the funding return": "Getting the table ready…",
    "Carrying both payouts into the next hand": "Dealing next hand…",
    "Waiting for returned funds": "Cashing out…",
    "Waiting for table funding confirmation": "Adding funds…",
    "Shuffling together": "Dealing next hand…",
    "Preparing the full game": "Getting the table ready…",
    "Waiting for your opponent’s preparation": "Waiting for your opponent’s table to be ready",
    "Starting the funded hand": "Dealing the hand…",
    "Connection paused — retrying": "Reconnecting…",
    "Transaction confirmed": "Getting the table ready…",
    "Card reveal confirmed": "Dealing cards…",
  };
  return { title: titles[stage] ?? "Getting the table ready…", detail: "" };
}

export function playerError(message, inGame = true) {
  if (/Wasm (artifact|manifest) (request failed|failed manifest verification|Content-Length)/i.test(message)) return "A required app file couldn’t load. Reload this tab and reconnect.";
  if (/QuotaExceeded|quota.*exceed/i.test(message)) return "Browser storage is full. Free up disk space, then reconnect.";
  if (/Player already active|seat is open in another tab/i.test(message)) return "This seat is open in another tab. Close that tab, then reconnect here.";
  if (/Paste a valid table invitation|Invalid.*invit/i.test(message)) return "That invite link doesn’t look right. Ask the host for a new one.";
  if (/32-byte.*key|private key|invalid.*key|Invalid hex/i.test(message)) return "Check the wallet’s private key and try again.";
  if (/^This wallet needs|^Wait for your opponent|^Both players need|^Network fees exceed/.test(message)) return message;
  if (/cached engine|Wasm engine/i.test(message)) return "This saved game needs an older app version. Open it in the browser where you started it.";
  if (/below.*minimum|at least.*200|busted/i.test(message)) return "A player needs more funds. Leave this table and start a new one.";
  if (/different|changed|mismatch|wrong|invalid.*signature|does not match/i.test(message)) return "The game could not be verified. Play is paused. Try reconnecting.";
  if (/fetch|network|connect|timeout|HTTP|Relay [45]/i.test(message)) return "Can’t reach the table. Check your connection and try reconnecting.";
  return inGame ? "Something went wrong. Try reconnecting to the table." : "Couldn’t open the table. Try again, or check your invite link.";
}

// Activity is attached to the affected game objects, never to a player's thinking time.
export function tableActivity({data, view, submission, error}) {
  const activity = {local: false, opponent: false, hole: false, board: []};
  if (error || data.left || data.leaveRequested || data.walletNeeded) return activity;
  const pending = !!(submission || view?.pendingMove || view?.pending || data.pending);
  if (view?.betting && !view.terminal) {
    activity.local = pending;
    activity.opponent = !!view.pendingMove && !submission;
    return activity;
  }
  if (view?.terminal) return activity;
  const phase = view?.phase ?? '';
  const end = /Flop/.test(phase) ? 3 : /Turn/.test(phase) ? 4 : /River/.test(phase) ? 5 : 0;
  if (end) {
    for (let i = 0; i < end; i++) if (view?.board?.[i] == null) activity.board.push(i);
  } else if (!view?.holeCards?.some(c => c != null)) {
    activity.hole = !!data.peer.profile || !!data.peer.keys || data.sender === 'bob';
  }
  return activity;
}
