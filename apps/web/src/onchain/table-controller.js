import { localWallet } from "./local-wallet.js";
import { appUpdateAvailable } from "../wasm/loader.js";
import { renderCard, highlightTurn, animateChips, renderChipStack, renderPlayerNames, playerName, savedPlayerName } from "../practice/render-table.js";
import { formatBitcoinAmount } from "../ui/bitcoin-amount.js";
import { tableFeedback, tableActivity, idleFeedback, playerError, confirmedRoundBets } from "./table-feedback.js";
import { TableSession, parseInvite, inviteUrl } from "./table-session.js";
const nickname = () => playerName(document.getElementById("nickname").value) || savedPlayerName();
const $ = (id) => document.getElementById(id);
let session, config, last, walletPromptShown = false, starting = false, autoInviteAttempt = null;
document.body.classList.add("onchain-table");
if (!location.hash.startsWith("#/table/")) document.body.classList.add("wallet-onboarding", "wallet-checking");
document.querySelector(".poker-table").append($("table-message"));
const nextHandLabel = document.createElement("div");
nextHandLabel.className = "next-hand-label hidden";
const nextHandTitle = document.createElement("h2");
const nextHandProgress = document.createElement("progress");
nextHandProgress.className = "progress-indicator";
nextHandProgress.setAttribute("aria-label", "Preparing hand");
nextHandLabel.append(nextHandTitle, nextHandProgress);
nextHandLabel.setAttribute("role", "status");
document.querySelector(".poker-table").append(nextHandLabel);
let nextHandTransition = null;
function renderNextHandTransition(state) {
  const {data, view} = state;
  const eligible = view?.terminal && data.wantsNext && !data.sitOutNext && !data.leaveRequested && !data.cashout && !view?.cashoutStarted && !data.left && !state.error;
  const key = eligible ? `${data.gameId}/${view.hand}/${view.node}` : null;
  if (nextHandTransition?.key !== key) {
    for (const timer of nextHandTransition?.timers ?? []) clearTimeout(timer);
    nextHandTransition = key ? {key, started: performance.now(), timers: []} : null;
    if (nextHandTransition) {
      const current = nextHandTransition;
      for (const delay of [3450]) current.timers.push(setTimeout(() => {
        if (nextHandTransition === current && last) render(last);
      }, delay));
    }
  }
  const elapsed = nextHandTransition ? performance.now() - nextHandTransition.started : 0;
  const settingUp = !view?.terminal && !view?.betting && !view?.holeCards?.some(c => c != null) &&
    !view?.board?.some(c => c != null) && !!(data.peer.profile || data.peer.keys || data.sender === "bob") &&
    !data.walletNeeded && !data.leaveRequested && !data.cashout && !view?.cashoutStarted && !data.left && !state.error;
  // Card backs represent dealt cards, not empty seats or a deck being prepared.
  const cardsNotDealt = !view?.terminal && !view?.betting &&
    !view?.holeCards?.some(c => c != null) && !view?.board?.some(c => c != null);
  document.querySelector(".poker-table").classList.toggle("cards-not-dealt", cardsNotDealt);
  nextHandLabel.classList.toggle("initial-hand-status", settingUp);
  nextHandTitle.textContent = "Dealing next hand…";
  nextHandLabel.classList.toggle("hidden", !settingUp && (!eligible || elapsed < 3450));
  document.querySelector(".poker-table").classList.toggle("previous-cards-cleared", !!eligible && elapsed >= 3450);
}

function visible(id, show) {
  $(id).classList.toggle("hidden", !show);
}
function card(element, id, placeholder = "") {
  if (id === null || id === undefined) {
    delete element.dataset.suit;
    element.replaceChildren();
    element.textContent = placeholder;
    element.classList.remove("dealt", "red");
    element.classList.add("empty");
    element.setAttribute("aria-label", "Card not yet revealed");
    return;
  }
  renderCard(element, id);
}
function outcome(view) {
  const text = view.outcome ?? "";
  const local = view.role === 0 ? "Alice" : "Bob";
  if (text.includes("Split")) return "Split pot";
  if (text.includes("Showdown"))
    return text.includes(`${local}Win`)
      ? "You win the showdown"
      : "Opponent wins the showdown";
  if (text.includes("Fold"))
    return text.includes(local) ? "You folded" : "Opponent folded — you win";
  if (text.includes("Timeout"))
    return text.includes(`defaulting: ${local}`)
      ? "Your turn timed out"
      : "Opponent timed out — you win";
  return "Hand complete";
}
function render(state) {
  session = state.activeSession ?? session;
  last = state;
  const { data, view, error, busy, busyAction } = state;
  if (!data) return;
  renderNextHandTransition(state);
  $("table-message").classList.toggle("cashout-status", !!data.leaveRequested && !data.left);
  document.querySelector(".poker-table").classList.toggle("cards-collected", !!(data.leaveRequested || data.cashout || view?.cashoutStarted || data.left));
  const enteringTable = $("game").classList.contains("hidden");
  document.body.classList.remove("entry-pending");
  visible("lobby", false);
  visible("game", true);
  if (enteringTable) {
    window.scrollTo({ top: 0, left: 0, behavior: "instant" });
    requestAnimationFrame(() => window.scrollTo({ top: 0, left: 0, behavior: "instant" }));
  }
  $("local-avatar").textContent = data.sender === "alice" ? "H" : "G";
  $("opponent-avatar").textContent = data.sender === "alice" ? "G" : "H";
  $("local-name").textContent = "You";
  $("opponent-name").textContent = "Opponent";
  renderPlayerNames(data.playerName, data.peer.profile?.name ?? data.opponentName);
  $("opponent-state").textContent = (data.peer.keys || data.peer.profile)
    ? ""
    : "Waiting to join";
  $("table-small-blind").textContent = formatBitcoinAmount(100);
  $("table-big-blind").textContent = formatBitcoinAmount(200);
  $("share-link").value = inviteUrl(data.gameId, data.inviteSecret);
  visible("invite-card", data.sender === "alice" && !data.peer.keys && !data.peer.profile);
  if (state.walletBalance !== undefined) $("wallet-balance").textContent = formatBitcoinAmount(state.walletBalance);
  if (data.walletNeeded) {
    if (!walletPromptShown) $("wallet-panel").open = true;
    walletPromptShown = true;
    $("wallet-status").textContent = data.walletSeparatePayment
      ? `Send a separate payment of at least ${formatBitcoinAmount(data.walletNeeded)} to this wallet for the second seat.`
      : `Send at least ${formatBitcoinAmount(data.walletNeeded)} to your wallet to join this table.`;
  }
  if (!data.walletNeeded) walletPromptShown = false;
  const pending = data.pending || view?.pending;
  const feedback = tableFeedback(state);
  const idle = idleFeedback(state);
  $("table-phase").textContent = error ? "Play paused" : view?.terminal ? outcome(view) : feedback.active ? feedback.title : idle.title;
  $("table-phase").classList.toggle("busy", (feedback.active || !!busyAction) && !error);
  $("table-detail").textContent = error ? "" : feedback.active ? feedback.detail : idle.detail;
  const shuffling = state.stage === "Shuffling together";
  const preparingNext = state.stage === "Preparing the next hand";
  const starting = state.stage === "Starting the funded hand" || /^Starting the (?:next )?hand/.test(feedback.active ? feedback.title : idle.title ?? "");
  const preparing = ((data.peer.profile && !data.peer.keys) || shuffling || starting || preparingNext || state.stage === "Preparing the full game") && !error && (!view?.betting || view?.terminal) && !data.left;
  $("preparation-title").textContent = starting ? "Starting the hand…" : preparingNext ? "Dealing next hand…" : shuffling ? (view?.terminal ? "Dealing next hand…" : "Dealing next hand…") : "Getting the table ready…";
  visible("table-preparation", preparing);
  const progressBar = $("preparation-progress");
  progressBar.setAttribute("aria-label", starting ? "Starting the hand" : preparingNext ? "Next hand preparation" : shuffling ? "Shuffling the deck" : "Table preparation");
  if (!preparingNext && !shuffling && !starting && state.progress?.total > 0) progressBar.value = Math.max(0, Math.min(100, 100 * state.progress.done / state.progress.total));
  else progressBar.removeAttribute("value");
  visible("table-message", !preparing && !(data.sender === "alice" && !data.peer.keys && !data.peer.profile) && (feedback.active || !view?.betting || !!error));
  visible("game-error", !!error);
  $("game-error").textContent = error ? playerError(error) : "";
  $("game-error-detail").textContent = error ?? "";
  visible("game-error-detail", !!error);
  visible("resume-connection", !!error);
  const stacks = view?.nextStacks ??
      view?.stacks ??
      data.terms?.stacks ??
      data.continuation?.stacks ?? [20000, 20000],
    role = view?.role ?? data.continuation?.role ?? 0;
  const localButton = data.terms
    ? role === (data.terms.button ?? 0)
    : data.continuation && data.continuation.role !== data.continuation.button;
  visible("local-dealer", !!localButton);
  visible("opponent-dealer", !!(data.terms || data.continuation) && !localButton);
  $("local-stack").textContent = formatBitcoinAmount(stacks[role]);
  $("opponent-stack").textContent = formatBitcoinAmount(stacks[1 - role]);
  highlightTurn(view?.betting && !view?.terminal && !pending && !busy ? (view.actor === role ? "local" : "opponent") : null);
  const result = outcome(view ?? {});
  const confirmedBets = confirmedRoundBets(view, data);
  animateChips({hand:data.gameId, bets:[confirmedBets[role], confirmedBets[1-role]], pot:view?.terminal ? 0 : (view?.pot ?? 0), terminal:!!view?.terminal,
    winner:result === "Split pot" ? null : /you win/i.test(result) ? "local" : "opponent"});
  for (const [seat, player] of [["local", role], ["opponent", 1 - role]]) {
    const amount = feedback.roundBets[player] ?? 0;
    renderChipStack($(`${seat}-bet`).querySelector(".chip-stack"), amount);
    visible(`${seat}-bet`, amount > 0);
    $(`${seat}-bet-amount`).textContent = formatBitcoinAmount(amount);
    $(`${seat}-bet`).setAttribute("aria-label", `${seat === "local" ? "Your" : "Opponent’s"} bet this round: ${formatBitcoinAmount(amount)}`);
  }
  for (let i = 0; i < 5; i++)
    card($(`board-card-${i}`), view?.board?.[i]);
  for (let i = 0; i < 2; i++) card($(`hole-card-${i}`), view?.holeCards?.[i]);
  for (let i = 0; i < 2; i++)
    card($(`opponent-card-${i}`), view?.opponentCards?.[i]);
  $("opponent-hole-cards").classList.toggle("face-up", !!view?.opponentCards);
  $("opponent-hole-cards").setAttribute(
    "aria-label",
    view?.opponentCards
      ? "Opponent’s showdown cards"
      : "Opponent cards not shown",
  );
  $("local-hole-cards").classList.toggle(
    "face-up",
    !!view?.holeCards?.some((c) => c !== null),
  );
  document
    .querySelector(".community-cards")
    .setAttribute(
      "aria-label",
      view?.board?.some((c) => c !== null)
        ? "Community cards"
        : "Community cards not dealt",
    );
  $("local-hole-cards").setAttribute("aria-label", "Your hole cards");
  const activity = tableActivity(state);
  for (const seat of ["local", "opponent"]) {
    const avatar = $(`${seat}-avatar`);
    avatar.classList.toggle("processing", !!activity[seat]);
    avatar.setAttribute("aria-busy", String(!!activity[seat]));
  }
  for (let i = 0; i < 5; i++) {
    const loading = activity.board.includes(i);
    $(`board-card-${i}`).classList.toggle("card-loading", loading);
    $(`board-card-${i}`).setAttribute("aria-busy", String(loading));
  }
  for (let i = 0; i < 2; i++) {
    const loading = activity.hole && view?.holeCards?.[i] == null;
    $(`hole-card-${i}`).classList.toggle("card-loading", loading);
    $(`hole-card-${i}`).setAttribute("aria-busy", String(loading));
  }
  // Routine work belongs on seats/cards; retain explicit errors and required actions.
  visible("table-preparation", false);
  visible("table-message", !!error || !!data.walletNeeded || !!data.leaveRequested || !!view?.nextStacks?.some(n => n < 200));
  const actions = view?.actions ?? [];
  const canPlay = !!view?.tip && !!view?.betting && !view?.terminal && view.actor === role && !busy && !pending && !error;
  for (const [id, kinds] of [
    ["action-fold", ["Fold"]],
    ["action-check", ["Check"]],
    ["action-call", ["Call"]],
    ["action-aggressive", ["Bet", "Raise"]],
  ]) {
    const action = actions.find((a) =>
      kinds.some((k) => a.kind === `Action(${k})`),
    );
    visible(id, !!action && canPlay);
    $(id).disabled = !action || !canPlay;
    $(id).onclick = () => void session.act(action.index);
    if (id === "action-call")
      $(id).textContent = `Call ${formatBitcoinAmount(action?.betAmount ?? view?.toCall ?? 0)}`;
    if (id === "action-aggressive")
      $(id).textContent = `${action?.kind === "Action(Raise)" ? "Raise to" : "Bet"} ${formatBitcoinAmount((view?.roundBets?.[role] ?? 0) + (action?.betAmount ?? 0))}`;
  }
  const canLeave = !!view?.terminal && !!data.sitOutNext && !data.wantsNext && !data.handoffStarted && !data.left && !data.leaveRequested;
  visible("leave-table", canLeave);
  visible("action-bar", canLeave || !!data.left || canPlay && actions.some(a => /^Action\((Fold|Check|Call|Bet|Raise)\)$/.test(a.kind)));
  $("sit-out-next-hand").checked = !!data.sitOutNext;
  $("sit-out-next-hand").disabled = !!(data.successor || data.leaveRequested || data.peer.leave || data.cashout || data.left || (data.protocol==='channel-v1' && data.wantsNext));
  visible("back-to-lobby", !!data.left);
  if (data.left) {
    visible("table-message", false);
    $("table-phase").textContent = "";
    $("table-detail").textContent = "";
  } else if (data.leaveRequested) { $("table-phase").textContent = state.stage; $("table-detail").textContent = ""; }
  if (view?.nextStacks?.some((n) => n < 200))
    $("table-detail").textContent = "Not enough chips for another hand.";
  visible("table-detail", !!$("table-detail").textContent);
  $("chain-state").textContent = data.returned
    ? "Funds returned. You can leave the table."
    : view?.terminal
      ? `Your total funds: ${formatBitcoinAmount(view.payouts[role])}, including unused fees.`
      : feedback.active
        ? feedback.title
        : idle.title;
  $("table-transactions").replaceChildren(
    ...data.log.map((t, index) => {
      const li = document.createElement("li"),
        a = document.createElement("a");
      a.href = `${config.chain.explorerUrl.replace(/\/$/, "")}/tx/${t.txid}`;
      a.target = "_blank";
      a.rel = "noopener";
      a.textContent = `Transaction ${index + 1} · Block ${t.height}`;
      li.append(a);
      return li;
    }),
  );
}
async function start(operation, kind = "create") {
  if (starting) return;
  if (kind !== "resume" && (!nickname() || document.body.classList.contains("nickname-onboarding") || !walletBalanceKnown || !(wallet?.balance > 0))) { updateWalletEntry(); return; }
  starting = true;
  const button = $(kind === "resume" ? "resume-connection" : kind === "join" ? "join-retry" : "create-game");
  const label = kind === "resume" ? "Reconnect" : kind === "join" ? "Join table" : "Create table";
  button.textContent = kind === "resume" ? "Reconnecting…" : kind === "join" ? "Joining…" : "Creating…";
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  if (kind === "resume" || kind === "join") {
    document.body.classList.remove("wallet-onboarding");
    visible("lobby", false);
    visible("game", true);
    visible("invite-card", false);
    $("preparation-title").textContent = kind === "resume" ? "Reconnecting…" : "Joining table…";
    $("preparation-progress").removeAttribute("value");
    $("preparation-progress").setAttribute("aria-label", kind === "resume" ? "Reconnecting" : "Joining table");
    visible("table-preparation", true);
    $("table-phase").textContent = "Reconnecting…";
    $("table-phase").classList.add("busy");
    $("table-detail").textContent = "";
    visible("table-message", false);
  }
  visible("join-retry", false);
  visible("lobby-error", false);
  visible("lobby-error-details", false);
  $("create-game").disabled = $("join-retry").disabled = true;
  try {
    if (kind === "resume" && await appUpdateAvailable()) {
      session?.close();
      location.reload();
      return;
    }
    session?.close();
    session = new TableSession(config, render);
    await operation(session);
  } catch (e) {
    if (kind === "join") {
      document.body.classList.remove("entry-pending");
      visible("table-preparation", false);
      visible("game", false);
      visible("lobby", true);
    }
    if (kind === "resume") {
      visible("table-preparation", false);
      $("table-phase").textContent = "Couldn’t reconnect";
      visible("table-message", true);
      visible("resume-connection", true);
      visible("back-to-lobby", true);
    }
    visible("join-retry", kind === "join");
    visible("lobby-error", true);
    $("lobby-error").textContent = playerError(e.message, false);
    $("lobby-error-technical").textContent = e.message;
    visible("lobby-error-details", true);
    $("game-error-detail").textContent = e.message;
    visible("game-error-detail", true);
    console.error(e);
    visible("game-error", true);
    $("game-error").textContent = playerError(e.message);
  } finally {
    starting = false;
    button.textContent = kind === "join" ? "Try again" : label;
    button.disabled = false;
    updateWalletEntry();
    button.setAttribute("aria-busy", "false");
    if (kind === "resume") $("table-phase").classList.remove("busy");
  }
}
$("create-game").onclick = () => void start(s => s.create(nickname()));
$("join-retry").onclick = () => { autoInviteAttempt = null; void joinInviteRoute(); };
$("copy-link").onclick = async () => {
  $("copy-link").disabled = true;
  $("copy-link").textContent = "Copying…";
  try {
    await navigator.clipboard.writeText($("share-link").value);
    $("copy-state").textContent = "Invite copied.";
  } catch {
    $("share-link").select();
    $("copy-state").textContent = "Copy the selected link and send it to your opponent.";
  } finally {
    $("copy-link").disabled = false;
    $("copy-link").textContent = "Copy";
  }
};
$("leave-table").onclick = () => void session.leaveTable();
$("sit-out-next-hand").onchange = (event) => void session.setSitOutNext(event.target.checked);
$("resume-connection").onclick = () => {
  const route = location.hash.match(/^#\/table\/([a-f0-9]{64})\/(alice|bob)$/);
  const gameId = last?.data?.gameId ?? route?.[1];
  const sender = last?.data?.sender ?? route?.[2];
  if (gameId && sender) void start((s) => s.resume(gameId, sender), "resume");
};
config = await (await fetch("/api/v1/config")).json();
visible("wallet-panel", true);
let wallet, walletRefreshing = false, walletBalanceKnown = false, walletPending = false;
function updateWalletEntry() {
  const needsName = document.body.classList.contains("nickname-onboarding");
  const joining = location.hash.startsWith("#/join/");
  document.body.classList.toggle("invite-entry", joining);
  // Reveal the lobby only after prerequisites finish and only when it is the destination.
  document.body.classList.toggle("entry-pending", !needsName && !joining && !walletBalanceKnown || joining && autoInviteAttempt === null);
  const needsFunds = !needsName && $("game").classList.contains("hidden") && (!walletBalanceKnown || !(wallet?.balance > 0)) && !location.hash.startsWith("#/table/");
  document.body.classList.toggle("wallet-checking", !walletBalanceKnown);
  document.body.classList.toggle("wallet-awaiting", walletPending);
  $("wallet-progress").setAttribute("aria-label", walletPending ? "Funds arriving" : "Loading wallet");
  document.querySelector(".wallet-onboarding-title").textContent = !walletBalanceKnown ? "Loading wallet…" : walletPending ? "Funds arriving…" : "Fund your wallet";
  const wasOnboarding = document.body.classList.contains("wallet-onboarding");
  document.body.classList.toggle("wallet-onboarding", needsFunds);
  if (needsFunds) $("wallet-panel").open = true;
  else if (wasOnboarding) $("wallet-panel").open = false;
  $("create-game").disabled = $("join-retry").disabled = starting || needsName || !nickname() || !walletBalanceKnown || !(wallet?.balance > 0);
}
window.addEventListener("nickname-ready", () => { updateWalletEntry(); void joinInviteRoute(); });
updateWalletEntry();
async function refreshWallet({ quiet = false } = {}) {
  if (walletRefreshing) return;
  walletRefreshing = true;
  $("wallet-progress").classList.remove("hidden");
  $("wallet-retry").disabled = true;
  if (!quiet) $("wallet-retry").textContent = "Refreshing…";
  try {
    wallet ??= await localWallet(config);
    $("wallet-address").value = wallet.address;
    const coins = await wallet.refresh();
    visible("wallet-retry", false);
    $("wallet-progress").classList.remove("hidden");
    walletBalanceKnown = true;
    walletPending = wallet.balance === 0 && coins.some(coin => !coin.status.confirmed && coin.value > 0);
    $("wallet-balance").textContent = formatBitcoinAmount(wallet.balance);
    updateWalletEntry();
    $("wallet-status").textContent = wallet.balance ? "Available for buy-ins." : walletPending ? "Waiting for your funds to arrive." : "Send funds here to fund your buy-in.";
    void joinInviteRoute();
  } catch(error) {
    visible("wallet-retry", true);
    if (!walletBalanceKnown) {
      $("wallet-progress").classList.add("hidden");
      document.querySelector(".wallet-onboarding-title").textContent = "Couldn’t load wallet";
      $("wallet-status").textContent = "Try refreshing your balance.";
    } else if (!quiet) $("wallet-status").textContent = error.message;
  }
  finally { walletRefreshing = false; $("wallet-retry").disabled = false; $("wallet-retry").textContent = "Try again"; }
}
document.addEventListener("click", (event) => {
  const panel = $("wallet-panel");
  if (!document.body.classList.contains("wallet-onboarding") && !panel.contains(event.target)) panel.open = false;
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !document.body.classList.contains("wallet-onboarding")) $("wallet-panel").open = false;
});
$("wallet-retry").onclick = ()=>void refreshWallet();
$("copy-wallet").onclick = async()=>{
  $("copy-wallet").textContent="Copying…";
  try { await navigator.clipboard.writeText($("wallet-address").value); $("copy-wallet").textContent="Copied"; }
  catch { $("wallet-address").select(); $("copy-wallet").textContent="Copy"; }
};
$("back-to-lobby").onclick = ()=>{ session?.close();session=null;location.hash="";visible("game",false);visible("lobby",true);updateWalletEntry();void refreshWallet(); };
void refreshWallet();
setInterval(() => void refreshWallet({ quiet: true }), 15_000);
const match = location.hash.match(/^#\/table\/([a-f0-9]{64})\/(alice|bob)$/);
if (match) await start((s) => s.resume(match[1], match[2]), "resume");
else loadInviteRoute();
function loadInviteRoute() {
  updateWalletEntry();
  if (!location.hash.startsWith("#/join/")) { autoInviteAttempt = null; return; }
  void joinInviteRoute();
}
async function joinInviteRoute() {
  if (starting || document.body.classList.contains("nickname-onboarding") || !nickname() || !walletBalanceKnown || !(wallet?.balance > 0)) return;
  const route = location.hash;
  if (!route.startsWith("#/join/") || autoInviteAttempt === route) return;
  let invite;
  try { invite = parseInvite(route); } catch {
    document.body.classList.remove("entry-pending");
    visible("lobby-error", true);
    $("lobby-error").textContent = "This invite link is invalid.";
    return;
  }
  autoInviteAttempt = route;
  await start(s => s.join(invite, nickname()), "join");
}
window.addEventListener("hashchange", loadInviteRoute);
