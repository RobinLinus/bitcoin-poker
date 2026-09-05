import { WorkerRpcClient } from "/browser/worker/rpc-client.js";
import { OffchainMoveRatchet } from "/browser/game/offchain-ratchet.js";

const $ = (id) => document.getElementById(id);
const fill = (value) => new Uint8Array(32).fill(value);
const money = (value) => `₿${Number(value).toLocaleString("en-US")}`;
const ranks = ["2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A"];
const suits = ["♣", "♦", "♥", "♠"];
const identities = [
  { secret: fill(3), xonly: Uint8Array.from([83,31,230,6,129,52,80,61,39,35,19,50,39,200,103,172,143,166,200,60,83,126,154,68,195,197,189,189,203,31,227,55]) },
  { secret: fill(5), xonly: Uint8Array.from([98,192,160,70,218,204,232,109,221,3,67,198,211,199,199,156,34,8,186,13,156,156,242,74,109,4,109,33,210,31,144,247]) },
].sort((a, b) => bytesToHex(a.xonly).localeCompare(bytesToHex(b.xonly)));

let session = null;
let client = null;
let table = null;
let ratchet = null;
let ticking = false;
let setupSending = false;
let setupAccepted = false;
let privateSending = false;
let readySending = false;
let localRetryAttempt = 0;
let peerRetryAttempt = 0;
let pollTimer = null;
const sentFrames = new Set();
const frameIds = new Map();
const peerPublicOpenings = new Map();

function bytesToHex(value) {
  return Array.from(new Uint8Array(value), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(value) {
  return Uint8Array.from(value.match(/../g) || [], (byte) => Number.parseInt(byte, 16));
}

function randomHex() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
}

function toBase64(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeJson(value) {
  return toBase64(new TextEncoder().encode(JSON.stringify(value)));
}

function decodeJson(value) {
  return JSON.parse(new TextDecoder().decode(fromBase64(value)));
}

async function api(path, options = {}, token = null) {
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set("content-type", "application/json");
  if (token) headers.set("authorization", `Bearer ${token}`);
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body?.error?.message || `Request failed (${response.status})`);
  return body;
}

function showError(error) {
  console.error(error);
  const target = session ? $("game-error") : $("lobby-error");
  target.textContent = session
    ? "Connection interrupted. Reconnecting…"
    : "Couldn’t open that table. Check the invite and try again.";
  target.classList.remove("hidden");
}

function clearErrors() {
  for (const id of ["lobby-error", "game-error"]) {
    $(id).textContent = "";
    $(id).classList.add("hidden");
  }
}

function selectTab(name) {
  const creating = name === "create";
  $("create-tab").classList.toggle("active", creating);
  $("join-tab").classList.toggle("active", !creating);
  $("create-tab").setAttribute("aria-selected", String(creating));
  $("join-tab").setAttribute("aria-selected", String(!creating));
  $("create-panel").classList.toggle("hidden", !creating);
  $("join-panel").classList.toggle("hidden", creating);
  clearErrors();
}

function inviteLink(gameId, inviteSecret) {
  return `${location.origin}${location.pathname}#/join/${gameId}/${inviteSecret}`;
}

function parseInvite(value) {
  let hash = value.trim();
  try { hash = new URL(hash).hash; } catch (_) {}
  let match = hash.match(/^#?\/join\/([0-9a-f]{64})\/([0-9a-f]{64})$/i);
  if (!match) match = value.trim().match(/^([0-9a-f]{64}):([0-9a-f]{64})$/i);
  if (!match) throw new Error("Invalid invite");
  return { gameId: match[1].toLowerCase(), inviteSecret: match[2].toLowerCase() };
}

async function createGame() {
  clearErrors();
  $("create-game").disabled = true;
  try {
    const gameId = randomHex();
    const playerToken = randomHex();
    const inviteSecret = randomHex();
    await api("/api/v1/games", {
      method: "POST",
      body: JSON.stringify({ gameId, playerToken, inviteSecret }),
    });
    history.replaceState(null, "", `#/host/${gameId}/${playerToken}/${inviteSecret}`);
    await enterGame({ gameId, playerToken, inviteSecret, role: 0, cursor: 0, joined: false, hand: 1 });
  } catch (error) {
    showError(error);
    $("create-game").disabled = false;
  }
}

async function joinGame() {
  clearErrors();
  $("join-game").disabled = true;
  try {
    const { gameId, inviteSecret } = parseInvite($("invite-value").value);
    const playerToken = randomHex();
    await api(`/api/v1/games/${gameId}/join`, {
      method: "POST",
      body: JSON.stringify({ playerToken, inviteSecret }),
    });
    history.replaceState(null, "", `#/guest/${gameId}/${playerToken}`);
    await enterGame({ gameId, playerToken, role: 1, cursor: 0, joined: true, hand: 1 });
  } catch (error) {
    showError(error);
    $("join-game").disabled = false;
  }
}

async function enterGame(nextSession) {
  session = nextSession;
  $("lobby").classList.add("hidden");
  $("game").classList.remove("hidden");
  $("funding-card").classList.add("hidden");
  $("deployment-name").textContent = "Practice game";
  $("table-small-blind").textContent = money(50);
  $("table-big-blind").textContent = money(100);
  const host = session.role === 0;
  $("local-avatar").textContent = host ? "H" : "G";
  $("local-name").textContent = host ? "You · Host" : "You · Guest";
  $("opponent-avatar").textContent = host ? "G" : "H";
  $("opponent-name").textContent = host ? "Guest" : "Host";
  $("local-stack").textContent = `Stack · ${money(10_000)}`;
  $("opponent-stack").textContent = `Stack · ${money(10_000)}`;
  $("game-pot").textContent = money(0);
  $("next-hand").classList.add("hidden");
  $("invite-card").classList.toggle("hidden", !host);
  if (host) $("share-link").value = inviteLink(session.gameId, session.inviteSecret);
  setStatus(host ? "Waiting for opponent" : "Joining table…", host ? "Share the private link to fill the second seat." : "Connecting to the host.");
  clearErrors();
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => void tick(), 300);
  await tick();
}

function setStatus(headline, detail, visible = true) {
  $("table-phase").textContent = headline;
  $("table-detail").textContent = detail;
  $("table-message").classList.toggle("hidden", !visible);
}

async function initializeParticipant() {
  if (client) return;
  setStatus("Creating a fair deck…", "Both players are shuffling together.");
  $("opponent-state").textContent = "Connected";
  const wasm = await (await fetch("/wasm/dlog52.wasm", { cache: "no-store" })).arrayBuffer();
  const room = hexToBytes(session.gameId);
  const anchor = Uint8Array.from(room);
  const anchorView = new DataView(anchor.buffer);
  anchorView.setUint32(28, anchorView.getUint32(28, false) ^ session.hand, false);
  const nonce = Uint8Array.from(anchor).reverse();
  nonce[0] ^= 0xa5;
  const config = {
    networkGenesis: fill(1),
    sessionAnchor: anchor,
    identityA: identities[0].xonly,
    identityB: identities[1].xonly,
    sessionNonce: nonce,
    rulesHash: fill(4),
  };
  client = new WorkerRpcClient(new Worker("/browser/deal/dlog52-worker.js", { type: "module" }));
  const identitySecret = Uint8Array.from(identities[session.role].secret);
  const entropy = crypto.getRandomValues(new Uint8Array(32));
  await client.request("init", {
    wasm,
    request: { config, role: session.role, identitySecret, entropy },
  }, { transfer: [wasm, identitySecret.buffer, entropy.buffer] });
}

function ratchetStorageKey() {
  return `bp52:offchain:${session.gameId}:${session.hand}:${session.role}`;
}

async function initializeRatchet() {
  if (ratchet) return ratchet;
  if (!client || !setupAccepted) throw new Error("The fair deal must finish before play begins");
  ratchet = await new OffchainMoveRatchet({
    gameId: session.gameId,
    hand: session.hand,
    localRole: session.role,
    sign: async (hash) => {
      const auxiliaryRandomness = crypto.getRandomValues(new Uint8Array(32));
      const result = await client.request("sign-offchain", {
        commitmentHash: hexToBytes(hash),
        auxiliaryRandomness,
      }, { transfer: [auxiliaryRandomness.buffer] });
      return bytesToHex(result.signature);
    },
    verify: async (role, hash, signature) => {
      const commitmentHash = hexToBytes(hash);
      const signatureBytes = hexToBytes(signature);
      await client.request("verify-offchain", {
        signer: role,
        commitmentHash,
        signature: signatureBytes,
      }, { transfer: [commitmentHash.buffer, signatureBytes.buffer] });
    },
    load: () => {
      const value = localStorage.getItem(ratchetStorageKey());
      return value ? JSON.parse(value) : null;
    },
    save: (value) => {
      const encoded = JSON.stringify(value);
      localStorage.setItem(ratchetStorageKey(), encoded);
      if (localStorage.getItem(ratchetStorageKey()) !== encoded) {
        throw new Error("Couldn’t safely save the latest move");
      }
    },
  }).initialize();
  return ratchet;
}

async function sendFrame(key, kind, payload) {
  const scopedKey = `hand-${session.hand}-${key}`;
  if (sentFrames.has(scopedKey)) return;
  const messageId = frameIds.get(scopedKey) || randomHex();
  frameIds.set(scopedKey, messageId);
  await api(`/api/v1/games/${session.gameId}/messages`, {
    method: "POST",
    body: JSON.stringify({ messageId, kind, payload }),
  }, session.playerToken);
  sentFrames.add(scopedKey);
}

async function sendJson(key, kind, value) {
  await sendFrame(key, kind, encodeJson({ hand: session.hand, ...value }));
}

async function advanceSetup() {
  if (!client || setupAccepted || setupSending) return;
  setupSending = true;
  try {
    let snapshot = (await client.request("snapshot")).snapshot;
    if (snapshot.retryRequired && !snapshot.hasPendingOutgoing) {
      const nextAttempt = snapshot.attempt + 1;
      await sendJson(`retry-${nextAttempt}`, "dlog52.retry", { nextAttempt });
      localRetryAttempt = nextAttempt;
      await maybeStartRetry();
      return;
    }
    if (snapshot.accepted) {
      const certificate = await client.request("export-certificate").then((result) => result.certificate);
      await client.request("verify-certificate", { certificate }, { transfer: [certificate] });
      setupAccepted = true;
      table ||= new NetworkTable(session.role, [10_000, 10_000], session.hand);
      await initializeRatchet();
      setStatus("Dealing cards…", "Your cards stay private in this browser.");
      await sendPrivateShares();
      return;
    }
    const prepared = await client.request("prepare-outgoing");
    if (prepared.envelope) {
      const envelope = prepared.envelope;
      const key = `setup-${snapshot.attempt}-${snapshot.stage}-${bytesToHex(new Uint8Array(envelope).subarray(0, 8))}`;
      await sendJson(key, "dlog52.setup", { envelope: toBase64(envelope) });
      await client.request("confirm-outgoing", { envelope }, { transfer: [envelope] });
    }
  } finally {
    setupSending = false;
  }
}

async function maybeStartRetry() {
  if (!client || localRetryAttempt === 0 || localRetryAttempt !== peerRetryAttempt) return;
  const snapshot = (await client.request("snapshot")).snapshot;
  if (!snapshot.retryRequired || snapshot.hasPendingOutgoing || localRetryAttempt !== snapshot.attempt + 1) return;
  await client.request("start-retry", { nextAttempt: localRetryAttempt });
  localRetryAttempt = 0;
  peerRetryAttempt = 0;
  setStatus("Reshuffling…", "Both players are creating a fresh fair deck.");
}

function ownPrivateSlots() {
  return session.role === 0 ? [0, 2] : [1, 3];
}

function peerPrivateSlots() {
  return session.role === 0 ? [1, 3] : [0, 2];
}

async function sendPrivateShares() {
  if (!setupAccepted || privateSending) return;
  privateSending = true;
  try {
    for (const slot of peerPrivateSlots()) {
      const key = `private-${slot}`;
      if (sentFrames.has(`hand-${session.hand}-${key}`)) continue;
      const opening = await client.request("export-share", {
        slot,
        recipient: 1 - session.role,
        stage: 0,
        auxiliaryRandomness: crypto.getRandomValues(new Uint8Array(32)),
      }).then((result) => result.opening);
      await sendJson(key, "deal.private", { slot, opening: toBase64(opening) });
    }
  } finally {
    privateSending = false;
  }
}

async function acceptPrivateShare(value) {
  if (!ownPrivateSlots().includes(value.slot) || table?.cards[value.slot] !== undefined) return;
  const opening = fromBase64(value.opening);
  const result = await client.request("sign-card", {
    slot: value.slot,
    peerOpening: opening,
    sighash: fill(0x80 + value.slot),
    auxiliaryRandomness: crypto.getRandomValues(new Uint8Array(32)),
  }, { transfer: [opening.buffer] });
  table ||= new NetworkTable(session.role, [10_000, 10_000], session.hand);
  table.cards[value.slot] = result.cardId;
  await client.request("gate-leaf", { slot: value.slot, rawSum: result.rawSum });
  table.showOwnCards();
  await sendReadyIfPossible();
}

async function sendReadyIfPossible() {
  if (!table || readySending || table.localReady || ownPrivateSlots().some((slot) => table.cards[slot] === undefined)) return;
  readySending = true;
  try {
    await sendJson("deal-ready", "game.ready", { ready: true });
    table.localReady = true;
    table.beginIfReady();
  } finally {
    readySending = false;
  }
}

async function tick() {
  if (!session || ticking) return;
  ticking = true;
  try {
    const status = await api(`/api/v1/games/${session.gameId}`, {}, session.playerToken);
    session.joined = Boolean(status.joined);
    if (!session.joined) {
      $("opponent-state").textContent = "Waiting to join";
      return;
    }
    $("invite-card").classList.add("hidden");
    await initializeParticipant();
    const page = await api(`/api/v1/games/${session.gameId}/messages?after=${session.cursor}&limit=64`, {}, session.playerToken);
    for (const message of page.messages || []) {
      await applyMessage(message);
      session.cursor = message.cursor;
    }
    await advanceSetup();
    if (setupAccepted) await sendPrivateShares();
    clearErrors();
  } catch (error) {
    showError(error);
  } finally {
    ticking = false;
  }
}

async function applyMessage(message) {
  const localSender = message.sender === (session.role === 0 ? "alice" : "bob");
  if (message.kind === "dlog52.setup") {
    const value = decodeJson(message.payload);
    if (value.hand !== session.hand) return;
    if (!localSender && !setupAccepted) {
      const envelope = fromBase64(value.envelope);
      await client.request("accept-peer", { envelope }, { transfer: [envelope.buffer] });
    }
    return;
  }
  if (message.kind === "dlog52.retry") {
    const value = decodeJson(message.payload);
    if (value.hand !== session.hand) return;
    if (!localSender) peerRetryAttempt = value.nextAttempt;
    await maybeStartRetry();
    return;
  }
  if (message.kind === "deal.private") {
    const value = decodeJson(message.payload);
    if (value.hand === session.hand && !localSender) await acceptPrivateShare(value);
    return;
  }
  if (message.kind === "game.ready") {
    const value = decodeJson(message.payload);
    if (value.hand !== session.hand) return;
    table ||= new NetworkTable(session.role, [10_000, 10_000], session.hand);
    if (localSender) table.localReady = true;
    else table.peerReady = true;
    table.beginIfReady();
    return;
  }
  if (message.kind === "deal.public" || message.kind === "deal.showdown") {
    const value = decodeJson(message.payload);
    if (value.hand === session.hand && !localSender) await acceptPublicShare(value);
    return;
  }
  if (message.kind === "game.proposal") {
    const value = decodeJson(message.payload);
    if (value.hand !== session.hand) return;
    const senderRole = message.sender === "alice" ? 0 : 1;
    if (localSender) return;
    await initializeRatchet();
    const before = ratchet.sequence;
    const acknowledgement = await ratchet.acceptProposal(
      value.proposal,
      (body) => table?.canApplyCommitment(body, senderRole) ?? false,
    );
    await sendJson(
      `ack-${acknowledgement.sequence}-${acknowledgement.hash}`,
      "game.ack",
      { acknowledgement },
    );
    if (ratchet.sequence !== before) {
      await table.applyCommittedAction(value.proposal.body, senderRole);
    }
    return;
  }
  if (message.kind === "game.ack") {
    const value = decodeJson(message.payload);
    if (value.hand !== session.hand || localSender) return;
    await initializeRatchet();
    const pending = ratchet.pendingProposal;
    const before = ratchet.sequence;
    const record = await ratchet.acceptAcknowledgement(value.acknowledgement);
    if (ratchet.sequence !== before) {
      if (!pending || pending.hash !== record.hash) throw new Error("Acknowledged move changed while pending");
      await table.applyCommittedAction(record.body, session.role);
    }
    return;
  }
  if (message.kind === "game.next") {
    const value = decodeJson(message.payload);
    if (value.hand === session.hand && value.nextHand === session.hand + 1) {
      await startNextHand(value.nextHand);
    }
  }
}

async function acceptPublicShare(value) {
  if (!table || table.cards[value.slot] !== undefined && value.stage !== 4) return;
  peerPublicOpenings.set(`${value.stage}-${value.slot}`, value.opening);
  await table.completePendingReveal();
}

function resetCards() {
  for (let index = 0; index < 2; index += 1) {
    const local = $(`hole-card-${index}`);
    local.replaceChildren();
    local.className = "";
    local.removeAttribute("aria-label");
  }
  $("local-hole-cards").classList.remove("face-up");
  $("local-hole-cards").classList.add("face-down");
  $("local-hole-cards").setAttribute("aria-label", "Hole cards not dealt");
  const opponentCards = document.querySelectorAll(".seat-opponent .card-pair > span");
  opponentCards.forEach((card) => {
    card.replaceChildren();
    card.className = "";
    card.removeAttribute("aria-label");
  });
  opponentCards[0]?.parentElement.classList.remove("face-up");
  opponentCards[0]?.parentElement.setAttribute("aria-hidden", "true");
  $("local-blind").classList.add("hidden");
  $("opponent-blind").classList.add("hidden");
  for (let index = 0; index < 5; index += 1) {
    const board = $(`board-card-${index}`);
    board.replaceChildren(String(index + 1));
    board.className = "playing-card empty";
    board.removeAttribute("aria-label");
  }
  document.querySelector(".community-cards").setAttribute("aria-label", "Community cards not dealt");
}

async function startNextHand(nextHand) {
  if (nextHand !== session.hand + 1) return;
  const stacks = table?.stacks.slice() || [10_000, 10_000];
  if (client) await client.close();
  client = null;
  ratchet = null;
  session.hand = nextHand;
  setupAccepted = false;
  setupSending = false;
  privateSending = false;
  readySending = false;
  localRetryAttempt = 0;
  peerRetryAttempt = 0;
  peerPublicOpenings.clear();
  table = new NetworkTable(session.role, stacks, session.hand);
  resetCards();
  $("next-hand").classList.add("hidden");
  $("next-hand").disabled = false;
  $("action-bar").classList.add("hidden");
  $("game-pot").textContent = money(0);
  $("opponent-state").textContent = "Shuffling";
  document.body.removeAttribute("data-game-complete");
  setStatus(`Preparing hand ${session.hand}…`, "Both players are creating a fresh deck.");
  await initializeParticipant();
  await advanceSetup();
}

class NetworkTable {
  constructor(localRole, stacks = [10_000, 10_000], handNumber = 1) {
    this.localRole = localRole;
    this.handNumber = handNumber;
    this.cards = new Array(9);
    this.stacks = stacks.slice();
    this.pot = 0;
    this.streetCommitted = [0, 0];
    this.localReady = false;
    this.peerReady = false;
    this.started = false;
    this.complete = false;
    this.pendingAction = false;
    this.actionSeq = 0;
    this.reveal = null;
  }

  showCard(element, id) {
    const rank = ranks[Math.floor(id / 4)];
    const suit = suits[id % 4];
    const label = document.createElement("span");
    const rankNode = document.createElement("span");
    const suitNode = document.createElement("span");
    label.className = `card-label${rank === "10" ? " wide-rank" : ""}`;
    rankNode.className = "card-rank";
    suitNode.className = "card-suit";
    rankNode.textContent = rank;
    suitNode.textContent = suit;
    label.append(rankNode, suitNode);
    element.replaceChildren(label);
    element.setAttribute("aria-label", `${rank} ${suit}`);
    element.classList.remove("empty");
    element.classList.add("dealt");
    element.classList.toggle("red", id % 4 === 1 || id % 4 === 2);
  }

  showOwnCards() {
    const slots = ownPrivateSlots();
    slots.forEach((slot, index) => {
      if (this.cards[slot] !== undefined) this.showCard($(`hole-card-${index}`), this.cards[slot]);
    });
    if (slots.every((slot) => this.cards[slot] !== undefined)) {
      $("local-hole-cards").classList.remove("face-down");
      $("local-hole-cards").classList.add("face-up");
      $("local-hole-cards").setAttribute("aria-label", "Your hole cards");
    }
  }

  beginIfReady() {
    if (this.started || !this.localReady || !this.peerReady) return;
    this.started = true;
    this.button = (this.handNumber - 1) % 2;
    this.bigBlind = 1 - this.button;
    this.street = "preflop";
    this.actor = this.button;
    this.currentBet = 100;
    this.lastAction = "blind";
    this.raises = 0;
    this.pay(this.button, 50);
    this.pay(this.bigBlind, 100);
    $("local-blind").textContent = this.localRole === this.button ? "SB" : "BB";
    $("opponent-blind").textContent = this.localRole === this.button ? "BB" : "SB";
    $("local-blind").classList.remove("hidden");
    $("opponent-blind").classList.remove("hidden");
    $("opponent-state").textContent = "Playing";
    this.renderTurn();
  }

  pay(role, amount) {
    if (amount < 0 || this.stacks[role] < amount) throw new Error("Invalid wager");
    this.stacks[role] -= amount;
    this.streetCommitted[role] += amount;
    this.pot += amount;
    this.renderMoney();
  }

  renderMoney() {
    $("local-stack").textContent = `Stack · ${money(this.stacks[this.localRole])}`;
    $("opponent-stack").textContent = `Stack · ${money(this.stacks[1 - this.localRole])}`;
    $("game-pot").textContent = money(this.pot);
  }

  legalActions() {
    const toCall = Math.max(0, this.currentBet - this.streetCommitted[this.actor]);
    const unit = this.street === "turn" || this.street === "river" ? 200 : 100;
    return {
      toCall,
      canCheck: toCall === 0,
      canCall: toCall > 0,
      canAggressive: this.raises < 3 && this.stacks[this.actor] > toCall,
      aggressiveTarget: this.currentBet === 0 ? unit : this.currentBet + unit,
    };
  }

  renderTurn() {
    if (this.complete || this.actor === null) return;
    const legal = this.legalActions();
    const localTurn = this.actor === this.localRole;
    $("opponent-state").textContent = localTurn ? "Waiting" : "Their turn";
    const street = this.street[0].toUpperCase() + this.street.slice(1);
    setStatus(
      `${street} · ${localTurn ? "your action" : "opponent’s action"}`,
      legal.toCall > 0
        ? `${localTurn ? "Call" : "Waiting on"} ${money(legal.toCall)}, raise, or fold.`
        : `${localTurn ? "Check or bet" : "Waiting for the other player"}.`,
      false,
    );
    $("action-bar").classList.remove("hidden");
    $("action-fold").textContent = "Fold";
    $("action-check").textContent = "Check";
    $("action-call").textContent = legal.toCall ? `Call ${money(legal.toCall)}` : "Call";
    $("action-aggressive").textContent = `${this.currentBet === 0 ? "Bet" : "Raise to"} ${money(legal.aggressiveTarget)}`;
    $("action-fold").disabled = !localTurn || this.pendingAction;
    $("action-check").disabled = !localTurn || !legal.canCheck || this.pendingAction;
    $("action-call").disabled = !localTurn || !legal.canCall || this.pendingAction;
    $("action-aggressive").disabled = !localTurn || !legal.canAggressive || this.pendingAction;
  }

  async sendAction(kind) {
    if (this.complete || this.actor !== this.localRole || this.pendingAction) return;
    this.pendingAction = true;
    this.renderTurn();
    try {
      await initializeRatchet();
      const proposal = await ratchet.propose({
        actor: this.actor,
        street: this.street,
        action: kind,
      });
      await sendJson(`proposal-${proposal.body.sequence}-${proposal.hash}`, "game.proposal", { proposal });
      await tick();
    } catch (error) {
      this.pendingAction = false;
      this.renderTurn();
      throw error;
    }
  }

  canApplyCommitment(value, senderRole) {
    if (this.complete || this.reveal) return false;
    if (value.sequence !== this.actionSeq || value.street !== this.street ||
        value.actor !== this.actor || senderRole !== this.actor) return false;
    const legal = this.legalActions();
    return value.action === "fold" ||
      (value.action === "check" && legal.canCheck) ||
      (value.action === "call" && legal.canCall) ||
      (value.action === "aggressive" && legal.canAggressive);
  }

  async applyCommittedAction(value, senderRole) {
    if (this.complete || this.reveal) return;
    if (!this.canApplyCommitment(value, senderRole)) {
      throw new Error("Players received inconsistent game actions");
    }
    const legal = this.legalActions();
    if (value.action === "fold") {
      this.actionSeq += 1;
      this.pendingAction = false;
      this.finish(1 - this.actor);
      return;
    }
    if (value.action === "check") {
      if (!legal.canCheck) throw new Error("Illegal check");
      const closes = this.lastAction === "check" || (this.street === "preflop" && this.lastAction === "opening-call" && this.actor === this.bigBlind);
      this.actionSeq += 1;
      this.pendingAction = false;
      if (closes) await this.closeStreet();
      else {
        this.lastAction = "check";
        this.actor = 1 - this.actor;
        this.renderTurn();
      }
      return;
    }
    if (value.action === "call") {
      if (!legal.canCall) throw new Error("Illegal call");
      this.pay(this.actor, legal.toCall);
      const openingCall = this.street === "preflop" && this.lastAction === "blind" && this.raises === 0;
      this.actionSeq += 1;
      this.pendingAction = false;
      if (openingCall) {
        this.lastAction = "opening-call";
        this.actor = this.bigBlind;
        this.renderTurn();
      } else await this.closeStreet();
      return;
    }
    if (value.action === "aggressive") {
      if (!legal.canAggressive) throw new Error("Illegal bet");
      const target = Math.min(legal.aggressiveTarget, this.streetCommitted[this.actor] + this.stacks[this.actor]);
      this.pay(this.actor, target - this.streetCommitted[this.actor]);
      this.currentBet = target;
      this.raises += 1;
      this.lastAction = "aggressive";
      this.actor = 1 - this.actor;
      this.actionSeq += 1;
      this.pendingAction = false;
      this.renderTurn();
      return;
    }
    throw new Error("Unknown poker action");
  }

  async closeStreet() {
    this.actor = null;
    $("action-bar").classList.add("hidden");
    const next = this.street === "preflop" ? "flop" : this.street === "flop" ? "turn" : this.street === "turn" ? "river" : "showdown";
    await this.beginReveal(next);
  }

  async beginReveal(next) {
    const slots = next === "flop" ? [4, 5, 6] : next === "turn" ? [7] : next === "river" ? [8] : [0, 1, 2, 3];
    const stage = next === "flop" ? 1 : next === "turn" ? 2 : next === "river" ? 3 : 4;
    this.reveal = { next, slots, stage };
    setStatus(next === "showdown" ? "Showdown" : `Dealing the ${next}…`, "Both players are revealing the next cards.", false);
    for (const slot of slots) {
      const key = `${next}-share-${slot}`;
      if (sentFrames.has(`hand-${session.hand}-${key}`)) continue;
      const opening = await client.request("export-share", {
        slot,
        recipient: 255,
        stage,
        auxiliaryRandomness: crypto.getRandomValues(new Uint8Array(32)),
      }).then((result) => result.opening);
      await sendJson(key, next === "showdown" ? "deal.showdown" : "deal.public", { slot, stage, opening: toBase64(opening) });
    }
    await this.completePendingReveal();
  }

  async completePendingReveal() {
    if (!this.reveal) return;
    const { next, slots, stage } = this.reveal;
    for (const slot of slots) {
      const openingValue = peerPublicOpenings.get(`${stage}-${slot}`);
      if (!openingValue) continue;
      if (stage !== 4 && this.cards[slot] !== undefined) continue;
      if (stage === 4 && this.cards[slot] !== undefined && !peerPrivateSlots().includes(slot)) continue;
      const opening = fromBase64(openingValue);
      const result = await client.request("sign-card", {
        slot,
        peerOpening: opening,
        sighash: fill(0x80 + slot),
        auxiliaryRandomness: crypto.getRandomValues(new Uint8Array(32)),
      }, { transfer: [opening.buffer] });
      if (this.cards[slot] !== undefined && this.cards[slot] !== result.cardId) throw new Error("A revealed card changed");
      this.cards[slot] = result.cardId;
      await client.request("gate-leaf", { slot, rawSum: result.rawSum });
      if (slot >= 4) this.showCard($(`board-card-${slot - 4}`), result.cardId);
    }
    if (slots.some((slot) => this.cards[slot] === undefined)) return;
    this.reveal = null;
    if (next === "showdown") {
      await this.showdown();
      return;
    }
    this.street = next;
    this.streetCommitted = [0, 0];
    this.currentBet = 0;
    this.lastAction = null;
    this.raises = 0;
    this.actor = this.bigBlind;
    this.renderTurn();
  }

  async showdown() {
    const opponent = document.querySelectorAll(".seat-opponent .card-pair > span");
    peerPrivateSlots().forEach((slot, index) => this.showCard(opponent[index], this.cards[slot]));
    opponent[0].parentElement.classList.add("face-up");
    opponent[0].parentElement.removeAttribute("aria-hidden");
    opponent[0].parentElement.setAttribute("aria-label", "Opponent hole cards at showdown");
    const board = this.cards.slice(4);
    const alice = await client.request("evaluate-seven", { cards: Uint8Array.from([this.cards[0], this.cards[2], ...board]) }).then((result) => result.evaluation);
    const bob = await client.request("evaluate-seven", { cards: Uint8Array.from([this.cards[1], this.cards[3], ...board]) }).then((result) => result.evaluation);
    this.finish(alice.score === bob.score ? null : alice.score > bob.score ? 0 : 1);
  }

  async requestNextHand() {
    if (!this.complete || $("next-hand").disabled) return;
    $("next-hand").disabled = true;
    setStatus("Starting next hand…", "Preparing a fresh shuffle with the other player.");
    try {
      await sendJson(`next-${this.handNumber + 1}`, "game.next", { nextHand: this.handNumber + 1 });
      await tick();
    } catch (error) {
      $("next-hand").disabled = false;
      throw error;
    }
  }

  finish(winner) {
    this.complete = true;
    this.actor = null;
    $("action-bar").classList.add("hidden");
    if (winner === null) {
      this.stacks[0] += this.pot / 2;
      this.stacks[1] += this.pot / 2;
    } else this.stacks[winner] += this.pot;
    this.renderMoney();
    const label = winner === null ? "Split pot" : winner === this.localRole ? "You win" : "Opponent wins";
    setStatus(label, `${money(this.pot)} hand complete.`);
    $("opponent-state").textContent = "Hand complete";
    $("next-hand").disabled = false;
    $("next-hand").classList.remove("hidden");
    document.body.dataset.gameComplete = "true";
  }
}

function copyInvite() {
  const input = $("share-link");
  navigator.clipboard?.writeText(input.value).then(() => {
    $("copy-state").textContent = "Invite copied. Send it to the other player.";
    $("copy-link").textContent = "Copied";
  }).catch(() => {
    input.select();
    $("copy-state").textContent = "Copy the selected link and send it privately.";
  });
}

function loadInviteRoute() {
  const match = location.hash.match(/^#\/join\/([0-9a-f]{64})\/([0-9a-f]{64})$/i);
  if (!match) return;
  selectTab("join");
  $("invite-value").value = location.href;
  $("join-hint").textContent = "Invite recognized. Join when you’re ready.";
}

$("deployment-name").textContent = "Practice game";
$("create-tab").addEventListener("click", () => selectTab("create"));
$("join-tab").addEventListener("click", () => selectTab("join"));
$("create-game").addEventListener("click", () => void createGame());
$("join-game").addEventListener("click", () => void joinGame());
$("copy-link").addEventListener("click", copyInvite);
$("action-fold").addEventListener("click", () => void table?.sendAction("fold").catch(showError));
$("action-check").addEventListener("click", () => void table?.sendAction("check").catch(showError));
$("action-call").addEventListener("click", () => void table?.sendAction("call").catch(showError));
$("action-aggressive").addEventListener("click", () => void table?.sendAction("aggressive").catch(showError));
$("next-hand").addEventListener("click", () => void table?.requestNextHand().catch(showError));
loadInviteRoute();
