import assert from "node:assert/strict";

if (!globalThis.atob) {
  globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
}
if (!globalThis.btoa) {
  globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
}

import {
  dealVerificationIsDue,
  GameplayPublishAction,
  GameAdvanceKind,
  bytesEqual,
  bytesToBase64,
  canonicalBase64ToBytes,
  deriveChainRecovery,
  deriveChainRelayTransition,
  gameChainRefreshReady,
  localRoleMayAuthorizeEdge,
  mayPublishLamportBundle,
  normalizeDealDispatch,
  normalizeRelayMessage,
  normalizeSetupAcceptance,
  nextGameplayPublishAction,
  ownedBytes,
  planAuthorizedEdge,
  planConfirmedSpend,
  relayFramesInCursorOrder,
  recordAutomaticEdgeResult,
  rememberRelayFrame,
  roleForRelaySender,
  selectAutomaticGameEdge,
  selectGameAdvance,
  selectVerifiedSpecialEdge,
  verifyAcceptedDealRecovery,
} from "./orchestration.js";
import { GamePhase } from "../game/game-runtime.js";
import { ChainPhase, ChainSetupKind } from "../chain/chain-runtime.js";

const id = (marker) => new Uint8Array(32).fill(marker);
const hexId = (marker) => Buffer.from(id(marker)).toString("hex");
const payload = bytesToBase64(Uint8Array.of(1, 2, 3));

assert.equal(mayPublishLamportBundle(0, ChainPhase.LAMPORT_READY), true);
assert.equal(mayPublishLamportBundle(1, ChainPhase.LAMPORT_READY), false);
assert.equal(mayPublishLamportBundle(1, ChainPhase.GRAPH_READY), true);
assert.throws(() => mayPublishLamportBundle(2, ChainPhase.GRAPH_READY), /publication state/);
const relay = (cursor, marker, sender = "alice") => ({
  cursor,
  messageId: hexId(marker),
  sender,
  kind: "test.exchange",
  payload,
});

// Worker boundary normalization always produces an owned Uint8Array and
// respects view offsets instead of leaking a whole backing buffer.
const backing = Uint8Array.of(9, 1, 2, 8);
const view = new DataView(backing.buffer, 1, 2);
const copy = ownedBytes(view, "view", 2);
assert.deepEqual([...copy], [1, 2]);
backing[1] = 7;
assert.deepEqual([...copy], [1, 2]);
assert.ok(bytesEqual(copy, Uint8Array.of(1, 2).buffer));

assert.deepEqual([...canonicalBase64ToBytes(payload, { maximumDecodedBytes: 3 })], [1, 2, 3]);
assert.throws(
  () => canonicalBase64ToBytes("AQID", { maximumDecodedBytes: 2 }),
  /fixed bound/,
);
assert.throws(() => canonicalBase64ToBytes("Zh=="), /noncanonical/);

const normalizedRelay = normalizeRelayMessage(relay(2, 2), {
  kind: "test.exchange",
  maximumDecodedBytes: 3,
});
assert.deepEqual([...normalizedRelay.event], [1, 2, 3]);
assert.throws(
  () => normalizeRelayMessage({ ...relay(2, 2), cursor: 0 }, { kind: "test.exchange" }),
  /malformed exchange metadata/,
);

let remembered = rememberRelayFrame([], relay(8, 8), {
  retainKind: true,
  sortByCursor: true,
});
remembered = rememberRelayFrame(remembered.frames, relay(3, 3, "bob"), {
  retainKind: true,
  sortByCursor: true,
});
assert.deepEqual(remembered.frames.map((frame) => frame.cursor), [3, 8]);
const duplicate = rememberRelayFrame(remembered.frames, relay(3, 3, "bob"), {
  retainKind: true,
});
assert.equal(duplicate.duplicate, true);
assert.throws(
  () => rememberRelayFrame(remembered.frames, { ...relay(3, 3, "bob"), payload: "BA==" }),
  /rebound/,
);
assert.throws(
  () => rememberRelayFrame(remembered.frames, relay(3, 4, "bob")),
  /cursor was assigned/,
);
assert.deepEqual(
  relayFramesInCursorOrder([relay(9, 9), relay(1, 1)]).map((frame) => frame.cursor),
  [1, 9],
);
assert.equal(roleForRelaySender("bob", "bob", 0), 0);
assert.equal(roleForRelaySender("alice", "bob", 0), 1);

const refreshReady = {
  sessionActive: true,
  chainFlowPresent: true,
  gameFlowPresent: true,
  gameFlowStarting: false,
  chainHalted: false,
};
assert.equal(gameChainRefreshReady(refreshReady), true);
assert.equal(gameChainRefreshReady({ ...refreshReady, gameFlowStarting: true }), false);
assert.equal(gameChainRefreshReady({ ...refreshReady, chainHalted: true }), false);
assert.equal(gameChainRefreshReady({ ...refreshReady, gameFlowPresent: false }), false);

function gameProjection(intent, phase = 1, dealEnvelopes = 4) {
  return { status: { phase, dealEnvelopes }, intents: intent ? [intent] : [] };
}

const gameAdvanceCases = [
  [{ hasPendingRelay: true }, GameAdvanceKind.WAIT_RELAY],
  [{
    projection: gameProjection({ name: "deal-envelope-due", sender: 0, sequence: 4 }),
  }, GameAdvanceKind.BUILD_DEAL_ENVELOPE],
  [{
    projection: gameProjection({ name: "deal-envelope-due", sender: 1, sequence: 4 }),
  }, GameAdvanceKind.WAIT_DEAL_ENVELOPE],
  [{ projection: gameProjection({ name: "approve-deal-retry" }) }, GameAdvanceKind.SIGN_DEAL_RETRY],
  [{ projection: gameProjection({ name: "sign-accepted-deal" }) }, GameAdvanceKind.SIGN_ACCEPTED_DEAL],
  [{ projection: gameProjection(null, GamePhase.SIGNING_DESCRIPTOR) }, GameAdvanceKind.DEAL_COMPLETE],
  [{ projection: gameProjection(null, 1) }, GameAdvanceKind.IDLE],
];
for (const [overrides, expected] of gameAdvanceCases) {
  const step = selectGameAdvance({
    projection: gameProjection(null),
    localRole: 0,
    hasPendingRelay: false,
    ...overrides,
  });
  assert.equal(step.kind, expected);
}

assert.equal(dealVerificationIsDue(gameProjection(null, GamePhase.DEALING, 15)), false);
assert.equal(dealVerificationIsDue(gameProjection(null, GamePhase.DEALING, 16)), true);
assert.equal(dealVerificationIsDue(gameProjection(null, GamePhase.ACCEPTING_DEAL, 16)), false);
assert.throws(
  () => dealVerificationIsDue(gameProjection(null, GamePhase.DEALING, 17)),
  /invalid DEAL envelope count/u,
);

assert.deepEqual(
  [...normalizeDealDispatch({ kind: "deal-envelope", envelope: Uint8Array.of(4).buffer }).envelope],
  [4],
);
assert.equal(
  normalizeDealDispatch({
    kind: "accepted-deal-signature",
    role: 1,
    signature: new Uint8Array(64).buffer,
  }).signature.byteLength,
  64,
);
assert.throws(
  () => normalizeDealDispatch({ kind: "accepted-deal-signature", role: 1, signature: id(1) }),
  /exactly 64 bytes/,
);
assert.throws(() => normalizeDealDispatch({ kind: "mystery" }), /unknown/);

const accepted = {
  version: 1,
  contextDigest: "context",
  revision: 7,
  storageKeyHex: "11".repeat(32),
  accepted: {
    deal: Uint8Array.of(1, 2),
    attestation: Uint8Array.of(3),
    sealedPreimages: Uint8Array.of(4, 5),
  },
};
const durable = structuredClone(accepted);
const recovery = verifyAcceptedDealRecovery(accepted, durable);
assert.deepEqual([...recovery.deal], [1, 2]);
durable.accepted.attestation[0] ^= 0xff;
assert.throws(() => verifyAcceptedDealRecovery(accepted, durable), /byte check/);
assert.throws(
  () => verifyAcceptedDealRecovery(accepted, { ...structuredClone(accepted), revision: 8 }),
  /read-back check/,
);

function chainProjection(intent, phase = GamePhase.SIGNING_DESCRIPTOR) {
  return { status: { phase }, intents: intent ? [intent] : [] };
}

const setupAccepted = normalizeSetupAcceptance({
  applicable: true,
  setupKind: ChainSetupKind.DESCRIPTOR_SIGNATURE,
  localLamportBundle: Uint8Array.of(5, 6).buffer,
});
assert.equal(setupAccepted.setupKind, ChainSetupKind.DESCRIPTOR_SIGNATURE);
assert.deepEqual([...setupAccepted.localLamportBundle], [5, 6]);
assert.throws(
  () => normalizeSetupAcceptance({ applicable: true, setupKind: 99 }),
  /invalid setup kind/,
);

const activationTransaction = Uint8Array.of(2, 0, 0, 0);
const recovered = deriveChainRecovery({
  acknowledged: true,
  localRole: 1,
  recovered: true,
  runtimeStatus: {
    phase: ChainPhase.INVENTORY_VERIFIED,
    inventoryVerified: true,
    inventoryAttestation: new Uint8Array(64).fill(9).buffer,
  },
}, {
  status: { phase: GamePhase.AUTHORIZING_ACTIVATION },
  intents: [{
    name: "broadcast-transaction",
    purpose: 0,
    transaction: activationTransaction.buffer,
  }],
}, 1);
assert.equal(recovered.recoveredPhase, ChainPhase.INVENTORY_VERIFIED);
assert.deepEqual([...recovered.activationTransaction], [...activationTransaction]);
assert.equal(recovered.inventoryVerified, true);
assert.throws(
  () => deriveChainRecovery({ acknowledged: true, localRole: 0 }, chainProjection(null), 1),
  /different canonical role/,
);

const localReady = deriveChainRelayTransition({
  accepted: true,
  deferred: false,
  package: 1,
  role: 0,
  readyForActivation: true,
  activationTransaction: null,
}, relay(1, 1, "alice"), "alice");
assert.equal(localReady.inventoryReadySent, true);
assert.equal(localReady.retryDeferred, true);
const lamportReady = deriveChainRelayTransition({
  accepted: true,
  deferred: false,
  package: 3,
  role: 0,
  readyForActivation: false,
  activationTransaction: null,
}, relay(4, 4, "alice"), "alice");
assert.equal(lamportReady.retryDeferred, true);
const earlyPeerSignature = deriveChainRelayTransition({
  accepted: false,
  deferred: true,
  package: 2,
  role: 1,
  readyForActivation: false,
  activationTransaction: null,
}, relay(2, 2, "bob"), "alice");
assert.equal(earlyPeerSignature.disposition, "deferred");
assert.equal(earlyPeerSignature.activationConsent, false);
const echoedLocalSignature = deriveChainRelayTransition({
  accepted: true,
  deferred: false,
  package: 2,
  role: 0,
  readyForActivation: true,
  activationTransaction: activationTransaction.buffer,
}, relay(3, 3, "alice"), "alice");
assert.equal(echoedLocalSignature.activationConsent, true);
assert.equal(echoedLocalSignature.activationSignatureSent, true);
assert.deepEqual([...echoedLocalSignature.activationTransaction], [...activationTransaction]);

function edgeProjection(edge, timeoutMaturesAt) {
  return {
    status: { phase: GamePhase.ACTIVE },
    intents: [{ name: "choose-runtime-edge", edges: [edge], timeoutMaturesAt }],
  };
}
function plan(edge, options = {}) {
  return planAuthorizedEdge({
    projection: edgeProjection(edge, options.timeoutMaturesAt),
    childNodeId: edge.childNodeId,
    localRole: options.localRole ?? 0,
    cards: options.cards ?? null,
    lastTipHeight: options.lastTipHeight,
  });
}

const action = {
  childNodeId: id(11),
  kind: { name: "action", action: 2 },
  authorization: { name: "betting-action", actor: 0 },
};
assert.deepEqual(plan(action).workerArguments, [2]);
assert.throws(() => plan(action, { localRole: 1 }), /selected actor/);
const reveal = {
  childNodeId: id(12),
  kind: { name: "community-reveal" },
  authorization: { name: "reveal-preimages", revealer: 1 },
};
assert.equal(plan(reveal, { localRole: 1 }).workerMethod, "buildReveal");
assert.throws(() => plan(reveal), /required revealer/);
const aliceShowdown = {
  childNodeId: id(13),
  kind: { name: "alice-showdown" },
  authorization: { name: "reveal-preimages" },
};
assert.equal(
  plan(aliceShowdown, { cards: { aliceHand: { subset: 2, score: 8 } } }).workerMethod,
  "buildAliceShowdown",
);
assert.throws(() => plan(aliceShowdown), /unavailable/);
const bobPayout = {
  childNodeId: id(14),
  kind: { name: "bob-payout", outcome: 2 },
  authorization: { name: "both-presigned" },
};
assert.equal(plan(bobPayout, {
  localRole: 1,
  cards: { bobHand: { subset: 3, score: 9 }, outcome: 2 },
}).workerArguments[0].outcome, 2);
assert.throws(() => plan(bobPayout, {
  localRole: 1,
  cards: { bobHand: { subset: 3, score: 9 }, outcome: 1 },
}), /unavailable/);
const timeout = {
  childNodeId: id(15),
  kind: { name: "timeout" },
  authorization: { name: "timeout", beneficiary: 0 },
};
assert.equal(plan(timeout, { timeoutMaturesAt: 200, lastTipHeight: 200 }).workerMethod, "buildTimeout");
assert.throws(
  () => plan(timeout, { timeoutMaturesAt: 200, lastTipHeight: 199 }),
  /not mature/,
);
const advance = {
  childNodeId: id(16),
  kind: { name: "advance" },
  authorization: { name: "both-presigned" },
};
assert.equal(plan(advance).workerMethod, "buildEdge");
assert.throws(
  () => planAuthorizedEdge({
    projection: edgeProjection(action),
    childNodeId: id(99),
    localRole: 0,
  }),
  /not reducer-authorized/,
);

assert.equal(localRoleMayAuthorizeEdge(action, 0), true);
assert.equal(localRoleMayAuthorizeEdge(action, 1), false);
assert.equal(selectAutomaticGameEdge([action, timeout], {
  localRole: 0,
  cards: {},
}), null, "strategic actions and timeout claims always require a click");
assert.equal(selectAutomaticGameEdge([reveal], {
  localRole: 1,
  cards: {},
}), reveal);
assert.equal(selectAutomaticGameEdge([reveal], {
  localRole: 0,
  cards: {},
}), null);
assert.equal(selectAutomaticGameEdge([advance], {
  localRole: 0,
  cards: {},
}), advance);
assert.equal(selectAutomaticGameEdge([advance], {
  localRole: 0,
  cards: {},
  authorizedChildNodeIds: [hexId(16)],
}), null, "an automatic edge is authorized at most once per browser session");
const failedAutomaticEdges = recordAutomaticEdgeResult(new Set(), hexId(16), false);
assert.equal(failedAutomaticEdges.has(hexId(16)), false, "a failed Worker action remains retryable");
assert.equal(selectAutomaticGameEdge([advance], {
  localRole: 0,
  cards: {},
  authorizedChildNodeIds: failedAutomaticEdges,
  retryReady: false,
}), null, "a transient automatic failure observes its retry backoff");
assert.equal(selectAutomaticGameEdge([advance], {
  localRole: 0,
  cards: {},
  authorizedChildNodeIds: failedAutomaticEdges,
  retryReady: true,
}), advance, "the same automatic edge is eligible again after its retry backoff");
const completedAutomaticEdges = recordAutomaticEdgeResult(failedAutomaticEdges, hexId(16), true);
assert.equal(completedAutomaticEdges.has(hexId(16)), true);
const authorizedAliceShowdown = {
  ...aliceShowdown,
  authorization: { name: "alice-score" },
};
assert.equal(selectAutomaticGameEdge([authorizedAliceShowdown], {
  localRole: 0,
  cards: { aliceHand: { subset: 2, score: 8 } },
}), authorizedAliceShowdown);
assert.equal(selectAutomaticGameEdge([authorizedAliceShowdown], {
  localRole: 0,
  cards: {},
}), null);
const authorizedBobPayout = {
  ...bobPayout,
  authorization: { name: "bob-live-payout" },
};
assert.equal(selectAutomaticGameEdge([authorizedBobPayout], {
  localRole: 1,
  cards: { bobHand: { subset: 3, score: 9 }, outcome: 2 },
}), authorizedBobPayout);
assert.equal(selectAutomaticGameEdge([authorizedBobPayout], {
  localRole: 1,
  cards: { bobHand: { subset: 3, score: 9 }, outcome: 1 },
}), null);

const confirmed = planConfirmedSpend({
  status: { phase: GamePhase.AWAITING_ACTIVATION },
}, {
  confirmedIn: { height: 100 },
  observedTip: { height: 101 },
  spendingTransaction: activationTransaction.buffer,
});
assert.equal(confirmed.activation, true);
assert.deepEqual([...confirmed.workerInput.transaction], [...activationTransaction]);
assert.throws(() => planConfirmedSpend({ status: {} }, {
  confirmedIn: { height: 102 },
  observedTip: { height: 101 },
  spendingTransaction: activationTransaction,
}), /invalid authenticated heights/);

const pendingMove = {
  ownsSeat: true,
  halted: false,
  busy: false,
  retryReady: true,
  originRefunded: false,
  pendingPurpose: 1,
  pendingTransactionPresent: true,
  pendingTxid: hexId(42),
  submitted: false,
};
assert.deepEqual(nextGameplayPublishAction(pendingMove), {
  kind: GameplayPublishAction.PUBLISH_MOVE,
  pendingTxid: hexId(42),
});
assert.equal(nextGameplayPublishAction({ ...pendingMove, busy: true }), null);
assert.equal(nextGameplayPublishAction({ ...pendingMove, submitted: true }), null);
assert.equal(nextGameplayPublishAction({ ...pendingMove, pendingPurpose: 0 }), null);
assert.equal(nextGameplayPublishAction({ ...pendingMove, originRefunded: true }), null);
// A failed publish remains pending but observes the retry backoff. Once the
// retry window opens it deterministically selects the same transaction again.
assert.equal(nextGameplayPublishAction({ ...pendingMove, retryReady: false }), null);
assert.deepEqual(
  nextGameplayPublishAction({ ...pendingMove, retryReady: true }),
  { kind: GameplayPublishAction.PUBLISH_MOVE, pendingTxid: hexId(42) },
);
assert.throws(
  () => nextGameplayPublishAction({ ...pendingMove, pendingTxid: "not-a-txid" }),
  /pending gameplay transaction id/u,
);

const payoutEdges = [0, 2, 1].map((outcome) => ({
  kind: { name: "bob-payout", outcome },
  childNodeId: id(20 + outcome),
}));
assert.equal(selectVerifiedSpecialEdge(payoutEdges, 1), payoutEdges[2]);
assert.equal(selectVerifiedSpecialEdge(payoutEdges, null), null);

process.stdout.write("browser flow pure orchestration tests ok\n");
