import { GamePhase } from "../game/game-runtime.js";
import {
  ChainPhase,
  ChainSetupKind,
} from "../chain/chain-runtime.js";

/**
 * Side-effect-free browser-flow policy.
 *
 * The coordinators own Workers, storage, and network I/O. Everything in this
 * module only validates data or chooses the next effect, which keeps protocol
 * ordering and authorization coverage in fast unit tests.
 */

export function byteView(value, label) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new Error(`${label} must be bytes`);
}

export function ownedBytes(value, label, expectedLength) {
  const bytes = byteView(value, label);
  if (expectedLength !== undefined && bytes.byteLength !== expectedLength) {
    throw new Error(`${label} must be exactly ${expectedLength} bytes`);
  }
  return Uint8Array.from(bytes);
}

export function exactHex(value, length, label) {
  if (typeof value !== "string" || !new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value)) {
    throw new Error(`${label} must be ${length} canonical lowercase hex bytes`);
  }
  return value;
}

export function hexToBytes(value, length, label) {
  exactHex(value, length, label);
  return Uint8Array.from(value.match(/../g), (pair) => Number.parseInt(pair, 16));
}

export function bytesToHex(value) {
  return Array.from(byteView(value, "hex value"), (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

export function bytesEqual(left, right) {
  const a = byteView(left, "left bytes");
  const b = byteView(right, "right bytes");
  return a.byteLength === b.byteLength && a.every((value, index) => value === b[index]);
}

export function concatBytes(...values) {
  const arrays = values.map((value) => byteView(value, "concatenated value"));
  const output = new Uint8Array(arrays.reduce((sum, value) => sum + value.byteLength, 0));
  let offset = 0;
  for (const value of arrays) {
    output.set(value, offset);
    offset += value.byteLength;
  }
  return output;
}

export function bytesToBase64(value) {
  const bytes = byteView(value, "base64 value");
  let output = "";
  for (let offset = 0; offset < bytes.byteLength; offset += 32 * 1024) {
    output += String.fromCharCode(...bytes.subarray(offset, offset + 32 * 1024));
  }
  return btoa(output);
}

/** Chain observation may only read the synchronous game projection after the
 * asynchronous coordinator start has completed. */
export function gameChainRefreshReady(state) {
  return Boolean(
    state?.sessionActive && state?.chainFlowPresent && state?.gameFlowPresent &&
    !state?.gameFlowStarting && !state?.chainHalted
  );
}

export function canonicalBase64ToBytes(value, {
  maximumDecodedBytes,
  maximumEncodedBytes,
  label = "game exchange payload",
} = {}) {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0) {
    throw new Error(`${label} is not canonical padded base64`);
  }
  if (Number.isSafeInteger(maximumEncodedBytes) && value.length > maximumEncodedBytes) {
    throw new Error(`${label} exceeds the deployment relay bound`);
  }
  let binary;
  try {
    binary = atob(value);
  } catch (_) {
    throw new Error(`${label} is not valid base64`);
  }
  if (Number.isSafeInteger(maximumDecodedBytes) && binary.length > maximumDecodedBytes) {
    throw new Error(`${label} exceeds its fixed bound`);
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytesToBase64(bytes) !== value) {
    throw new Error(`${label} is noncanonical base64`);
  }
  return bytes;
}

export function roleForRelaySender(sender, transportRole, localRole) {
  if (sender !== "alice" && sender !== "bob") {
    throw new Error("relay message has an invalid authenticated sender");
  }
  if (transportRole !== "alice" && transportRole !== "bob") {
    throw new Error("transport role must be alice or bob");
  }
  if (localRole !== 0 && localRole !== 1) {
    throw new Error("local role must be canonical Alice or Bob");
  }
  return sender === transportRole ? localRole : 1 - localRole;
}

export function normalizeRelayMessage(message, {
  kind,
  maximumDecodedBytes,
  maximumEncodedBytes,
  metadataError = "relay returned malformed exchange metadata",
} = {}) {
  if (
    !message || message.kind !== kind ||
    !Number.isSafeInteger(message.cursor) || message.cursor < 1 ||
    !/^[0-9a-f]{64}$/.test(message.messageId || "") ||
    (message.sender !== "alice" && message.sender !== "bob") ||
    typeof message.payload !== "string"
  ) {
    throw new Error(metadataError);
  }
  const event = canonicalBase64ToBytes(message.payload, {
    maximumDecodedBytes,
    maximumEncodedBytes,
  });
  return {
    message: {
      cursor: message.cursor,
      messageId: message.messageId,
      sender: message.sender,
      kind: message.kind,
      payload: message.payload,
    },
    event,
  };
}

/** Return a new relay-frame array while rejecting identifier rebinding. */
export function rememberRelayFrame(frames, message, {
  processed,
  retainKind = false,
  sortByCursor = false,
  reboundError = "a relay identifier was rebound to different bytes",
} = {}) {
  if (!Array.isArray(frames)) throw new Error("relay frames must be an array");
  const existing = frames.find((frame) => frame.messageId === message.messageId);
  if (existing) {
    if (
      existing.cursor !== message.cursor || existing.sender !== message.sender ||
      existing.payload !== message.payload ||
      (retainKind && existing.kind !== message.kind)
    ) {
      throw new Error(reboundError);
    }
    return { frames: frames.slice(), frame: existing, duplicate: true };
  }
  if (frames.some((frame) => frame.cursor === message.cursor)) {
    throw new Error("a relay cursor was assigned to multiple message identifiers");
  }
  const frame = {
    cursor: message.cursor,
    messageId: message.messageId,
    sender: message.sender,
    payload: message.payload,
  };
  if (retainKind) frame.kind = message.kind;
  if (processed !== undefined) frame.processed = processed;
  const next = [...frames, frame];
  if (sortByCursor) {
    next.sort((left, right) =>
      left.cursor - right.cursor || left.messageId.localeCompare(right.messageId)
    );
  }
  return { frames: next, frame, duplicate: false };
}

export function relayFramesInCursorOrder(frames, predicate = () => true) {
  return frames
    .filter(predicate)
    .slice()
    .sort((left, right) =>
      left.cursor - right.cursor || left.messageId.localeCompare(right.messageId)
    );
}

export const GameAdvanceKind = Object.freeze({
  WAIT_RELAY: "wait-relay",
  BUILD_DEAL_ENVELOPE: "build-deal-envelope",
  WAIT_DEAL_ENVELOPE: "wait-deal-envelope",
  SIGN_DEAL_RETRY: "sign-deal-retry",
  SIGN_ACCEPTED_DEAL: "sign-accepted-deal",
  DEAL_COMPLETE: "deal-complete",
  IDLE: "idle",
});

export function selectGameAdvance({ projection, localRole, hasPendingRelay }) {
  if (!projection?.status || !Array.isArray(projection.intents)) {
    throw new Error("game projection is unavailable");
  }
  if (localRole !== 0 && localRole !== 1) throw new Error("invalid canonical local role");
  if (hasPendingRelay) {
    return {
      kind: GameAdvanceKind.WAIT_RELAY,
      stage: "awaiting-relay",
      detail: "Waiting for the relay to echo the durable local frame…",
    };
  }
  const intent = projection.intents[0];
  if (intent?.name === "deal-envelope-due") {
    if ((intent.sender !== 0 && intent.sender !== 1) ||
        !Number.isSafeInteger(intent.sequence) || intent.sequence < 0) {
      throw new Error("game reducer returned an invalid DEAL envelope intent");
    }
    if (intent.sender !== localRole) {
      return {
        kind: GameAdvanceKind.WAIT_DEAL_ENVELOPE,
        stage: "dealing",
        detail: `Private deal ${projection.status.dealEnvelopes}/16 · waiting for ${intent.sender === 0 ? "Alice" : "Bob"}`,
        intent,
      };
    }
    return {
      kind: GameAdvanceKind.BUILD_DEAL_ENVELOPE,
      stage: "dealing",
      detail: `Building authenticated private-deal envelope ${intent.sequence + 1}/16…`,
      intent,
    };
  }
  if (intent?.name === "approve-deal-retry") {
    return {
      kind: GameAdvanceKind.SIGN_DEAL_RETRY,
      stage: "deal-retry",
      detail: "Starting a fresh shuffle…",
      intent,
    };
  }
  if (intent?.name === "sign-accepted-deal") {
    return {
      kind: GameAdvanceKind.SIGN_ACCEPTED_DEAL,
      stage: "accepting-deal",
      detail: "Authenticating the verifier-derived private deal…",
      intent,
    };
  }
  if (projection.status.phase >= GamePhase.SIGNING_DESCRIPTOR) {
    return {
      kind: GameAdvanceKind.DEAL_COMPLETE,
      stage: "private-deal-complete",
      detail: "Private deal complete · preparing the fixed transaction graph locally…",
    };
  }
  return { kind: GameAdvanceKind.IDLE };
}

export function dealVerificationIsDue(projection) {
  if (!projection?.status) throw new Error("game projection is unavailable");
  const { phase, dealEnvelopes } = projection.status;
  if (!Number.isSafeInteger(dealEnvelopes) || dealEnvelopes < 0 || dealEnvelopes > 16) {
    throw new Error("game projection has an invalid DEAL envelope count");
  }
  return phase === GamePhase.DEALING && dealEnvelopes === 16;
}

export function normalizeDealDispatch(dispatch) {
  if (!dispatch || typeof dispatch !== "object") {
    throw new Error("game Worker returned an invalid private-DEAL dispatch");
  }
  if (dispatch.kind === "none") return { kind: "none" };
  if (dispatch.kind === "deal-envelope") {
    return { kind: dispatch.kind, envelope: ownedBytes(dispatch.envelope, "DEAL envelope") };
  }
  if (dispatch.kind === "accepted-deal-signature") {
    if (dispatch.role !== 0 && dispatch.role !== 1) {
      throw new Error("game Worker returned an invalid accepted-DEAL role");
    }
    return {
      kind: dispatch.kind,
      role: dispatch.role,
      signature: ownedBytes(dispatch.signature, "accepted-DEAL signature", 64),
    };
  }
  if (dispatch.kind === "deal-retry-signature") {
    if (!Number.isSafeInteger(dispatch.nextAttempt) || dispatch.nextAttempt < 1) {
      throw new Error("game Worker returned an invalid DEAL retry attempt");
    }
    if (dispatch.role !== 0 && dispatch.role !== 1) {
      throw new Error("game Worker returned an invalid DEAL retry role");
    }
    return {
      kind: dispatch.kind,
      nextAttempt: dispatch.nextAttempt,
      role: dispatch.role,
      signature: ownedBytes(dispatch.signature, "DEAL retry signature", 64),
    };
  }
  throw new Error("game Worker returned an unknown private-DEAL dispatch");
}

export function verifyAcceptedDealRecovery(record, durable) {
  const expected = record?.accepted;
  if (
    !expected || !durable || durable.version !== record.version ||
    durable.contextDigest !== record.contextDigest ||
    durable.revision !== record.revision ||
    durable.storageKeyHex !== record.storageKeyHex ||
    !durable.accepted
  ) {
    throw new Error("durable accepted-DEAL recovery record failed its read-back check");
  }
  let deal;
  let attestation;
  let sealedPreimages;
  try {
    deal = ownedBytes(durable.accepted.deal, "durable accepted deal");
    attestation = ownedBytes(
      durable.accepted.attestation,
      "durable DEAL verification attestation",
    );
    sealedPreimages = ownedBytes(
      durable.accepted.sealedPreimages,
      "durable sealed DEAL preimages",
    );
  } catch (_) {
    throw new Error("durable accepted-DEAL recovery record failed its byte check");
  }
  if (
    !bytesEqual(deal, expected.deal) ||
    !bytesEqual(attestation, expected.attestation) ||
    !bytesEqual(sealedPreimages, expected.sealedPreimages)
  ) {
    throw new Error("durable accepted-DEAL recovery record failed its byte check");
  }
  return { deal, attestation, sealedPreimages, storageKeyHex: durable.storageKeyHex };
}

export function normalizeSetupAcceptance(result) {
  if (!result || typeof result.applicable !== "boolean") {
    throw new Error("CHAIN Worker returned an invalid setup acknowledgement");
  }
  const localLamportBundle = ownedBytes(
    result.localLamportBundle ?? new Uint8Array(),
    "local Lamport bundle",
  );
  if (!result.applicable) {
    return {
      applicable: false,
      localLamportBundle,
      checkpointReceipt: result.checkpointReceipt,
    };
  }
  if (
    !Number.isSafeInteger(result.setupKind) ||
    result.setupKind < ChainSetupKind.DESCRIPTOR_SIGNATURE ||
    result.setupKind > ChainSetupKind.PREAUTHORIZATION_OPENING
  ) {
    throw new Error("CHAIN Worker returned an invalid setup kind");
  }
  return {
    applicable: true,
    setupKind: result.setupKind,
    localLamportBundle,
    checkpointReceipt: result.checkpointReceipt,
  };
}

export function deriveChainRecovery(acknowledgement, projection, localRole) {
  if (
    !acknowledgement?.acknowledged ||
    acknowledgement.localRole !== localRole
  ) {
    throw new Error("CHAIN Worker acknowledged a different canonical role");
  }
  const runtimeStatus = acknowledgement.runtimeStatus;
  const pendingActivation = projection?.intents?.find(
    (intent) => intent.name === "broadcast-transaction" && intent.purpose === 0,
  );
  const activationTransaction = pendingActivation?.transaction
    ? ownedBytes(pendingActivation.transaction, "restored activation transaction")
    : undefined;
  const recoveredPhase = acknowledgement.recovered
    ? runtimeStatus?.phase ?? acknowledgement.phase
    : ChainPhase.EMPTY;
  if (!Number.isSafeInteger(recoveredPhase)) {
    throw new Error("CHAIN Worker returned an invalid recovered phase");
  }
  return {
    recoveredPhase,
    activationTransaction,
    inventoryVerified: Boolean(runtimeStatus?.inventoryVerified),
  };
}

/**
 * Let Alice materialize second so two tabs never compile the 56k-state graph
 * concurrently. Bob publishes only after accepting Alice's bundle and finishing
 * his own materialization; Alice's bundle is the deterministic hand-off token.
 */
export function mayPublishLamportBundle(localRole, recoveredPhase) {
  if ((localRole !== 0 && localRole !== 1) || !Number.isSafeInteger(recoveredPhase)) {
    throw new Error("Lamport publication state is invalid");
  }
  return localRole === 0 || recoveredPhase >= ChainPhase.GRAPH_READY;
}

export function deriveChainRelayTransition(result, message, transportRole) {
  if (
    !result || typeof result.accepted !== "boolean" ||
    typeof result.deferred !== "boolean" ||
    typeof result.readyForActivation !== "boolean" ||
    result.accepted !== !result.deferred ||
    !Number.isSafeInteger(result.package) || result.package < 1 || result.package > 7 ||
    (result.role !== 0 && result.role !== 1)
  ) {
    throw new Error("CHAIN Worker returned an invalid relay acknowledgement");
  }
  if (result.deferred && result.activationTransaction) {
    throw new Error("deferred CHAIN relay acknowledgement assembled an activation");
  }
  if (result.package !== 2 && result.activationTransaction) {
    throw new Error("a non-activation package unexpectedly assembled an activation");
  }
  if (message?.sender !== "alice" && message?.sender !== "bob") {
    throw new Error("CHAIN relay transition has an invalid authenticated sender");
  }
  if (transportRole !== "alice" && transportRole !== "bob") {
    throw new Error("CHAIN relay transition has an invalid transport role");
  }
  const local = message.sender === transportRole;
  return {
    disposition: result.deferred ? "deferred" : "applied",
    package: result.package,
    role: result.role,
    setup: result.setup ?? null,
    readyForActivation: Boolean(result.readyForActivation),
    inventoryReadySent: result.package === 1 && local,
    activationConsent: result.package === 2 && local,
    activationSignatureSent: result.package === 2 && local,
    retryDeferred: !result.deferred && result.package !== 2,
    activationTransaction: result.activationTransaction
      ? ownedBytes(result.activationTransaction, "assembled activation transaction")
      : undefined,
  };
}

export function planAuthorizedEdge({
  projection,
  childNodeId,
  localRole,
  cards,
  lastTipHeight,
}) {
  if (localRole !== 0 && localRole !== 1) {
    throw new Error("invalid canonical local role");
  }
  const intent = projection?.intents?.find((value) => value.name === "choose-runtime-edge");
  if (!intent) throw new Error("the reducer is not accepting a gameplay choice");
  const requested = typeof childNodeId === "string"
    ? exactHex(childNodeId, 32, "child node id")
    : bytesToHex(childNodeId);
  const edge = intent.edges.find((value) => bytesToHex(value.childNodeId) === requested);
  if (!edge) throw new Error("the requested gameplay edge is not reducer-authorized");
  if (edge.kind.name === "action") {
    if (edge.authorization.name !== "betting-action" || edge.authorization.actor !== localRole) {
      throw new Error("only the reducer-selected actor may choose this action");
    }
    return { edge, workerMethod: "buildAction", workerArguments: [edge.kind.action] };
  }
  if (["hole-card-reveal", "community-reveal"].includes(edge.kind.name)) {
    if (edge.authorization.name !== "reveal-preimages" ||
        edge.authorization.revealer !== localRole) {
      throw new Error("the peer is the required revealer for this branch");
    }
    return { edge, workerMethod: "buildReveal", workerArguments: [] };
  }
  if (edge.kind.name === "alice-showdown") {
    if (localRole !== 0 || !cards?.aliceHand) {
      throw new Error("Alice's verified showdown hand is unavailable");
    }
    return { edge, workerMethod: "buildAliceShowdown", workerArguments: [cards.aliceHand] };
  }
  if (edge.kind.name === "bob-payout") {
    if (
      localRole !== 1 || !cards?.bobHand || ![0, 1, 2].includes(cards.outcome) ||
      edge.kind.outcome !== cards.outcome
    ) {
      throw new Error("Bob's verified payout proof is unavailable");
    }
    return {
      edge,
      workerMethod: "buildBobPayout",
      workerArguments: [{ ...cards.bobHand, outcome: edge.kind.outcome }],
    };
  }
  if (edge.kind.name === "timeout") {
    if (
      edge.authorization.name !== "timeout" ||
      edge.authorization.beneficiary !== localRole ||
      !Number.isSafeInteger(intent.timeoutMaturesAt) ||
      !Number.isSafeInteger(lastTipHeight) ||
      lastTipHeight < intent.timeoutMaturesAt
    ) {
      throw new Error("this timeout is not mature for the local beneficiary");
    }
    return { edge, workerMethod: "buildTimeout", workerArguments: [] };
  }
  if (edge.kind.name === "advance" && edge.authorization.name === "both-presigned") {
    return {
      edge,
      workerMethod: "buildEdge",
      workerArguments: [{ childNodeId: ownedBytes(edge.childNodeId, "child node id", 32) }],
    };
  }
  throw new Error("this reducer-authorized edge needs a Rust builder not present in v1");
}

export function localRoleMayAuthorizeEdge(edge, localRole) {
  if (!edge || (localRole !== 0 && localRole !== 1)) return false;
  if (edge.authorization?.name === "betting-action") {
    return edge.authorization.actor === localRole;
  }
  if (edge.authorization?.name === "reveal-preimages") {
    return edge.authorization.revealer === localRole;
  }
  if (edge.authorization?.name === "alice-score") return localRole === 0;
  if (edge.authorization?.name === "bob-live-payout") return localRole === 1;
  if (edge.authorization?.name === "timeout") {
    return edge.authorization.beneficiary === localRole;
  }
  return edge.authorization?.name === "both-presigned" && edge.kind?.name === "advance";
}

/** Select a non-strategic edge that does not need another player decision. */
export function selectAutomaticGameEdge(edges, {
  localRole,
  cards,
  authorizedChildNodeIds = [],
  retryReady = true,
} = {}) {
  if (!retryReady || !Array.isArray(edges)) return null;
  const authorized = new Set(authorizedChildNodeIds);
  const candidates = edges.filter((edge) =>
    ["hole-card-reveal", "community-reveal", "advance", "alice-showdown", "bob-payout"]
      .includes(edge?.kind?.name) &&
    localRoleMayAuthorizeEdge(edge, localRole) &&
    !authorized.has(bytesToHex(edge.childNodeId))
  );
  for (const edge of candidates) {
    if (edge.kind.name === "alice-showdown" && !cards?.aliceHand) continue;
    if (
      edge.kind.name === "bob-payout" &&
      (!cards?.bobHand || ![0, 1, 2].includes(cards?.outcome) || edge.kind.outcome !== cards.outcome)
    ) continue;
    return edge;
  }
  return null;
}

/** Return a new authorization set, recording only a completed Worker action. */
export function recordAutomaticEdgeResult(authorizedChildNodeIds, childNodeId, succeeded) {
  const next = new Set(authorizedChildNodeIds);
  const id = exactHex(childNodeId, 32, "automatic child node id");
  if (succeeded) next.add(id);
  return next;
}

export function planConfirmedSpend(projection, event) {
  if (!event?.confirmedIn || !event?.observedTip) {
    throw new Error("confirmed spend is missing authenticated block facts");
  }
  if (
    !Number.isSafeInteger(event.confirmedIn.height) ||
    !Number.isSafeInteger(event.observedTip.height) ||
    event.confirmedIn.height < 0 ||
    event.observedTip.height < event.confirmedIn.height
  ) {
    throw new Error("confirmed spend has invalid authenticated heights");
  }
  return {
    activation: projection?.status?.phase === GamePhase.AWAITING_ACTIVATION,
    workerInput: {
      confirmedHeight: event.confirmedIn.height,
      tipHeight: event.observedTip.height,
      transaction: ownedBytes(event.spendingTransaction, "spending transaction"),
    },
  };
}

export const GameplayPublishAction = Object.freeze({
  PUBLISH_MOVE: "publish-move",
});

/**
 * Decide whether an already authorized Rust/Wasm gameplay transaction should
 * be published. Authorization itself stays outside this policy; this only
 * removes the redundant second click once the verified transaction exists.
 */
export function nextGameplayPublishAction(state) {
  if (!state || state.pendingPurpose !== 1) return null;
  if (!state.pendingTransactionPresent || !state.pendingTxid) return null;
  const pendingTxid = exactHex(state.pendingTxid, 32, "pending gameplay transaction id");
  if (
    !state.ownsSeat || state.halted || state.busy || !state.retryReady ||
    state.originRefunded || state.submitted
  ) return null;
  return { kind: GameplayPublishAction.PUBLISH_MOVE, pendingTxid };
}

export function selectVerifiedSpecialEdge(edges, verifiedOutcome) {
  if (!Array.isArray(edges)) return null;
  const special = edges.filter(
    (edge) => edge?.kind && !["action", "timeout"].includes(edge.kind.name),
  );
  const payouts = special.filter((edge) => edge.kind.name === "bob-payout");
  if (payouts.length === 0) return special[0] ?? null;
  if (![0, 1, 2].includes(verifiedOutcome)) return null;
  const matching = payouts.filter((edge) => edge.kind.outcome === verifiedOutcome);
  return matching.length === 1 ? matching[0] : null;
}
