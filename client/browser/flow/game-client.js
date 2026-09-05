import {
  GameEventSource,
  GameEventType,
  GamePhase,
  encodeSessionEvent,
} from "../game/game-runtime.js";
import { loadWasmBytes } from "../config/wasm-loader.js";
import { WorkerRpcClient } from "../worker/rpc-client.js";
import {
  GameAdvanceKind,
  dealVerificationIsDue,
  byteView as asBytes,
  bytesEqual,
  bytesToBase64,
  bytesToHex,
  canonicalBase64ToBytes,
  exactHex,
  hexToBytes,
  normalizeDealDispatch,
  normalizeRelayMessage,
  relayFramesInCursorOrder,
  roleForRelaySender,
  selectGameAdvance,
  verifyAcceptedDealRecovery,
} from "./orchestration.js";

const RECORD_VERSION = 3;

function base64ToBytes(value, maximum) {
  return canonicalBase64ToBytes(value, { maximumDecodedBytes: maximum });
}

async function sha256(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", asBytes(value, "hash value")));
}

function checkpointReceipt(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error("CHAIN verification did not return a durable checkpoint receipt");
  }
  return value;
}

/** Compact one processed relay frame without losing replay/rebinding evidence. */
export function compactProcessedGameFrame(frame, {
  payloadSha256,
  disposition,
  chainCheckpointReceipt,
  dealRecoveryRevision,
  gameRevision,
} = {}) {
  const hasChainReceipt = chainCheckpointReceipt !== undefined;
  const hasDealRecovery = Number.isSafeInteger(dealRecoveryRevision) && dealRecoveryRevision > 0;
  if (
    !frame || !Number.isSafeInteger(frame.cursor) || frame.cursor < 1 ||
    !/^[0-9a-f]{64}$/.test(frame.messageId || "") ||
    (frame.sender !== "alice" && frame.sender !== "bob") ||
    !/^[0-9a-f]{64}$/.test(payloadSha256 || "") ||
    (disposition !== "game" && disposition !== "verified-receipt") ||
    !Number.isSafeInteger(gameRevision) || gameRevision < 1 ||
    (!hasChainReceipt && !hasDealRecovery) ||
    (disposition === "verified-receipt" && !hasChainReceipt)
  ) {
    throw new Error("processed game frame cannot be compacted without exact durable bindings");
  }
  const compact = {
    cursor: frame.cursor,
    messageId: frame.messageId,
    sender: frame.sender,
    payloadSha256,
    disposition,
    processed: true,
    gameRevision,
  };
  if (hasChainReceipt) compact.chainCheckpointReceipt = checkpointReceipt(chainCheckpointReceipt);
  if (hasDealRecovery) compact.dealRecoveryRevision = dealRecoveryRevision;
  return compact;
}

function validateContext(context) {
  if (!context || typeof context !== "object") throw new Error("game context is required");
  exactHex(context.roomId, 32, "roomId");
  exactHex(context.sessionNonceHex, 32, "sessionNonceHex");
  exactHex(context.localSecretKeyHex, 32, "localSecretKeyHex");
  exactHex(context.localXOnlyKeyHex, 32, "localXOnlyKeyHex");
  exactHex(context.peerXOnlyKeyHex, 32, "peerXOnlyKeyHex");
  exactHex(context.origin?.displayTxid, 32, "origin.displayTxid");
  exactHex(context.origin?.scriptPubkeyHex, 34, "origin.scriptPubkeyHex");
  exactHex(context.origin?.witnessScriptHex, 104, "origin.witnessScriptHex");
  if (context.transportRole !== "alice" && context.transportRole !== "bob") {
    throw new Error("transportRole must be alice or bob");
  }
  if (context.localXOnlyKeyHex === context.peerXOnlyKeyHex) {
    throw new Error("the two identity keys must be distinct");
  }
  const deployment = context.deploymentConfig;
  if (
    !deployment?.relay?.kinds?.gameExchange ||
    !Number.isSafeInteger(deployment.protocolProfileCode) ||
    deployment.protocolProfileCode < 0 || deployment.protocolProfileCode > 0xff ||
    !Number.isSafeInteger(deployment.chain?.bitcoinNetworkCode) ||
    deployment.chain.bitcoinNetworkCode < 0 || deployment.chain.bitcoinNetworkCode > 0xff ||
    !Number.isSafeInteger(deployment.relay.maxPayloadBase64Bytes) ||
    !/^[0-9a-f]{64}$/.test(deployment.deploymentDigestHex || "") ||
    !/^[0-9a-f]{64}$/.test(deployment.chain?.profileIdHex || "") ||
    !Number.isSafeInteger(deployment.game?.originValueSat)
  ) {
    throw new Error("validated deploymentConfig is required");
  }
  if (context.origin.vout !== 0 || context.origin.valueSat !== deployment.game.originValueSat) {
    throw new Error("origin does not match the configured deployment output");
  }
  if (!context.chain || typeof context.chain.originFact !== "function") {
    throw new Error("an authenticated chain adapter is required");
  }
  if (typeof context.sendExchange !== "function") {
    throw new Error("sendExchange callback is required");
  }
}

function publicContext(context, identities, localRole) {
  const { chain, game, relay, deploymentId } = context.deploymentConfig;
  return {
    version: RECORD_VERSION,
    deploymentId,
    deploymentDigestHex: context.deploymentConfig.deploymentDigestHex,
    networkId: chain.profileIdHex,
    gameExchangeKind: relay.kinds.gameExchange,
    originConfirmationDepth: chain.confirmations.origin,
    gameplayConfirmationDepth: chain.confirmations.gameplay,
    activationFeeSat: game.activationFeeSat,
    button: game.button,
    revealOrder: game.revealOrder,
    splitRemainderRecipient: game.splitRemainderRecipient,
    roomId: context.roomId,
    sessionNonceHex: context.sessionNonceHex,
    transportRole: context.transportRole,
    localXOnlyKeyHex: context.localXOnlyKeyHex,
    peerXOnlyKeyHex: context.peerXOnlyKeyHex,
    identities: identities.map(bytesToHex),
    localRole,
    origin: {
      displayTxid: context.origin.displayTxid,
      vout: context.origin.vout,
      valueSat: context.origin.valueSat,
      scriptPubkeyHex: context.origin.scriptPubkeyHex,
      witnessScriptHex: context.origin.witnessScriptHex,
    },
  };
}

async function contextDigest(value) {
  return bytesToHex(await sha256(new TextEncoder().encode(JSON.stringify(value))));
}

function newSecretHex() {
  const value = new Uint8Array(32);
  crypto.getRandomValues(value);
  const encoded = bytesToHex(value);
  value.fill(0);
  return encoded;
}

function randomMessageId() {
  const value = new Uint8Array(32);
  crypto.getRandomValues(value);
  const encoded = bytesToHex(value);
  value.fill(0);
  return encoded;
}

function createProtocolWorkerRpc(url, workerFactory) {
  const worker = workerFactory
    ? workerFactory(url)
    : new Worker(url, { type: "module" });
  return new WorkerRpcClient(worker);
}

export class IndexedDbGameStore {
  constructor(indexedDb = globalThis.indexedDB) {
    if (!indexedDb) throw new Error("IndexedDB is required for durable private-game recovery");
    this.indexedDb = indexedDb;
    this.database = undefined;
  }

  async load(key) {
    const database = await this.#open();
    return new Promise((resolve, reject) => {
      const transaction = database.transaction("flows", "readonly");
      const request = transaction.objectStore("flows").get(key);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error("private-game recovery state could not be read"));
    });
  }

  async save(key, value) {
    const database = await this.#open();
    await new Promise((resolve, reject) => {
      const transaction = database.transaction("flows", "readwrite");
      transaction.objectStore("flows").put(value, key);
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new Error("private-game recovery state could not be saved"));
      transaction.onabort = () => reject(new Error("private-game recovery state save was aborted"));
    });
    const restored = await this.load(key);
    if (!restored || restored.revision !== value.revision || restored.contextDigest !== value.contextDigest) {
      throw new Error("private-game recovery state failed its durable read-back check");
    }
  }

  #open() {
    if (this.database) return this.database;
    this.database = new Promise((resolve, reject) => {
      const request = this.indexedDb.open("bp52-private-game-v2", 1);
      request.onupgradeneeded = () => request.result.createObjectStore("flows");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error("private-game recovery database is unavailable"));
    });
    return this.database;
  }
}

export class MemoryGameStore {
  constructor() {
    this.records = new Map();
  }

  async load(key) {
    return structuredClone(this.records.get(key));
  }

  async save(key, value) {
    this.records.set(key, structuredClone(value));
  }
}

/**
 * Browser coordinator for the public reducer and the private DEAL runtime.
 * The relay sees only already-authenticated SessionEvent bytes.
 */
export class BrowserGameFlow {
  constructor(context, options = {}) {
    validateContext(context);
    this.context = context;
    this.deployment = context.deploymentConfig;
    this.gameExchangeKind = this.deployment.relay.kinds.gameExchange;
    this.maxExchangeBytes = Math.floor(
      this.deployment.relay.maxPayloadBase64Bytes / 4
    ) * 3;
    this.store = options.store ?? new IndexedDbGameStore();
    this.workerFactory = options.workerFactory;
    this.gameWasm = options.gameWasm;
    this.dealWasm = options.dealWasm;
    this.gameWorkerUrl = options.gameWorkerUrl ?? "/browser/game/game-worker.js";
    this.dealWorkerUrl = options.dealWorkerUrl ?? "/browser/deal/deal-worker.js";
    this.onUpdate = context.onUpdate ?? (() => {});
    this.onProjection = context.onProjection ?? (() => {});
    this.identities = [
      hexToBytes(context.localXOnlyKeyHex, 32, "localXOnlyKeyHex"),
      hexToBytes(context.peerXOnlyKeyHex, 32, "peerXOnlyKeyHex"),
    ].sort((left, right) => bytesToHex(left).localeCompare(bytesToHex(right)));
    this.localRole = bytesToHex(this.identities[0]) === context.localXOnlyKeyHex ? 0 : 1;
    this.key = [
      context.deploymentConfig.deploymentDigestHex,
      context.roomId,
      context.transportRole,
    ].join("/");
    this.closed = false;
    this.started = false;
    this.operation = Promise.resolve();
    this.ephemeralPreparedAttempts = new Set();
    this.localDealMutations = new Set();
  }

  start() {
    return this.#enqueue(() => this.#start());
  }

  acceptRelayMessage(message, verification) {
    return this.#enqueue(() => this.#acceptRelayMessage(message, verification));
  }

  stageRelayMessage(message) {
    return this.#enqueue(() => this.#stageRelayMessage(message));
  }

  publishExchangeEvent(event) {
    return this.#enqueue(async () => {
      this.#requireStarted();
      if (!event || typeof event !== "object" || event instanceof ArrayBuffer || ArrayBuffer.isView(event)) {
        throw new Error("published exchange events must be structured local events");
      }
      if (event.type === GameEventType.ACTIVATION_AUTHORIZED && !this.#activationIsLocallyReady()) {
        throw new Error("activation cannot be published before local inventory and preauthorizations verify");
      }
      const bytes = encodeSessionEvent(event);
      await this.#publish(bytes, `external:${event.type}`);
    });
  }

  applyGraphPreparedReceipt(receipt) {
    return this.#enqueue(() => this.#applyRuntimeReceipt("apply-graph-prepared-receipt", receipt));
  }

  applyRuntimeAuthorizationReceipt(receipt) {
    return this.#enqueue(() => this.#applyRuntimeReceipt(
      "apply-runtime-authorization-receipt",
      receipt,
    ));
  }

  applyConfirmedStateReceipt(receipt) {
    return this.#enqueue(() => this.#applyRuntimeReceipt("apply-confirmed-state-receipt", receipt));
  }

  applyOffchainStateReceipt(receipt) {
    return this.#enqueue(() => this.#applyRuntimeReceipt("apply-offchain-state-receipt", receipt));
  }

  applyLocalWalletEvent(event) {
    return this.#enqueue(() => this.#applyLocalEvent(GameEventSource.LOCAL_WALLET, event));
  }

  applyChainEvent(event) {
    return this.#enqueue(() => this.#applyLocalEvent(GameEventSource.AUTHENTICATED_CHAIN, event));
  }

  /**
   * Hand the sealed accepted-DEAL recovery package to a secret Worker. The
   * durable copy is byte-verified before the memory-heavy DEAL Worker is
   * closed, so a failed consumer can retry from sealed storage after reload.
   * Plaintext preimages are never materialized in this coordinator.
   */
  handoffAcceptedDeal(consumer) {
    return this.#enqueue(async () => {
      this.#requireStarted();
      if (typeof consumer !== "function") throw new Error("accepted-DEAL consumer is required");
      if (!this.record.accepted) throw new Error("accepted DEAL is not durably available yet");
      const recovery = await this.#readBackAcceptedDeal();
      const deal = this.deal;
      this.deal = undefined;
      await deal?.close();

      const storageKey = hexToBytes(recovery.storageKeyHex, 32, "DEAL storage key");
      let acknowledgement;
      try {
        acknowledgement = await consumer({
          deal: recovery.deal,
          attestation: recovery.attestation,
          sealedPreimages: recovery.sealedPreimages,
          storageKey,
        });
      } finally {
        if (storageKey.byteLength > 0) storageKey.fill(0);
      }
      if (acknowledgement !== true && acknowledgement?.accepted !== true) {
        throw new Error("secret Worker did not acknowledge the accepted-DEAL handoff");
      }
      this.record.acceptedHandedOff = true;
      await this.#saveRecord();
      return this.#view();
    });
  }

  async cancel() {
    this.closed = true;
    await Promise.allSettled([this.game?.close(), this.deal?.close()]);
    this.game = undefined;
    this.deal = undefined;
  }

  view() {
    return this.#view();
  }

  currentProjection() {
    this.#requireStarted();
    return structuredClone(this.projection);
  }

  exchangeHistory() {
    this.#requireStarted();
    return this.record.frames
      .filter((frame) => typeof frame.payload === "string")
      .map((frame) => ({
        cursor: frame.cursor,
        messageId: frame.messageId,
        sender: frame.sender,
        kind: this.gameExchangeKind,
        payload: frame.payload,
      }));
  }

  async #start() {
    if (this.started) return this.#view();
    this.#assertOpen();
    this.#update("verifying-origin", "Rechecking the exact confirmed deployment origin…");
    const publicBinding = publicContext(this.context, this.identities, this.localRole);
    const digest = await contextDigest(publicBinding);
    let record = await this.store.load(this.key);
    if (record) {
      if (record.version !== RECORD_VERSION || record.contextDigest !== digest) {
        throw new Error("saved private-game state belongs to a different immutable game context");
      }
    } else {
      record = {
        version: RECORD_VERSION,
        contextDigest: digest,
        publicBinding,
        entropyHex: newSecretHex(),
        storageKeyHex: newSecretHex(),
        frames: [],
        outbox: [],
        revision: 0,
      };
      await this.#saveRecord(record);
    }
    this.record = record;

    const fact = await this.context.chain.originFact({
      outpoint: { displayTxid: this.context.origin.displayTxid, vout: 0 },
      valueSat: this.deployment.game.originValueSat,
      scriptPubkey: hexToBytes(this.context.origin.scriptPubkeyHex, 34, "origin scriptPubkey"),
      minConfirmations: this.deployment.chain.confirmations.origin,
    });
    if (!fact) throw new Error("the exact origin is not yet confirmed on the configured chain");
    this.#assertOpen();

    this.game = createProtocolWorkerRpc(this.gameWorkerUrl, this.workerFactory);
    const config = {
      protocolProfile: this.deployment.protocolProfileCode,
      bitcoinNetwork: this.deployment.chain.bitcoinNetworkCode,
      networkId: hexToBytes(this.deployment.chain.profileIdHex, 32, "network id"),
      originOutpoint: {
        displayTxid: hexToBytes(this.context.origin.displayTxid, 32, "origin txid"),
        vout: 0,
      },
      relayRoomId: hexToBytes(this.context.roomId, 32, "room id"),
      dealSessionNonce: hexToBytes(this.context.sessionNonceHex, 32, "session nonce"),
      identityKeys: this.identities,
      localRole: this.localRole,
      originConfirmationDepth: this.deployment.chain.confirmations.origin,
      gameplayConfirmationDepth: this.deployment.chain.confirmations.gameplay,
      button: this.deployment.game.button === "alice" ? 0 : 1,
      revealOrder: [
        this.deployment.game.revealOrder.flopFirst === "alice" ? 0 : 1,
        this.deployment.game.revealOrder.turnFirst === "alice" ? 0 : 1,
        this.deployment.game.revealOrder.riverFirst === "alice" ? 0 : 1,
      ],
      splitRemainderRecipient:
        this.deployment.game.splitRemainderRecipient === "alice" ? 0 : 1,
      originValueSat: BigInt(this.deployment.game.originValueSat),
      activationFeeSat: BigInt(this.deployment.game.activationFeeSat),
      originWitnessScript: hexToBytes(
        this.context.origin.witnessScriptHex,
        104,
        "origin witness script",
      ),
    };
    const gameWasm = this.gameWasm ?? await loadWasmBytes("game");
    let initialized;
    if (record.gameSnapshot) {
      initialized = await this.game.request("replay", {
        wasm: gameWasm,
        config,
        snapshot: record.gameSnapshot,
      });
    } else {
      initialized = await this.game.request("init", { wasm: gameWasm, config });
      initialized = await this.game.request("apply-event", {
        source: GameEventSource.AUTHENTICATED_CHAIN,
        event: { type: GameEventType.ORIGIN_CONFIRMED, ...fact },
      });
      await this.#saveGameSnapshot();
    }
    this.projection = initialized.projection;

    if (!record.accepted) {
      this.deal = createProtocolWorkerRpc(this.dealWorkerUrl, this.workerFactory);
      const localSecretKey = hexToBytes(this.context.localSecretKeyHex, 32, "local secret key");
      const entropy = hexToBytes(record.entropyHex, 32, "saved DEAL entropy");
      try {
        const dealWasm = this.dealWasm ?? await loadWasmBytes("deal");
        const dealInit = await this.deal.request("init", {
          wasm: dealWasm,
          request: {
            sharedConfigHash: this.projection.status.sharedConfigHash,
            sessionNonce: hexToBytes(this.context.sessionNonceHex, 32, "session nonce"),
            gameId: this.projection.status.dealGameId,
            localSecretKey,
            identityKeys: this.identities,
            entropy,
          },
        });
        if (dealInit.snapshot.localRole !== this.localRole) {
          throw new Error("DEAL and game reducers disagree on the canonical local role");
        }
      } finally {
        localSecretKey.fill(0);
        entropy.fill(0);
      }
      this.#update("recovering-deal", "Replaying the durable private-deal transcript…");
      for (const frame of relayFramesInCursorOrder(
        record.frames,
        (value) => value.processed,
      )) {
        const event = base64ToBytes(frame.payload, this.maxExchangeBytes);
        const replayed = await this.game.request("apply-exchange-event", {
          senderRole: this.#roleForSender(frame.sender),
          event,
        });
        this.projection = replayed.projection;
        await this.#applyToDeal(frame, replayed.dealDispatch, true);
      }
    }

    this.started = true;
    await this.#flushOutbox();
    await this.#advance();
    return this.#view();
  }

  async #acceptRelayMessage(message, verification) {
    this.#requireStarted();
    const remembered = await this.#stageRelayMessage(message);
    if (remembered.frame.processed) {
      if (remembered.frame.disposition !== "game") {
        throw new Error("a processed CHAIN-receipt frame cannot enter the raw GAME reducer");
      }
      const outboxLength = this.record.outbox.length;
      this.record.outbox = this.record.outbox.filter(
        (value) => value.messageId !== remembered.frame.messageId,
      );
      if (this.record.outbox.length !== outboxLength) await this.#saveRecord();
      await this.#flushOutbox();
      await this.#advance();
      return this.#view();
    }
    await this.#processFrame(remembered.frame, remembered.event, {
      chainCheckpointReceipt: verification?.chainCheckpointReceipt,
    });
    await this.#flushOutbox();
    await this.#advance();
    return this.#view();
  }

  async #stageRelayMessage(message) {
    this.#requireStarted();
    const normalized = normalizeRelayMessage(message, {
      kind: this.gameExchangeKind,
      maximumDecodedBytes: this.maxExchangeBytes,
      metadataError: "relay returned malformed game-exchange metadata",
    });
    const payloadSha256 = bytesToHex(await sha256(normalized.event));
    const existing = this.record.frames.find(
      (frame) => frame.messageId === normalized.message.messageId,
    );
    if (existing) {
      const payloadMatches = typeof existing.payload === "string"
        ? existing.payload === normalized.message.payload
        : existing.payloadSha256 === payloadSha256;
      if (
        existing.cursor !== normalized.message.cursor ||
        existing.sender !== normalized.message.sender ||
        !payloadMatches
      ) {
        throw new Error("a durable game-exchange identifier was rebound to different bytes");
      }
      return {
        duplicate: true,
        event: normalized.event,
        frame: existing,
        payloadSha256,
      };
    }
    if (this.record.frames.some((frame) => frame.cursor === normalized.message.cursor)) {
      throw new Error("a relay cursor was assigned to multiple message identifiers");
    }
    const frame = {
      cursor: normalized.message.cursor,
      messageId: normalized.message.messageId,
      sender: normalized.message.sender,
      payload: normalized.message.payload,
      payloadSha256,
      processed: false,
    };
    this.record.frames.push(frame);
    await this.#saveRecord();
    return { duplicate: false, event: normalized.event, frame, payloadSha256 };
  }

  async #processFrame(frame, event = base64ToBytes(frame.payload, this.maxExchangeBytes), {
    chainCheckpointReceipt,
  } = {}) {
    if (frame.processed) return true;
    const result = await this.game.request("apply-exchange-event", {
      senderRole: this.#roleForSender(frame.sender),
      event,
    });
    this.projection = result.projection;
    await this.#applyToDeal(frame, result.dealDispatch, false);
    await this.#captureGameSnapshot();
    frame.processed = true;
    frame.disposition = "game";
    this.record.outbox = this.record.outbox.filter(
      (value) => value.messageId !== frame.messageId,
    );
    this.localDealMutations.delete(frame.messageId);
    if (this.record.accepted) {
      const index = this.record.frames.indexOf(frame);
      this.record.frames[index] = compactProcessedGameFrame(frame, {
        payloadSha256: frame.payloadSha256,
        disposition: "game",
        chainCheckpointReceipt,
        dealRecoveryRevision: this.record.revision,
        gameRevision: this.record.revision + 1,
      });
    }
    await this.#saveRecord();
    await this.#persistAcceptedDealIfReady();
    this.#emitProjection();
    return true;
  }

  async #applyToDeal(frame, dispatch, replay) {
    dispatch = normalizeDealDispatch(dispatch);
    if (
      !replay && this.localDealMutations.has(frame.messageId) &&
      dispatch.kind === "accepted-deal-signature"
    ) {
      // Signing already installed this local signature inside DEAL. Capture
      // the terminal transition after its durable echo without signing twice.
      await this.#captureTerminalDealVerification();
      return;
    }
    if (dispatch.kind === "deal-envelope") {
      await this.#prepareBundleIfNeeded();
      if (replay && frame.sender === this.context.transportRole) {
        const generated = await this.deal.request("generate-envelope");
        if (!bytesEqual(generated.envelope, dispatch.envelope)) {
          throw new Error("saved local DEAL envelope does not reproduce byte-for-byte");
        }
      } else {
        // During a live run local generation already advanced DEAL. The
        // worker's exact-duplicate check makes its durable relay echo a no-op,
        // while peer envelopes advance normally. Only recovery must recreate
        // local generation so its private material is reconstructed.
        await this.deal.request("accept-envelope", { envelope: dispatch.envelope });
      }
    } else if (dispatch.kind === "accepted-deal-signature") {
      if (dispatch.role === this.localRole) {
        const body = await this.deal.request("export-accepted-body");
        const signed = await this.deal.request("make-acceptance-signature", { body: body.body });
        if (!bytesEqual(signed.signature, dispatch.signature)) {
          throw new Error("saved local accepted-DEAL signature does not reproduce byte-for-byte");
        }
      } else {
        await this.deal.request("accept-acceptance-signature", {
          role: dispatch.role,
          signature: dispatch.signature,
        });
      }
    } else if (
      dispatch.kind === "deal-retry-signature" &&
      this.projection.status.dealAttempt === dispatch.nextAttempt
    ) {
      await this.deal.request("start-retry", { approvedAttempt: dispatch.nextAttempt });
      this.ephemeralPreparedAttempts.delete(dispatch.nextAttempt - 1);
    }
    await this.#captureTerminalDealVerification();
  }

  async #captureTerminalDealVerification() {
    if (!this.deal || !dealVerificationIsDue(this.projection)) return;
    const exported = await this.deal.request("export-verification-attestation");
    const result = await this.game.request("apply-event", {
      source: GameEventSource.LOCAL_SECRET_RUNTIME,
      event: {
        type: GameEventType.DEAL_VERIFICATION_ATTESTED,
        attestation: exported.attestation,
      },
    });
    this.projection = result.projection;
  }

  async #advance() {
    this.#requireStarted();
    await this.#flushOutbox();
    const step = selectGameAdvance({
      projection: this.projection,
      localRole: this.localRole,
      hasPendingRelay: this.record.outbox.length > 0,
    });
    if (step.kind === GameAdvanceKind.WAIT_RELAY) {
      this.#update(step.stage, step.detail);
      return;
    }
    if (
      step.kind === GameAdvanceKind.BUILD_DEAL_ENVELOPE ||
      step.kind === GameAdvanceKind.WAIT_DEAL_ENVELOPE
    ) {
      await this.#prepareBundleIfNeeded();
      if (step.kind === GameAdvanceKind.WAIT_DEAL_ENVELOPE) {
        this.#update(step.stage, step.detail);
        return;
      }
      const intent = step.intent;
      this.#update(step.stage, step.detail);
      const generated = await this.deal.request("generate-envelope");
      const event = encodeSessionEvent({
        type: GameEventType.DEAL_ENVELOPE,
        envelope: generated.envelope,
      });
      const messageId = await this.#publish(event, `deal:${intent.attempt}:${intent.sequence}`);
      this.localDealMutations.add(messageId);
      return;
    }
    if (step.kind === GameAdvanceKind.SIGN_DEAL_RETRY) {
      this.#update(step.stage, step.detail);
      const signed = await this.deal.request("make-retry-signature", {
        nextAttempt: step.intent.nextAttempt,
        digest: step.intent.digest,
      });
      const event = encodeSessionEvent({
        type: GameEventType.DEAL_RETRY_SIGNATURE,
        nextAttempt: step.intent.nextAttempt,
        role: this.localRole,
        signature: signed.signature,
      });
      await this.#publish(event, `retry:${step.intent.nextAttempt}:${this.localRole}`);
      return;
    }
    if (step.kind === GameAdvanceKind.SIGN_ACCEPTED_DEAL) {
      const intent = step.intent;
      const state = await this.deal.request("snapshot");
      if (state.snapshot.status !== "local-acceptance-signature") {
        throw new Error("DEAL Worker and reducer disagree at accepted-body signing");
      }
      const body = await this.deal.request("export-accepted-body");
      if (!bytesEqual(body.body, intent.body)) {
        throw new Error("DEAL Worker and reducer derived different accepted bodies");
      }
      this.#update(step.stage, step.detail);
      const signed = await this.deal.request("make-acceptance-signature", { body: body.body });
      const event = encodeSessionEvent({
        type: GameEventType.ACCEPTED_DEAL_SIGNATURE,
        role: this.localRole,
        signature: signed.signature,
      });
      const messageId = await this.#publish(
        event,
        `accepted:${this.projection.status.dealAttempt}:${this.localRole}`,
      );
      this.localDealMutations.add(messageId);
      return;
    }
    if (step.kind === GameAdvanceKind.DEAL_COMPLETE) {
      await this.#persistAcceptedDealIfReady();
      this.#update(step.stage, step.detail);
      this.#emitProjection();
      return;
    }
    this.#emitProjection();
  }

  async #prepareBundleIfNeeded() {
    const snapshot = await this.deal.request("snapshot");
    if (snapshot.snapshot.nextSequence !== 6) return;
    const attempt = snapshot.snapshot.attempt;
    if (this.ephemeralPreparedAttempts.has(attempt)) return;
    this.#update(
      "preparing-proof",
      "Preparing the zero-knowledge card bundle in both private Workers; this can take a few minutes…",
    );
    await this.deal.request("prepare-bundle");
    this.ephemeralPreparedAttempts.add(attempt);
  }

  async #publish(eventBytes, intentKey) {
    const opaqueEvent = asBytes(eventBytes, "exchange event");
    if (opaqueEvent.byteLength === 0 || opaqueEvent.byteLength > this.maxExchangeBytes) {
      throw new Error("game exchange event exceeds its deployment relay bound");
    }
    const payload = bytesToBase64(opaqueEvent);
    let outbox = this.record.outbox.find((value) => value.intentKey === intentKey);
    if (outbox && outbox.payload !== payload) {
      throw new Error("one game intent produced conflicting exchange bytes");
    }
    if (!outbox) {
      let messageId;
      do {
        messageId = randomMessageId();
      } while (this.record.outbox.some((value) => value.messageId === messageId));
      outbox = { messageId, payload, intentKey, sent: false };
      this.record.outbox.push(outbox);
      await this.#saveRecord();
    }
    await this.#sendOutbox(outbox);
    return outbox.messageId;
  }

  async #flushOutbox() {
    for (const outbox of this.record?.outbox ?? []) {
      await this.#sendOutbox(outbox);
    }
  }

  async #sendOutbox(outbox) {
    this.#assertOpen();
    await this.context.sendExchange({
      messageId: outbox.messageId,
      kind: this.gameExchangeKind,
      payload: outbox.payload,
    });
    this.#assertOpen();
    if (!outbox.sent) {
      outbox.sent = true;
      await this.#saveRecord();
    }
  }

  async #applyLocalEvent(source, event) {
    this.#requireStarted();
    const result = await this.game.request("apply-event", { source, event });
    this.projection = result.projection;
    await this.#saveGameSnapshot();
    this.#emitProjection();
    await this.#advance();
    return this.#view();
  }

  async #applyRuntimeReceipt(type, receipt) {
    this.#requireStarted();
    const canonicalReceipt = asBytes(receipt, "verified CHAIN receipt");
    if (canonicalReceipt.byteLength === 0) {
      throw new Error("CHAIN returned an empty runtime receipt");
    }
    const result = await this.game.request(type, { receipt: canonicalReceipt });
    this.projection = result.projection;
    await this.#saveGameSnapshot();
    this.#emitProjection();
    await this.#advance();
    return this.#view();
  }

  async #persistAcceptedDealIfReady() {
    if (this.record.accepted) return;
    const snapshot = await this.deal.request("snapshot");
    if (snapshot.snapshot.status !== "accepted") return;
    const exported = await this.deal.request("export");
    const storageKey = hexToBytes(this.record.storageKeyHex, 32, "DEAL storage key");
    let sealed;
    try {
      sealed = await this.deal.request("seal-preimages", { storageKey });
    } finally {
      storageKey.fill(0);
    }
    const acceptedRecord = structuredClone(this.record);
    acceptedRecord.accepted = {
      deal: exported.deal,
      attestation: exported.attestation,
      sealedPreimages: sealed.sealedPreimages,
    };
    await this.#saveRecord(acceptedRecord);
    await this.#readBackAcceptedDeal(acceptedRecord);
    this.record = acceptedRecord;

    // The authenticated recovery package is durable and byte-confirmed. End
    // the proof-heavy Worker before any CHAIN consumer can be constructed.
    const deal = this.deal;
    this.deal = undefined;
    await deal?.close().catch(() => {});

    const compactedRecord = structuredClone(this.record);
    let compacted = false;
    compactedRecord.frames = compactedRecord.frames.map((frame) => {
      if (
        !frame.processed || typeof frame.payload !== "string" ||
        frame.disposition !== "game"
      ) {
        return frame;
      }
      compacted = true;
      return compactProcessedGameFrame(frame, {
        payloadSha256: frame.payloadSha256,
        disposition: "game",
        dealRecoveryRevision: this.record.revision,
        gameRevision: this.record.revision + 1,
      });
    });
    if (compacted) {
      await this.#saveRecord(compactedRecord);
      this.record = compactedRecord;
    }
  }

  async #readBackAcceptedDeal(expected = this.record) {
    const durable = await this.store.load(this.key);
    return verifyAcceptedDealRecovery(expected, durable);
  }

  async #saveGameSnapshot() {
    await this.#captureGameSnapshot();
    await this.#saveRecord();
  }

  async #captureGameSnapshot() {
    const snapshot = await this.game.request("snapshot");
    this.record.gameSnapshot = snapshot.snapshot;
  }

  async #saveRecord(record = this.record) {
    record.revision = (record.revision ?? 0) + 1;
    await this.store.save(this.key, record);
  }

  #enqueue(operation) {
    const next = this.operation.then(async () => {
      this.#assertOpen();
      try {
        return await operation();
      } catch (error) {
        this.#update("halted", error instanceof Error ? error.message : String(error), error);
        throw error;
      }
    });
    this.operation = next.catch(() => {});
    return next;
  }

  #emitProjection() {
    this.onProjection(this.projection, this);
    this.onUpdate(this.#view());
  }

  #update(stage, detail, error) {
    this.stage = stage;
    this.detail = detail;
    this.error = error;
    this.onUpdate(this.#view());
  }

  #view() {
    return {
      stage: this.stage ?? "idle",
      detail: this.detail ?? "Waiting to start private setup.",
      canonicalRole: this.localRole,
      phase: this.projection?.status?.phase,
      tableBalances: this.projection?.status?.tableBalances
        ? structuredClone(this.projection.status.tableBalances)
        : undefined,
      dealAttempt: this.projection?.status?.dealAttempt ?? 0,
      dealEnvelopes: this.projection?.status?.dealEnvelopes ?? 0,
      dealGameIdHex: this.projection?.status?.dealGameId
        ? bytesToHex(this.projection.status.dealGameId)
        : undefined,
      privateDealComplete: Boolean(
        this.projection && this.projection.status.phase >= GamePhase.SIGNING_DESCRIPTOR
      ),
      cancelled: this.closed,
      error: this.error instanceof Error ? this.error.message : undefined,
    };
  }

  #roleForSender(sender) {
    return roleForRelaySender(sender, this.context.transportRole, this.localRole);
  }

  #requireStarted() {
    if (!this.started) throw new Error("private-game coordinator is not initialized");
    this.#assertOpen();
  }

  #activationIsLocallyReady() {
    return this.projection?.status?.phase === GamePhase.AUTHORIZING_ACTIVATION &&
      this.projection.intents.some((intent) => intent.name === "authorize-activation");
  }

  #assertOpen() {
    if (this.closed) throw new Error("private-game coordinator was cancelled");
  }
}

export function createBrowserGameFlow(context, options) {
  return new BrowserGameFlow(context, options);
}

globalThis.BP52_GAME_FLOW = Object.freeze({
  create: createBrowserGameFlow,
});
