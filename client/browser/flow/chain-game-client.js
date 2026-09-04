import {
  GameEventType,
  GamePhase,
  MAX_EVENT_ARTIFACT_BYTES,
} from "../game/game-runtime.js";
import {
  BrowserChainWorker,
} from "../chain/chain-client.js?v=11";
import {
  ChainExchangePackage,
  ChainPhase,
  ChainSetupKind,
} from "../chain/chain-runtime.js";
import { loadWasmBytes } from "../config/wasm-loader.js";
import {
  byteView as asBytes,
  bytesEqual as sameBytes,
  bytesToHex,
  deriveChainRecovery,
  deriveChainRelayTransition,
  exactHex,
  hexToBytes,
  mayPublishLamportBundle,
  normalizeRelayMessage,
  normalizeSetupAcceptance,
  ownedBytes,
  planAuthorizedEdge,
  planConfirmedSpend,
  relayFramesInCursorOrder,
  rememberRelayFrame,
  roleForRelaySender,
  selectVerifiedSpecialEdge,
} from "./orchestration.js";

export { selectVerifiedSpecialEdge };

const CHAIN_RELAY_DATABASE = "bp52-chain-relay-v1";
const CHAIN_RELAY_STORE = "frames";
const CHAIN_RELAY_RECORD_VERSION = 1;

async function sha256(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", asBytes(value, "hash input")));
}

class IndexedDbChainRelayStore {
  #open() {
    if (!globalThis.indexedDB) {
      return Promise.reject(new Error("IndexedDB is required for CHAIN relay recovery"));
    }
    return new Promise((resolve, reject) => {
      const request = globalThis.indexedDB.open(CHAIN_RELAY_DATABASE, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(CHAIN_RELAY_STORE)) {
          request.result.createObjectStore(CHAIN_RELAY_STORE);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error("failed to open CHAIN relay store"));
    });
  }

  async load(key) {
    const database = await this.#open();
    try {
      return await new Promise((resolve, reject) => {
        const transaction = database.transaction(CHAIN_RELAY_STORE, "readonly");
        const request = transaction.objectStore(CHAIN_RELAY_STORE).get(key);
        request.onsuccess = () => resolve(request.result ? structuredClone(request.result) : null);
        request.onerror = () => reject(request.error ?? new Error("failed to read CHAIN relay state"));
      });
    } finally {
      database.close();
    }
  }

  async save(key, value) {
    const database = await this.#open();
    try {
      await new Promise((resolve, reject) => {
        const transaction = database.transaction(CHAIN_RELAY_STORE, "readwrite");
        transaction.objectStore(CHAIN_RELAY_STORE).put(structuredClone(value), key);
        transaction.oncomplete = () => resolve();
        transaction.onerror = () => reject(transaction.error ?? new Error("failed to save CHAIN relay state"));
        transaction.onabort = () => reject(transaction.error ?? new Error("CHAIN relay transaction aborted"));
      });
    } finally {
      database.close();
    }
  }
}

export class MemoryChainRelayStore {
  constructor() {
    this.records = new Map();
  }

  async load(key) {
    const value = this.records.get(key);
    return value ? structuredClone(value) : null;
  }

  async save(key, value) {
    this.records.set(key, structuredClone(value));
  }
}

/**
 * Coordinates public reducer intents with the secret-bearing CHAIN Worker.
 * Bitcoin transactions and witnesses remain opaque; Rust/Wasm validates and
 * constructs them before this class can relay or publish anything.
 */
export class BrowserChainGameFlow {
  constructor(context, options = {}) {
    if (!context?.game || typeof context.game.handoffAcceptedDeal !== "function") {
      throw new Error("a started BrowserGameFlow is required");
    }
    if (context.transportRole !== "alice" && context.transportRole !== "bob") {
      throw new Error("transportRole must be alice or bob");
    }
    if (context.localRole !== 0 && context.localRole !== 1) {
      throw new Error("localRole must be canonical Alice or Bob");
    }
    if (!Array.isArray(context.identities) || context.identities.length !== 2) {
      throw new Error("canonical identities are required");
    }
    exactHex(context.roomId, 32, "roomId");
    exactHex(context.sessionNonceHex, 32, "sessionNonceHex");
    exactHex(context.localSecretKeyHex, 32, "localSecretKeyHex");
    exactHex(context.origin?.displayTxid, 32, "origin.displayTxid");
    exactHex(context.origin?.witnessScriptHex, 104, "origin.witnessScriptHex");
    if (typeof context.sendExchange !== "function") {
      throw new Error("sendExchange callback is required");
    }
    const deployment = context.deploymentConfig;
    if (
      !deployment?.relay?.kinds?.gameExchange ||
      !deployment.relay.kinds.chainExchange ||
      !Number.isSafeInteger(deployment.protocolProfileCode) ||
      deployment.protocolProfileCode < 0 || deployment.protocolProfileCode > 0xff ||
      !Number.isSafeInteger(deployment.chain?.bitcoinNetworkCode) ||
      deployment.chain.bitcoinNetworkCode < 0 || deployment.chain.bitcoinNetworkCode > 0xff ||
      !/^[0-9a-f]{64}$/.test(deployment.deploymentDigestHex || "") ||
      !Number.isSafeInteger(deployment.relay.maxPayloadBase64Bytes)
    ) {
      throw new Error("validated deploymentConfig is required");
    }
    this.context = context;
    this.gameExchangeKind = deployment.relay.kinds.gameExchange;
    this.chainExchangeKind = deployment.relay.kinds.chainExchange;
    this.maxRelayPayloadBase64Bytes = deployment.relay.maxPayloadBase64Bytes;
    this.store = options.store ?? new IndexedDbChainRelayStore();
    this.storeKey = [
      deployment.deploymentDigestHex,
      context.roomId,
      context.sessionNonceHex,
      context.transportRole,
    ].join("/");
    this.workerFactory = options.workerFactory;
    this.chainWasm = options.chainWasm;
    this.onUpdate = context.onUpdate ?? (() => {});
    this.worker = undefined;
    this.initialized = false;
    this.initializing = undefined;
    this.closed = false;
    this.operation = Promise.resolve();
    this.projection = undefined;
    this.gameFrames = new Map();
    this.appliedFrames = new Set();
    this.deferredChainFrames = new Map();
    this.appliedChainFrames = new Set();
    this.chainRelayRecord = undefined;
    this.localLamportBundle = undefined;
    this.publishedSetupKinds = new Set();
    this.acceptedSetupPackages = new Set();
    this.inventoryAttested = false;
    this.inventoryReadySent = false;
    this.readyForActivation = false;
    this.activationConsent = true;
    this.activationSignatureSent = false;
    this.activationTransaction = undefined;
    this.cards = null;
    this.lastTipHeight = undefined;
    this.recoveredPhase = ChainPhase.EMPTY;
    this.stage = "waiting-for-deal";
    this.detail = "Waiting for the accepted private deal.";
    this.error = undefined;
  }

  updateProjection(projection) {
    return this.#enqueue(async () => {
      this.projection = structuredClone(projection);
      await this.#initializeIfReady();
      if (this.initialized) {
        await this.#synchronizeSetup();
        await this.#driveSetup();
        await this.#refreshWorkerStatus();
      }
      this.#emit();
      return this.view();
    });
  }

  acceptGameRelayMessage(message) {
    return this.#enqueue(async () => {
      const normalized = normalizeRelayMessage(message, {
        kind: this.gameExchangeKind,
        maximumEncodedBytes: this.maxRelayPayloadBase64Bytes,
        maximumDecodedBytes: MAX_EVENT_ARTIFACT_BYTES + 256,
        metadataError: "CHAIN coordinator accepts only the configured game exchange kind",
      });
      const payloadSha256 = bytesToHex(await sha256(normalized.event));
      const existing = this.gameFrames.get(normalized.message.messageId);
      if (existing && (
        existing.message.cursor !== normalized.message.cursor ||
        existing.message.sender !== normalized.message.sender ||
        existing.message.kind !== normalized.message.kind ||
        existing.payloadSha256 !== payloadSha256
      )) {
        throw new Error("a game relay identifier was rebound to different bytes");
      }
      if (!existing) {
        this.gameFrames.set(normalized.message.messageId, {
          message: normalized.message,
          event: normalized.event,
          payloadSha256,
        });
      }
      await this.#initializeIfReady();
      let acceptance = existing?.acceptance;
      if (this.initialized) {
        acceptance = await this.#synchronizeSetup(normalized.message.messageId);
        await this.#driveSetup();
        await this.#refreshWorkerStatus();
      }
      this.#emit();
      return {
        ...(acceptance ?? {
          applicable: false,
          disposition: "game",
        }),
        view: this.view(),
      };
    });
  }

  acceptChainRelayMessage(message) {
    return this.#enqueue(async () => {
      await this.#initializeIfReady();
      if (!this.worker) throw new Error("secret CHAIN Worker is waiting for the accepted deal");
      const result = await this.#acceptChainFrame(message);
      await this.#driveSetup();
      await this.#refreshWorkerStatus();
      this.#emit();
      return {
        ...result,
        deferred: this.deferredChainFrames.has(message.messageId),
        view: this.view(),
      };
    });
  }

  authorizeActivation() {
    return this.#enqueue(async () => {
      this.activationConsent = true;
      await this.#initializeIfReady();
      await this.#driveSetup();
      this.#emit();
      return this.view();
    });
  }

  authorizeEdge(childNodeId) {
    return this.#enqueue(async () => {
      if (!this.worker || !this.projection) throw new Error("gameplay Worker is unavailable");
      const plan = planAuthorizedEdge({
        projection: this.projection,
        childNodeId,
        localRole: this.context.localRole,
        cards: this.cards,
        lastTipHeight: this.lastTipHeight,
      });
      const result = await this.worker[plan.workerMethod](...plan.workerArguments);
      await this.context.game.applyRuntimeAuthorizationReceipt(result.runtimeReceipt);
      this.projection = this.context.game.currentProjection();
      this.stage = "gameplay-authorized";
      this.detail = "Gameplay transaction verified locally. Waiting for explicit broadcast.";
      this.#emit();
      return this.view();
    });
  }

  observeTip(event) {
    return this.#enqueue(async () => {
      if (!this.worker) return this.view();
      await this.context.game.applyChainEvent(event);
      await this.worker.observeTip(event.block.height);
      this.lastTipHeight = event.block.height;
      this.projection = this.context.game.currentProjection();
      await this.#driveSetup();
      this.#emit();
      return this.view();
    });
  }

  confirmSpend(event) {
    return this.#enqueue(async () => {
      if (!this.worker) throw new Error("secret CHAIN Worker is unavailable");
      const plan = planConfirmedSpend(this.projection, event);
      await this.context.game.applyChainEvent(event);
      this.projection = this.context.game.currentProjection();
      let result;
      if (plan.activation) {
        result = await this.worker.confirmActivation(plan.workerInput);
      } else {
        result = await this.worker.confirmChild(plan.workerInput);
      }
      this.cards = result.cards;
      await this.context.game.applyConfirmedStateReceipt(result.stateReceipt);
      this.projection = this.context.game.currentProjection();
      this.lastTipHeight = event.observedTip.height;
      await this.#driveSetup();
      await this.#refreshWorkerStatus();
      this.#emit();
      return this.view();
    });
  }

  async cancel() {
    this.closed = true;
    await this.worker?.clear().catch(() => {});
    this.worker = undefined;
  }

  view() {
    const runtime = this.projection?.intents.find(
      (value) => value.name === "choose-runtime-edge"
    );
    const pendingBroadcast = this.projection?.intents.find(
      (value) => value.name === "broadcast-transaction"
    );
    const settlement = this.projection?.intents.find(
      (value) => value.name === "settlement-confirmed"
    );
    return {
      stage: this.stage,
      detail: this.detail,
      initialized: this.initialized,
      canonicalRole: this.context.localRole,
      phase: this.projection?.status?.phase,
      chainGameId: this.projection?.status?.chainGameId,
      graphRoot: this.projection?.status?.graphRoot,
      activationConsent: this.activationConsent,
      activationSignatureSent: this.activationSignatureSent,
      activationAssembled: Boolean(this.activationTransaction),
      inventoryAttested: this.inventoryAttested,
      inventoryReadySent: this.inventoryReadySent,
      readyForActivation: this.readyForActivation,
      pendingBroadcast,
      settlement,
      legalEdges: runtime?.edges ?? [],
      timeoutMaturesAt: runtime?.timeoutMaturesAt,
      tipHeight: this.lastTipHeight,
      cards: this.cards ? structuredClone(this.cards) : null,
      error: this.error instanceof Error ? this.error.message : undefined,
    };
  }

  async #initializeIfReady() {
    if (this.initialized || this.initializing) return this.initializing;
    if (!this.projection || this.projection.status.phase < GamePhase.SIGNING_DESCRIPTOR) return;
    if (!(this.projection.status.sharedConfigHash instanceof Uint8Array) ||
        this.projection.status.sharedConfigHash.byteLength !== 32) {
      throw new Error("game reducer did not expose its exact shared config hash");
    }
    this.stage = "initializing-chain";
    this.detail = "Opening the accepted deal inside the secret CHAIN Worker…";
    this.#emit();
    let recoveredState;
    this.initializing = this.context.game.handoffAcceptedDeal(async ({
      deal,
      attestation,
      sealedPreimages,
      storageKey,
    }) => {
      const worker = new BrowserChainWorker({
        transportRole: this.context.transportRole,
        chainExchangeKind: this.chainExchangeKind,
        workerFactory: this.workerFactory,
      });
      this.worker = worker;
      try {
        const acknowledgement = await worker.init({
          wasm: this.chainWasm ?? await loadWasmBytes("chain"),
          config: {
            configHash: this.projection.status.sharedConfigHash,
            protocolProfile: this.context.deploymentConfig.protocolProfileCode,
            deploymentDigest: hexToBytes(
              this.context.deploymentConfig.deploymentDigestHex,
              32,
              "deployment digest",
            ),
            bitcoinNetwork: this.context.deploymentConfig.chain.bitcoinNetworkCode,
            networkId: hexToBytes(
              this.context.deploymentConfig.chain.profileIdHex,
              32,
              "network id",
            ),
            relayRoomId: hexToBytes(this.context.roomId, 32, "roomId"),
            sessionNonce: hexToBytes(
              this.context.sessionNonceHex,
              32,
              "session nonce",
            ),
            localRole: this.context.localRole,
            origin: {
              displayTxid: hexToBytes(this.context.origin.displayTxid, 32, "origin txid"),
              vout: this.context.origin.vout,
              witnessScript: hexToBytes(
                this.context.origin.witnessScriptHex,
                104,
                "origin witness script",
              ),
            },
            identities: this.context.identities.map((value) => Uint8Array.from(asBytes(value, "identity"))),
          },
          identitySecret: hexToBytes(this.context.localSecretKeyHex, 32, "identity secret"),
          deal: {
            certificate: deal,
            attestation,
            sealedPreimages,
            storageKey,
          },
        });
        recoveredState = deriveChainRecovery(
          acknowledgement,
          this.projection,
          this.context.localRole,
        );
        return { accepted: true };
      } catch (error) {
        await worker.clear().catch(() => {});
        if (this.worker === worker) this.worker = undefined;
        throw error;
      }
    });
    try {
      await this.initializing;
      this.initialized = true;
      this.recoveredPhase = recoveredState.recoveredPhase;
      this.inventoryAttested =
        this.projection.status.phase >= GamePhase.AUTHORIZING_ACTIVATION;
      await this.#loadChainRelayRecord();
      for (const historical of this.context.game.exchangeHistory()) {
        const normalized = normalizeRelayMessage(historical, {
          kind: this.gameExchangeKind,
          maximumEncodedBytes: this.maxRelayPayloadBase64Bytes,
          maximumDecodedBytes: MAX_EVENT_ARTIFACT_BYTES + 256,
          metadataError: "saved game exchange history is malformed",
        });
        if (this.gameFrames.has(normalized.message.messageId)) {
          throw new Error("saved game exchange history has a duplicate id");
        }
        const payloadSha256 = bytesToHex(await sha256(normalized.event));
        this.gameFrames.set(normalized.message.messageId, {
          message: normalized.message,
          event: normalized.event,
          payloadSha256,
        });
      }
      this.activationTransaction = recoveredState.activationTransaction;
      await this.#replayChainFrames();
      this.stage = "preparing-graph";
      this.detail = "Preparing the game…";
    } finally {
      this.initializing = undefined;
    }
  }

  async #synchronizeSetup(targetMessageId) {
    if (!this.worker) return undefined;
    let targetAcceptance = this.gameFrames.get(targetMessageId)?.acceptance;
    const frames = Array.from(this.gameFrames.entries())
      .sort((left, right) => (left[1].message.cursor ?? 0) - (right[1].message.cursor ?? 0));
    for (const [messageId, frame] of frames) {
      if (this.appliedFrames.has(messageId)) {
        if (messageId === targetMessageId) targetAcceptance = frame.acceptance;
        continue;
      }
      if (!(frame.event instanceof Uint8Array)) {
        throw new Error("unapplied GAME setup frame lost its canonical payload");
      }
      const local = frame.message.sender === this.context.transportRole;
      const result = normalizeSetupAcceptance(await this.worker.acceptSessionEvent(
        roleForRelaySender(
          frame.message.sender,
          this.context.transportRole,
          this.context.localRole,
        ),
        frame.event,
      ));
      if (!result.applicable) {
        this.appliedFrames.add(messageId);
        frame.acceptance = {
          applicable: false,
          checkpointReceipt: result.checkpointReceipt,
          disposition: "game",
        };
        frame.event = undefined;
        frame.message = {
          cursor: frame.message.cursor,
          messageId: frame.message.messageId,
          sender: frame.message.sender,
          kind: frame.message.kind,
        };
        if (messageId === targetMessageId) targetAcceptance = frame.acceptance;
        continue;
      }
      if (result.localLamportBundle.byteLength > 0) {
        if (this.localLamportBundle && !sameBytes(this.localLamportBundle, result.localLamportBundle)) {
          throw new Error("replayed descriptor events produced a conflicting local Lamport bundle");
        }
        this.localLamportBundle = Uint8Array.from(asBytes(
          result.localLamportBundle,
          "local Lamport bundle",
        ));
      }
      if (local) this.publishedSetupKinds.add(result.setupKind);
      this.appliedFrames.add(messageId);
      frame.acceptance = {
        applicable: true,
        setupKind: result.setupKind,
        checkpointReceipt: result.checkpointReceipt,
        disposition: "game",
      };
      frame.event = undefined;
      frame.message = {
        cursor: frame.message.cursor,
        messageId: frame.message.messageId,
        sender: frame.message.sender,
        kind: frame.message.kind,
      };
      if (messageId === targetMessageId) targetAcceptance = frame.acceptance;
    }
    return targetAcceptance;
  }

  async #driveSetup() {
    if (!this.worker || !this.projection) return;
    for (;;) {
      const intent = this.projection.intents[0];
      if (
        intent?.name === "sign-descriptor" &&
        !this.publishedSetupKinds.has(ChainSetupKind.DESCRIPTOR_SIGNATURE)
      ) {
        const result = await this.worker.signDescriptor(intent.descriptor);
        await this.context.game.publishExchangeEvent({
          type: GameEventType.DESCRIPTOR_SIGNATURE,
          role: this.context.localRole,
          descriptor: intent.descriptor,
          signature: ownedBytes(result.signature, "descriptor signature", 64),
        });
        this.publishedSetupKinds.add(ChainSetupKind.DESCRIPTOR_SIGNATURE);
        return;
      }

      if (
        this.localLamportBundle &&
        !this.publishedSetupKinds.has(ChainExchangePackage.LAMPORT_PUBLIC_BUNDLE) &&
        mayPublishLamportBundle(this.context.localRole, this.recoveredPhase)
      ) {
        const bundle = this.localLamportBundle;
        const result = await this.worker.makeLamportBundle(bundle);
        await this.#sendChainExchange(result.exchange);
        this.publishedSetupKinds.add(ChainExchangePackage.LAMPORT_PUBLIC_BUNDLE);
        bundle.fill(0);
        this.localLamportBundle = undefined;
        return;
      }

      if (intent?.name === "prepare-graph") {
        if (this.recoveredPhase === ChainPhase.GRAPH_READY) {
          if (!this.publishedSetupKinds.has(ChainExchangePackage.GRAPH_ROOT_COMMITMENT)) {
            const result = await this.worker.makeRootCommitment();
            await this.#sendChainExchange(result.exchange);
            this.publishedSetupKinds.add(ChainExchangePackage.GRAPH_ROOT_COMMITMENT);
            return;
          }
          if (
            this.#bothSetupPackagesAccepted(ChainExchangePackage.GRAPH_ROOT_COMMITMENT) &&
            !this.publishedSetupKinds.has(ChainExchangePackage.GRAPH_ROOT_OPENING)
          ) {
            const result = await this.worker.openRoot();
            await this.#sendChainExchange(result.exchange);
            this.publishedSetupKinds.add(ChainExchangePackage.GRAPH_ROOT_OPENING);
            return;
          }
        }

        if (this.recoveredPhase === ChainPhase.ROOT_AGREED) {
          if (!this.publishedSetupKinds.has(ChainExchangePackage.PREAUTHORIZATION_COMMITMENT)) {
            const result = await this.worker.makePreauthorizationCommitment();
            await this.#sendChainExchange(result.exchange);
            this.publishedSetupKinds.add(ChainExchangePackage.PREAUTHORIZATION_COMMITMENT);
            return;
          }
          if (
            this.#bothSetupPackagesAccepted(ChainExchangePackage.PREAUTHORIZATION_COMMITMENT) &&
            !this.publishedSetupKinds.has(ChainExchangePackage.PREAUTHORIZATION_OPENING)
          ) {
            const result = await this.worker.openPreauthorizations();
            await this.#sendChainExchange(result.exchange);
            this.publishedSetupKinds.add(ChainExchangePackage.PREAUTHORIZATION_OPENING);
            return;
          }
        }

        if (
          this.recoveredPhase >= ChainPhase.PREAUTHORIZATIONS_READY &&
          !this.inventoryAttested
        ) {
          const result = await this.worker.attestInventory();
          if (result.role !== this.context.localRole) {
            throw new Error("CHAIN Worker attested inventory for a different role");
          }
          await this.context.game.applyGraphPreparedReceipt(result.graphReceipt);
          this.projection = this.context.game.currentProjection();
          this.inventoryAttested = true;
          continue;
        }
      }

      if (this.inventoryAttested && !this.inventoryReadySent) {
        const result = await this.worker.makeInventoryReady();
        await this.#sendChainExchange(result.exchange);
        this.inventoryReadySent = true;
        await this.#retryDeferredChainFrames();
        continue;
      }

      if (this.projection.intents[0]?.name === "authorize-activation") {
        if (!this.readyForActivation) {
          await this.#refreshWorkerStatus();
        }
        if (this.readyForActivation && !this.activationSignatureSent) {
          const activation = this.projection.intents[0];
          const result = await this.worker.signActivation(activation.unsignedTransaction);
          await this.#sendChainExchange(result.exchange);
          this.activationSignatureSent = true;
          await this.#retryDeferredChainFrames();
          return;
        }
        this.stage = "preparing-game";
        this.detail = "Preparing the game…";
        return;
      }

      const display = new Map([
        [GamePhase.AWAITING_ACTIVATION, ["ready", "Ready to play."]],
        [GamePhase.ACTIVE, ["active", "Your turn."]],
        [GamePhase.SETTLED, ["settled", "Game complete."]],
        [GamePhase.HALTED, ["halted", "The game stopped safely."]],
      ]).get(this.projection.status.phase);
      if (display) [this.stage, this.detail] = display;
      return;
    }
  }

  async #retryDeferredChainFrames() {
    const messages = relayFramesInCursorOrder(
      Array.from(this.deferredChainFrames.values()),
    );
    for (const message of messages) {
      const messageId = message.messageId;
      const result = await this.worker.acceptRelayMessage(message);
      const transition = this.#applyChainRelayTransition(message, result);
      if (transition.disposition === "deferred") continue;
      this.deferredChainFrames.delete(messageId);
      this.appliedChainFrames.add(messageId);
      await this.#acceptAssembledActivation(transition.activationTransaction);
    }
  }

  async #refreshWorkerStatus() {
    if (!this.worker) return;
    const status = await this.worker.status();
    this.readyForActivation = Boolean(status.readyForActivation);
    if (status.readyRoles?.includes(this.context.localRole)) {
      this.inventoryReadySent = true;
    }
    if (status.cards) this.cards = structuredClone(status.cards);
    if (Number.isSafeInteger(status.phase)) this.recoveredPhase = status.phase;
  }

  #relayBinding() {
    return [
      bytesToHex(this.projection.status.sharedConfigHash),
      this.context.deploymentConfig.deploymentDigestHex,
      this.context.origin.displayTxid,
      String(this.context.origin.vout),
      ...this.context.identities.map((value) => bytesToHex(value)),
    ].join("/");
  }

  async #loadChainRelayRecord() {
    const binding = this.#relayBinding();
    let saved = await this.store.load(this.storeKey);
    if (!saved) {
      this.chainRelayRecord = {
        version: CHAIN_RELAY_RECORD_VERSION,
        binding,
        revision: 0,
        frames: [],
      };
      await this.#saveChainRelayRecord();
      return;
    }
    if (
      saved?.version !== CHAIN_RELAY_RECORD_VERSION || saved.binding !== binding ||
      !Number.isSafeInteger(saved.revision) || saved.revision < 0 ||
      !Array.isArray(saved.frames)
    ) {
      throw new Error("saved CHAIN relay state differs from this exact game binding");
    }
    const ids = new Set();
    const cursors = new Set();
    for (const message of saved.frames) {
      this.#validateChainMessage(message);
      if (ids.has(message.messageId)) throw new Error("saved CHAIN relay state has a duplicate id");
      if (cursors.has(message.cursor)) {
        throw new Error("saved CHAIN relay state has a duplicate cursor");
      }
      ids.add(message.messageId);
      cursors.add(message.cursor);
    }
    saved.frames = relayFramesInCursorOrder(saved.frames);
    this.chainRelayRecord = saved;
  }

  async #saveChainRelayRecord() {
    if (!this.chainRelayRecord) throw new Error("CHAIN relay recovery state is unavailable");
    this.chainRelayRecord.revision += 1;
    await this.store.save(this.storeKey, this.chainRelayRecord);
  }

  #validateChainMessage(message) {
    return normalizeRelayMessage(message, {
      kind: this.chainExchangeKind,
      maximumEncodedBytes: this.maxRelayPayloadBase64Bytes,
      maximumDecodedBytes: MAX_EVENT_ARTIFACT_BYTES + 256,
      metadataError: "relay returned malformed CHAIN exchange metadata",
    }).message;
  }

  async #rememberChainFrame(message) {
    const normalized = this.#validateChainMessage(message);
    const remembered = rememberRelayFrame(this.chainRelayRecord.frames, normalized, {
      retainKind: true,
      sortByCursor: true,
      reboundError: "a durable CHAIN relay identifier was rebound to different bytes",
    });
    this.chainRelayRecord.frames = remembered.frames;
    if (!remembered.duplicate) await this.#saveChainRelayRecord();
    return { message: normalized, duplicate: remembered.duplicate };
  }

  async #acceptChainFrame(message) {
    const remembered = await this.#rememberChainFrame(message);
    message = remembered.message;
    if (this.appliedChainFrames.has(message.messageId)) {
      return { accepted: true, duplicate: true, deferred: false };
    }
    if (this.recoveredPhase === ChainPhase.LAMPORT_READY) {
      this.stage = "preparing-graph";
      this.detail = "Preparing the game in the background…";
      this.#emit();
    }
    const result = await this.worker.acceptRelayMessage(message);
    const transition = this.#applyChainRelayTransition(message, result);
    if (transition.disposition === "deferred") {
      this.deferredChainFrames.set(message.messageId, { ...message });
    } else {
      this.deferredChainFrames.delete(message.messageId);
      this.appliedChainFrames.add(message.messageId);
      await this.#acceptAssembledActivation(transition.activationTransaction);
      if (transition.retryDeferred && this.deferredChainFrames.size > 0) {
        await this.#retryDeferredChainFrames();
      }
    }
    return result;
  }

  #applyChainRelayTransition(message, result) {
    const transition = deriveChainRelayTransition(result, message, this.context.transportRole);
    this.readyForActivation = transition.readyForActivation;
    if (transition.disposition === "applied") {
      this.acceptedSetupPackages.add(
        `${transition.package}:${transition.role}`,
      );
      if (message.sender === this.context.transportRole) {
        this.publishedSetupKinds.add(transition.package);
      }
      if (Number.isSafeInteger(transition.setup?.phase)) {
        this.recoveredPhase = transition.setup.phase;
      }
    }
    if (transition.inventoryReadySent) this.inventoryReadySent = true;
    if (transition.activationConsent) this.activationConsent = true;
    if (transition.activationSignatureSent) this.activationSignatureSent = true;
    return transition;
  }

  #bothSetupPackagesAccepted(packageId) {
    return this.acceptedSetupPackages.has(`${packageId}:0`) &&
      this.acceptedSetupPackages.has(`${packageId}:1`);
  }

  async #replayChainFrames() {
    for (const message of this.chainRelayRecord.frames) {
      await this.#acceptChainFrame(message);
    }
  }

  async #acceptAssembledActivation(transaction) {
    if (!transaction) return;
    if (this.activationTransaction && !sameBytes(this.activationTransaction, transaction)) {
      throw new Error("CHAIN Worker assembled conflicting activation bytes");
    }
    this.activationTransaction = ownedBytes(
      transaction,
      "assembled activation transaction",
    );
    if (this.projection.status.phase >= GamePhase.AWAITING_ACTIVATION) return;
    await this.context.game.publishExchangeEvent({
      type: GameEventType.ACTIVATION_AUTHORIZED,
      transaction,
    });
    this.projection = this.context.game.currentProjection();
  }

  async #sendChainExchange(exchange) {
    if (
      !exchange || exchange.kind !== this.chainExchangeKind ||
      typeof exchange.payload !== "string" || !/^[0-9a-f]{64}$/u.test(exchange.messageId || "")
    ) {
      throw new Error("CHAIN Worker returned a malformed relay exchange");
    }
    await this.context.sendExchange({
      messageId: exchange.messageId,
      kind: this.chainExchangeKind,
      payload: exchange.payload,
    });
  }

  #enqueue(operation) {
    const next = this.operation.then(async () => {
      if (this.closed) throw new Error("CHAIN game coordinator was cancelled");
      try {
        return await operation();
      } catch (error) {
        this.error = error;
        this.stage = "halted";
        this.detail = error instanceof Error ? error.message : String(error);
        this.#emit();
        throw error;
      }
    });
    this.operation = next.catch(() => {});
    return next;
  }

  #emit() {
    this.onUpdate(this.view());
  }
}

export function createBrowserChainGameFlow(context, options) {
  return new BrowserChainGameFlow(context, options);
}

globalThis.BP52_CHAIN_GAME_FLOW = Object.freeze({
  create: createBrowserChainGameFlow,
});
