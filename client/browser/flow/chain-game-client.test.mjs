import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
if (!globalThis.atob) {
  globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
}
if (!globalThis.btoa) {
  globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
}

const {
  BrowserChainGameFlow,
  MemoryChainRelayStore,
  selectVerifiedSpecialEdge,
} = await import("./chain-game-client.js");
const {
  localRoleMayAuthorizeEdge,
  nextGameplayPublishAction,
  selectAutomaticGameEdge,
} = await import("./orchestration.js");
const { tableBalancesForViewer } = await import("./table-view.js");
const {
  GameEventType,
  GamePhase,
  encodeSessionEvent,
} = await import("../game/game-runtime.js");
const {
  ChainExchangePackage,
  ChainPhase,
  ChainSetupKind,
} = await import("../chain/chain-runtime.js");

const SETUP_KIND_BY_EVENT_TYPE = new Map([
  [GameEventType.DESCRIPTOR_SIGNATURE, ChainSetupKind.DESCRIPTOR_SIGNATURE],
]);

const GAME_EXCHANGE_KIND = "test.game.exchange";
const CHAIN_EXCHANGE_KIND = "test.chain.exchange";
const DEPLOYMENT = Object.freeze({
  deploymentId: "test",
  protocolProfile: "headsUpFixedLimitV1",
  protocolProfileCode: 1,
  deploymentDigestHex: "77".repeat(32),
  relay: Object.freeze({
    maxPayloadBase64Bytes: 22_369_624,
    kinds: Object.freeze({
      gameExchange: GAME_EXCHANGE_KIND,
      chainExchange: CHAIN_EXCHANGE_KIND,
    }),
  }),
  chain: Object.freeze({
    network: "signet",
    bitcoinNetworkCode: 2,
    profileIdHex: "44".repeat(32),
  }),
  game: Object.freeze({
    unitSat: 100,
    startingStackSat: 20_000,
    maxBetsPerStreet: 4,
    button: "alice",
  }),
});
const ROOM_ID = "09".repeat(32);
const ORIGIN_TXID = "aa".repeat(32);
const IDENTITIES = [new Uint8Array(32).fill(0x11), new Uint8Array(32).fill(0x22)];
const ACTIVATION_TRANSACTION = Uint8Array.of(0x02, 0x00, 0x00, 0x00, 0xac);
const STARTING_BALANCES = Object.freeze({
  aliceStackSat: 20_000,
  bobStackSat: 20_000,
  potSat: 0,
});
const POST_BLIND_BALANCES = Object.freeze({
  aliceStackSat: 19_900,
  bobStackSat: 19_800,
  potSat: 300,
});

const payoutEdges = [0, 2, 1].map((outcome) => ({
  kind: { name: "bob-payout", outcome },
  childNodeId: new Uint8Array(32).fill(0x30 + outcome),
}));
assert.equal(selectVerifiedSpecialEdge(payoutEdges, 0), payoutEdges[0]);
assert.equal(selectVerifiedSpecialEdge(payoutEdges, 1), payoutEdges[2]);
assert.equal(selectVerifiedSpecialEdge(payoutEdges, 2), payoutEdges[1]);
assert.equal(selectVerifiedSpecialEdge(payoutEdges, null), null);
assert.equal(selectVerifiedSpecialEdge(payoutEdges, 3), null);
assert.equal(selectVerifiedSpecialEdge([payoutEdges[0], payoutEdges[0]], 0), null);
const revealEdge = { kind: { name: "community-reveal", street: 1, revealer: 0 } };
assert.equal(
  selectVerifiedSpecialEdge([
    { kind: { name: "action", action: 2 } },
    revealEdge,
    { kind: { name: "timeout", timeoutKind: 0 } },
  ], null),
  revealEdge,
);

function bytesToHex(value) {
  return Buffer.from(value).toString("hex");
}

function framePayload(value) {
  return Buffer.from(value).toString("base64");
}

function exactBytes(value, length, label) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  assert.equal(bytes.byteLength, length, `${label} length`);
  return bytes;
}

function sameBytes(left, right) {
  return Buffer.from(left).equals(Buffer.from(right));
}

function nodeId(marker) {
  return new Uint8Array(32).fill(marker);
}

function opaqueTransaction(marker) {
  // This is deliberately only an opaque Rust/Wasm-result sentinel. The JS
  // orchestration test never parses, serializes, or mutates Bitcoin fields.
  return Uint8Array.of(0x02, marker, 0x51, 0x00, 0x00);
}

const MISSING_BOARD = Object.freeze([null, null, null, null, null]);

function cardsFor(role, progress = {}) {
  const {
    aliceHoleDelivered = false,
    bobHoleDelivered = false,
    boardCards = 0,
    aliceShown = false,
    bobShown = false,
  } = progress;
  const localDelivered = role === 0 ? aliceHoleDelivered : bobHoleDelivered;
  const publicAlice = aliceShown || (role === 0 && aliceHoleDelivered);
  const publicBob = bobShown || (role === 1 && bobHoleDelivered);
  const board = MISSING_BOARD.map((_, index) => index < boardCards ? index + 1 : null);
  const boardComplete = boardCards === 5;
  const aliceHand = publicAlice && boardComplete ? { subset: 0, score: 100 } : null;
  const bobHand = publicBob && boardComplete ? { subset: 1, score: 90 } : null;
  return {
    role,
    localHole: localDelivered ? (role === 0 ? [0, 12] : [13, 25]) : [null, null],
    board,
    aliceHole: publicAlice ? [0, 12] : [null, null],
    bobHole: publicBob ? [13, 25] : [null, null],
    aliceHand,
    bobHand,
    outcome: aliceHand && bobHand ? 0 : null,
  };
}

function chainPackage(packageId, role) {
  return {
    kind: CHAIN_EXCHANGE_KIND,
    payload: framePayload(Uint8Array.of(packageId, role, 0xa5)),
    messageId: Buffer.from(Uint8Array.from({ length: 32 }, (_, index) =>
      (packageId * 17 + role * 31 + index) & 0xff
    )).toString("hex"),
  };
}

class FakeSecretChainWorker {
  constructor(label, transportRole, lookupGameEvent) {
    this.label = label;
    this.transportRole = transportRole;
    this.lookupGameEvent = lookupGameEvent;
    this.listeners = { message: [], error: [] };
    this.terminated = false;
    this.localRole = undefined;
    this.phase = ChainPhase.EMPTY;
    this.descriptorSigned = false;
    this.descriptorRoles = new Set();
    this.lamportRoles = new Set();
    this.rootCommitmentRoles = new Set();
    this.rootOpeningRoles = new Set();
    this.preauthorizationCommitmentRoles = new Set();
    this.preauthorizationOpeningRoles = new Set();
    this.readyRoles = new Set();
    this.activationRoles = new Set();
    this.inventoryAttestation = null;
    this.cards = null;
    this.nextCards = null;
    this.calls = [];
  }

  expectConfirmedCards(cards) {
    this.nextCards = structuredClone(cards);
  }

  addEventListener(type, listener) {
    this.listeners[type].push(listener);
  }

  postMessage(message) {
    queueMicrotask(() => {
      if (this.terminated) return;
      try {
        const result = this.#handle(message);
        this.#emit("message", { data: { id: message.id, ok: true, ...result } });
      } catch (error) {
        this.#emit("message", {
          data: { id: message.id, ok: false, error: error.message },
        });
      }
    });
  }

  terminate() {
    this.terminated = true;
  }

  #emit(type, event) {
    for (const listener of this.listeners[type]) listener(event);
  }

  #status() {
    return {
      phase: this.phase,
      localRole: this.localRole,
      inventoryVerified: Boolean(this.inventoryAttestation),
      inventoryAttestation: this.inventoryAttestation
        ? Uint8Array.from(this.inventoryAttestation)
        : null,
      readyRoles: [...this.readyRoles].sort(),
      authorizationCached: false,
      erasureCached: false,
      readyForActivation: this.readyRoles.size === 2,
      cards: this.cards ? structuredClone(this.cards) : null,
    };
  }

  #artifactRole(value, prefix, label) {
    const artifact = value instanceof Uint8Array ? value : new Uint8Array(value);
    assert.equal(artifact[0], prefix, `${label} prefix`);
    assert.ok(artifact[1] === 0 || artifact[1] === 1, `${label} role`);
    return artifact[1];
  }

  #requireSize(set, size, operation) {
    assert.equal(set.size, size, `${operation} ran before its two peer artifacts were applied`);
  }

  #runtimeWitness(name, marker) {
    this.calls.push(name);
    return {
      witness: Uint8Array.of(0x57, marker, this.localRole),
      runtimeReceipt: Uint8Array.of(0x52, marker, this.localRole),
    };
  }

  #handle(message) {
    switch (message.type) {
      case "init": {
        this.localRole = message.request.config.localRole;
        assert.equal(message.request.config.transportRole, this.transportRole);
        assert.equal(
          message.request.config.protocolProfile,
          DEPLOYMENT.protocolProfileCode,
        );
        assert.equal(
          message.request.config.bitcoinNetwork,
          DEPLOYMENT.chain.bitcoinNetworkCode,
        );
        exactBytes(message.request.identitySecret, 32, "identity secret");
        exactBytes(message.request.deal.storageKey, 32, "DEAL storage key");
        this.phase = ChainPhase.ACCEPTED_DEAL;
        this.calls.push("init");
        return {
          acknowledged: true,
          localRole: this.localRole,
          phase: this.phase,
          recovered: false,
          restoredCounter: "0",
          runtimeStatus: this.#status(),
          checkpointReceipt: `${this.label}/init`,
        };
      }
      case "sign-descriptor":
        assert.ok(new Uint8Array(message.descriptor).byteLength > 0);
        this.descriptorSigned = true;
        // Rust records the local signature before its relay echo arrives.
        this.descriptorRoles.add(this.localRole);
        this.phase = ChainPhase.DESCRIPTOR_CANDIDATE;
        this.calls.push("signDescriptor");
        return { signature: new Uint8Array(64).fill(0x30 + this.localRole) };
      case "accept-session-event": {
        const event = this.lookupGameEvent(new Uint8Array(message.event));
        const setupKind = SETUP_KIND_BY_EVENT_TYPE.get(event?.type);
        let localLamportBundle = new Uint8Array();
        let duplicate = false;
        if (setupKind === ChainSetupKind.DESCRIPTOR_SIGNATURE) {
          assert.equal(event.role, message.senderRole, "descriptor sender binding");
          duplicate = this.descriptorRoles.has(message.senderRole);
          this.descriptorRoles.add(message.senderRole);
          if (this.descriptorRoles.size === 2) {
            this.phase = ChainPhase.LAMPORT_READY;
            this.lamportRoles.add(this.localRole);
            localLamportBundle = Uint8Array.of(0x50, this.localRole);
          }
        } else {
          this.calls.push("acceptSessionEvent:notApplicable");
          return {
            applicable: false,
            setupKind: 0xff,
            duplicate,
            phase: this.phase,
            localLamportBundle: localLamportBundle.buffer,
            checkpointReceipt: "cd".repeat(32),
          };
        }
        this.calls.push(`acceptSessionEvent:${setupKind}`);
        return {
          applicable: true,
          setupKind,
          duplicate,
          phase: this.phase,
          // Real Worker transfer lists expose this field as ArrayBuffer, not
          // as the Uint8Array returned by the in-Worker runtime decoder.
          localLamportBundle: localLamportBundle.buffer,
          checkpointReceipt: "cd".repeat(32),
        };
      }
      case "make-lamport-bundle":
        assert.equal(this.#artifactRole(message.bundle, 0x50, "Lamport bundle"), this.localRole);
        this.calls.push("makeLamportBundle");
        return { exchange: chainPackage(ChainExchangePackage.LAMPORT_PUBLIC_BUNDLE, this.localRole) };
      case "make-root-commitment":
        this.#requireSize(this.lamportRoles, 2, "root commitment");
        this.rootCommitmentRoles.add(this.localRole);
        this.calls.push("makeRootCommitment");
        return { exchange: chainPackage(ChainExchangePackage.GRAPH_ROOT_COMMITMENT, this.localRole) };
      case "open-root":
        this.#requireSize(this.rootCommitmentRoles, 2, "root opening");
        this.rootOpeningRoles.add(this.localRole);
        this.calls.push("openRoot");
        return { exchange: chainPackage(ChainExchangePackage.GRAPH_ROOT_OPENING, this.localRole) };
      case "make-preauthorization-commitment":
        this.#requireSize(this.rootOpeningRoles, 2, "preauthorization commitment");
        this.preauthorizationCommitmentRoles.add(this.localRole);
        this.calls.push("makePreauthorizationCommitment");
        return { exchange: chainPackage(ChainExchangePackage.PREAUTHORIZATION_COMMITMENT, this.localRole) };
      case "open-preauthorizations":
        this.#requireSize(
          this.preauthorizationCommitmentRoles,
          2,
          "preauthorization opening",
        );
        this.preauthorizationOpeningRoles.add(this.localRole);
        this.calls.push("openPreauthorizations");
        return { exchange: chainPackage(ChainExchangePackage.PREAUTHORIZATION_OPENING, this.localRole) };
      case "attest-inventory":
        this.#requireSize(this.preauthorizationOpeningRoles, 2, "inventory attestation");
        this.inventoryAttestation = new Uint8Array(64).fill(0xa0 + this.localRole);
        this.phase = ChainPhase.INVENTORY_VERIFIED;
        this.calls.push("attestInventory");
        return {
          role: this.localRole,
          signature: Uint8Array.from(this.inventoryAttestation).buffer,
          graphReceipt: Uint8Array.of(0xa5, this.localRole).buffer,
        };
      case "make-inventory-ready":
        assert.ok(this.inventoryAttestation);
        this.readyRoles.add(this.localRole);
        this.calls.push("makeInventoryReady");
        return { exchange: chainPackage(1, this.localRole) };
      case "accept-relay-message": {
        const encoded = Uint8Array.from(Buffer.from(message.message.payload, "base64"));
        const [packageId, role] = encoded;
        const expectedRole = message.message.sender === this.transportRole
          ? this.localRole
          : 1 - this.localRole;
        assert.equal(role, expectedRole, "relay sender/canonical role mapping");
        let setup = null;
        if (packageId === ChainExchangePackage.INVENTORY_READY) this.readyRoles.add(role);
        else if (packageId === ChainExchangePackage.ACTIVATION_SIGNATURE) this.activationRoles.add(role);
        else if (packageId === ChainExchangePackage.LAMPORT_PUBLIC_BUNDLE) {
          this.lamportRoles.add(role);
          if (this.lamportRoles.size === 2) this.phase = ChainPhase.GRAPH_READY;
          setup = { phase: this.phase };
        } else if (packageId === ChainExchangePackage.GRAPH_ROOT_COMMITMENT) {
          this.rootCommitmentRoles.add(role);
          setup = { phase: this.phase };
        } else if (packageId === ChainExchangePackage.GRAPH_ROOT_OPENING) {
          this.rootOpeningRoles.add(role);
          if (this.rootOpeningRoles.size === 2) this.phase = ChainPhase.ROOT_AGREED;
          setup = { phase: this.phase };
        } else if (packageId === ChainExchangePackage.PREAUTHORIZATION_COMMITMENT) {
          this.preauthorizationCommitmentRoles.add(role);
          setup = { phase: this.phase };
        } else if (packageId === ChainExchangePackage.PREAUTHORIZATION_OPENING) {
          this.preauthorizationOpeningRoles.add(role);
          if (this.preauthorizationOpeningRoles.size === 2) {
            this.phase = ChainPhase.PREAUTHORIZATIONS_READY;
          }
          setup = { phase: this.phase };
        } else assert.fail(`unexpected CHAIN package ${packageId}`);
        const readyForActivation = this.readyRoles.size === 2;
        if (packageId === 2 && !readyForActivation) {
          return {
            accepted: false,
            deferred: true,
            package: packageId,
            role,
            readyForActivation: false,
            activationTransaction: null,
          };
        }
        this.calls.push(`acceptPackage:${packageId}`);
        return {
          accepted: true,
          deferred: false,
          package: packageId,
          role,
          readyForActivation,
          activationTransaction: packageId === 2 && this.activationRoles.size === 2
            ? Uint8Array.from(ACTIVATION_TRANSACTION)
            : null,
          setup,
        };
      }
      case "sign-activation":
        assert.equal(this.readyRoles.size, 2);
        assert.ok(new Uint8Array(message.unsignedTransaction).byteLength > 0);
        this.activationRoles.add(this.localRole);
        this.calls.push("signActivation");
        return { exchange: chainPackage(2, this.localRole) };
      case "confirm-activation":
        assert.ok(sameBytes(message.transaction, ACTIVATION_TRANSACTION));
        this.phase = ChainPhase.ACTIVE;
        this.cards = cardsFor(this.localRole);
        this.calls.push("confirmActivation");
        return {
          cards: structuredClone(this.cards),
          stateReceipt: Uint8Array.of(0xc1, this.localRole),
        };
      case "observe-tip":
        assert.ok(Number.isSafeInteger(message.height));
        this.calls.push("observeTip");
        return {};
      case "build-action":
        assert.ok(message.action >= 0 && message.action <= 4);
        this.calls.push(`action:${message.action}`);
        return this.#runtimeWitness("buildAction", 0xb0 + message.action);
      case "build-edge":
        exactBytes(message.childNodeId, 32, "Advance child node id");
        return this.#runtimeWitness("buildEdge", 0xb5);
      case "build-reveal":
        return this.#runtimeWitness("buildReveal", 0xb6);
      case "build-alice-showdown":
        assert.equal(this.localRole, 0);
        assert.deepEqual(
          { subset: message.subset, score: message.score },
          this.cards.aliceHand,
        );
        return this.#runtimeWitness("buildAliceShowdown", 0xb7);
      case "build-bob-payout":
        assert.equal(this.localRole, 1);
        assert.equal(message.subset, this.cards.bobHand.subset);
        assert.equal(message.score, this.cards.bobHand.score);
        assert.equal(message.outcome, this.cards.outcome);
        return this.#runtimeWitness("buildBobPayout", 0xb8);
      case "build-timeout":
        return this.#runtimeWitness("buildTimeout", 0xb9);
      case "confirm-child":
        assert.ok(new Uint8Array(message.transaction).byteLength > 0);
        assert.ok(this.nextCards, "test graph supplied the card projection for this child");
        this.cards = structuredClone(this.nextCards);
        this.nextCards = null;
        this.calls.push("confirmChild");
        return {
          signature: new Uint8Array(64).fill(0xc0 + this.localRole),
          stateReceipt: Uint8Array.of(0xc2, this.localRole),
          cards: structuredClone(this.cards),
        };
      case "project-cards":
        return { cards: structuredClone(this.cards) };
      case "status":
        return this.#status();
      case "clear":
        this.calls.push("clear");
        return {};
      default:
        throw new Error(`unexpected fake CHAIN request ${message.type}`);
    }
  }
}

class FakeRustGameReducer {
  constructor(label, canonicalRole, transportRole, hub) {
    this.label = label;
    this.canonicalRole = canonicalRole;
    this.transportRole = transportRole;
    this.hub = hub;
    this.descriptorRoles = new Set();
    this.history = [];
    this.inventoryAttested = false;
    this.phase = GamePhase.SIGNING_DESCRIPTOR;
    this.activationTransaction = null;
    this.runtimeEdges = [];
    this.selectedRuntimeEdge = null;
    this.resultingBalancesByChild = new Map();
    this.tableBalances = structuredClone(STARTING_BALANCES);
    this.timeoutMaturesAt = undefined;
    this.pendingBroadcast = null;
    this.pendingSpend = null;
    this.currentTerminal = false;
    this.tipHeight = 100;
    this.handoffCount = 0;
  }

  async handoffAcceptedDeal(consumer) {
    this.handoffCount += 1;
    assert.equal(this.handoffCount, 1, `${this.label} accepted DEAL handed off once`);
    return consumer({
      deal: Uint8Array.of(0xd1),
      attestation: Uint8Array.of(0xa1),
      sealedPreimages: Uint8Array.of(0x51),
      storageKey: new Uint8Array(32).fill(0x71 + this.canonicalRole),
    });
  }

  exchangeHistory() {
    return this.history.map((message) => ({ ...message }));
  }

  currentProjection() {
    return structuredClone(this.#projection());
  }

  async publishExchangeEvent(event) {
    this.hub.enqueueGame(this, event);
  }

  async applyGraphPreparedReceipt(receipt) {
    assert.ok(new Uint8Array(receipt).byteLength > 0);
    assert.equal(this.phase, GamePhase.PREPARING_GRAPH);
    this.inventoryAttested = true;
    this.phase = GamePhase.AUTHORIZING_ACTIVATION;
  }

  async applyRuntimeAuthorizationReceipt(receipt) {
    assert.ok(new Uint8Array(receipt).byteLength > 0);
    assert.equal(this.phase, GamePhase.ACTIVE);
    assert.ok(this.runtimeEdges.length > 0);
    assert.ok(this.selectedRuntimeEdge, "test selected one reducer-authorized edge");
    const marker = this.selectedRuntimeEdge.childNodeId[0];
    this.pendingBroadcast = {
      name: "broadcast-transaction",
      txid: Uint8Array.from(this.selectedRuntimeEdge.childNodeId),
      transaction: opaqueTransaction(marker),
      purpose: 1,
    };
  }

  async applyConfirmedStateReceipt(receipt) {
    assert.ok(new Uint8Array(receipt).byteLength > 0);
    if (!this.pendingSpend) {
      assert.equal(this.phase, GamePhase.ACTIVE, "activation state receipt follows confirmation");
      return;
    }
    this.pendingSpend = null;
    this.pendingBroadcast = null;
    this.runtimeEdges = [];
    this.selectedRuntimeEdge = null;
    this.resultingBalancesByChild.clear();
    this.phase = this.currentTerminal ? GamePhase.SETTLED : GamePhase.ACTIVE;
  }

  async applyChainEvent(event) {
    if (event.type === GameEventType.TIP_OBSERVED || event.type === "tip-observed") {
      this.tipHeight = event.block.height;
      return;
    }
    assert.equal(event.type, GameEventType.SPEND_CONFIRMED);
    if (this.phase === GamePhase.AWAITING_ACTIVATION) {
      assert.ok(sameBytes(event.spendingTransaction, this.activationTransaction));
      this.phase = GamePhase.ACTIVE;
      this.tableBalances = structuredClone(POST_BLIND_BALANCES);
      this.pendingBroadcast = null;
      return;
    }
    assert.equal(this.phase, GamePhase.ACTIVE);
    const confirmedEdge = this.runtimeEdges.find((edge) =>
      sameBytes(edge.childNodeId, event.spendingDisplayTxid)
    );
    assert.ok(confirmedEdge, "confirmed transaction selected a reducer-authorized child");
    const resultingBalances = this.resultingBalancesByChild.get(bytesToHex(confirmedEdge.childNodeId));
    assert.ok(resultingBalances, "test graph supplied exact resulting balances");
    this.tableBalances = structuredClone(resultingBalances);
    this.pendingSpend = {
      nodeId: nodeId(0xe0 + (confirmedEdge.childNodeId[0] % 16)),
      spendingDisplayTxid: Uint8Array.from(event.spendingDisplayTxid),
    };
  }

  acceptGameFrame(message, event, senderRole) {
    this.history.push({ ...message });
    if (event.type === GameEventType.DESCRIPTOR_SIGNATURE) this.descriptorRoles.add(senderRole);
    if (event.type === GameEventType.ACTIVATION_AUTHORIZED) {
      if (this.activationTransaction) {
        assert.ok(sameBytes(this.activationTransaction, event.transaction));
      }
      this.activationTransaction = Uint8Array.from(event.transaction);
      this.phase = GamePhase.AWAITING_ACTIVATION;
      this.pendingBroadcast = {
        name: "broadcast-transaction",
        txid: nodeId(0xac),
        transaction: Uint8Array.from(event.transaction),
        purpose: 0,
      };
    }
  }

  setRuntime(edges, { terminal = false, timeoutMaturesAt, resultingBalances } = {}) {
    this.phase = GamePhase.ACTIVE;
    this.runtimeEdges = structuredClone(Array.isArray(edges) ? edges : [edges]);
    this.selectedRuntimeEdge = null;
    this.resultingBalancesByChild.clear();
    for (const edge of this.runtimeEdges) {
      this.resultingBalancesByChild.set(
        bytesToHex(edge.childNodeId),
        structuredClone(resultingBalances ?? this.tableBalances),
      );
    }
    this.timeoutMaturesAt = timeoutMaturesAt;
    this.currentTerminal = terminal;
    this.pendingBroadcast = null;
    this.pendingSpend = null;
  }

  selectRuntimeEdge(childNodeId) {
    const selected = this.runtimeEdges.find((edge) => sameBytes(edge.childNodeId, childNodeId));
    assert.ok(selected, "player or automation selected a reducer-authorized child");
    this.selectedRuntimeEdge = selected;
  }

  #projection() {
    const status = {
      phase: this.phase,
      dealGameId: nodeId(0xd0),
      sharedConfigHash: nodeId(0xc0),
      dealAttempt: 0,
      dealEnvelopes: 16,
      chainGameId: this.phase >= GamePhase.PREPARING_GRAPH ? nodeId(0xc1) : undefined,
      graphRoot: this.phase >= GamePhase.AUTHORIZING_ACTIVATION ? nodeId(0xc2) : undefined,
      tableBalances: structuredClone(this.tableBalances),
    };
    if (this.phase === GamePhase.AWAITING_ACTIVATION) {
      return {
        status,
        intents: [
          structuredClone(this.pendingBroadcast),
          { name: "observe-state", outpoint: { txid: nodeId(0xaa), vout: 0 } },
        ],
      };
    }
    if (this.phase === GamePhase.ACTIVE) {
      if (this.pendingSpend) {
        return {
          status,
          intents: [{
            name: "erase-node-secrets",
            nodeId: Uint8Array.from(this.pendingSpend.nodeId),
            txid: Uint8Array.from(this.pendingSpend.spendingDisplayTxid),
            digest: nodeId(0xed),
          }],
        };
      }
      const intents = this.pendingBroadcast
        ? [structuredClone(this.pendingBroadcast)]
        : [{
          name: "choose-runtime-edge",
          nodeId: nodeId(0xe1),
          nodeKind: 1,
          edges: structuredClone(this.runtimeEdges),
          timeoutMaturesAt: this.timeoutMaturesAt,
        }];
      intents.push({ name: "observe-state", outpoint: { txid: nodeId(0xbb), vout: 0 } });
      return { status, intents };
    }
    if (this.phase === GamePhase.SETTLED) {
      return { status, intents: [{ name: "settlement-confirmed", nodeId: nodeId(0xef), txid: nodeId(0xfe) }] };
    }
    if (this.phase === GamePhase.AUTHORIZING_ACTIVATION) {
      return {
        status,
        intents: [{ name: "authorize-activation", unsignedTransaction: Uint8Array.of(0xa1) }],
      };
    }
    if (this.descriptorRoles.size < 2) {
      return { status, intents: [{ name: "sign-descriptor", descriptor: Uint8Array.of(0xd5) }] };
    }
    this.phase = GamePhase.PREPARING_GRAPH;
    status.phase = this.phase;
    return { status, intents: [{ name: "prepare-graph" }] };
  }
}

class RelayHub {
  constructor(label) {
    this.label = label;
    this.queue = [];
    this.cursor = 0;
    this.delivered = 0;
    this.known = new Map();
    this.gameEventsByBytes = new Map();
    this.players = [];
    this.workers = new Map();
  }

  canonicalRole(transportRole) {
    return transportRole === "bob" ? 0 : 1;
  }

  workerFactory(transportRole) {
    return () => {
      const worker = new FakeSecretChainWorker(
        `${this.label}/${transportRole}`,
        transportRole,
        (bytes) => this.gameEventsByBytes.get(bytesToHex(bytes)),
      );
      this.workers.set(this.canonicalRole(transportRole), worker);
      return worker;
    };
  }

  sender(transportRole) {
    return async (frame) => this.#enqueue({ ...frame, sender: transportRole });
  }

  enqueueGame(game, event) {
    const bytes = encodeSessionEvent(event);
    this.gameEventsByBytes.set(bytesToHex(bytes), structuredClone(event));
    this.cursor += 1;
    const message = {
      cursor: this.cursor,
      messageId: this.cursor.toString(16).padStart(64, "0"),
      sender: game.transportRole,
      kind: GAME_EXCHANGE_KIND,
      payload: framePayload(bytes),
    };
    this.known.set(message.messageId, { message, event: structuredClone(event) });
    this.queue.push(this.known.get(message.messageId));
  }

  #enqueue(frame) {
    const prior = this.known.get(frame.messageId);
    if (prior) {
      assert.deepEqual(prior.message, { ...frame, cursor: prior.message.cursor });
      return;
    }
    this.cursor += 1;
    const entry = { message: { ...frame, cursor: this.cursor }, event: null };
    this.known.set(frame.messageId, entry);
    this.queue.push(entry);
  }

  async drain() {
    while (this.delivered < this.queue.length) {
      const entry = this.queue[this.delivered];
      this.delivered += 1;
      for (const player of this.players) {
        if (entry.message.kind === GAME_EXCHANGE_KIND) {
          // The sole public setup event is the descriptor signature. The graph
          // and preauthorization protocol stays inside CHAIN and returns only
          // compact receipts to GAME.
          const accepted = await player.flow.acceptGameRelayMessage(entry.message);
          assert.equal(accepted.disposition, "game");
          player.game.acceptGameFrame(
            entry.message,
            entry.event,
            this.canonicalRole(entry.message.sender),
          );
          await player.flow.updateProjection(player.game.currentProjection());
        } else {
          assert.equal(entry.message.kind, CHAIN_EXCHANGE_KIND);
          const result = await player.flow.acceptChainRelayMessage(entry.message);
          assert.equal(result.deferred, false, "normal setup must not defer a CHAIN frame");
        }
      }
    }
  }
}

function flowContext(game, hub, transportRole, localRole, updates) {
  return {
    deploymentConfig: DEPLOYMENT,
    game,
    roomId: ROOM_ID,
    sessionNonceHex: "39".repeat(32),
    transportRole,
    localRole,
    localSecretKeyHex: (localRole === 0 ? "31" : "32").repeat(32),
    identities: IDENTITIES.map((identity) => Uint8Array.from(identity)),
    origin: {
      displayTxid: ORIGIN_TXID,
      vout: 0,
      witnessScriptHex: "00".repeat(104),
    },
    sendExchange: hub.sender(transportRole),
    onUpdate: (view) => updates.push(view),
  };
}

async function activatedPair(label) {
  const hub = new RelayHub(label);
  const gameA = new FakeRustGameReducer(`${label}/A`, 0, "bob", hub);
  const gameB = new FakeRustGameReducer(`${label}/B`, 1, "alice", hub);
  const updatesA = [];
  const updatesB = [];
  const flowA = new BrowserChainGameFlow(
    flowContext(gameA, hub, "bob", 0, updatesA),
    {
      store: new MemoryChainRelayStore(),
      workerFactory: hub.workerFactory("bob"),
      chainWasm: new Uint8Array(8),
    },
  );
  const flowB = new BrowserChainGameFlow(
    flowContext(gameB, hub, "alice", 1, updatesB),
    {
      store: new MemoryChainRelayStore(),
      workerFactory: hub.workerFactory("alice"),
      chainWasm: new Uint8Array(8),
    },
  );
  hub.players.push({ game: gameA, flow: flowA }, { game: gameB, flow: flowB });
  const telemetry = {
    setupPlayerClicks: 0,
    automaticActivationAuthorizations: 0,
    playerDecisions: [],
    automaticEdges: [],
    publishedTransactions: [],
    confirmedTransactions: [],
  };

  // A confirmed two-player origin enters this fixture here. Everything through
  // activation authorization is driven in the background; no UI decision is
  // represented or required.
  await flowA.updateProjection(gameA.currentProjection());
  await flowB.updateProjection(gameB.currentProjection());
  await hub.drain();

  assert.equal(flowA.view().readyForActivation, true);
  assert.equal(flowB.view().readyForActivation, true);
  assert.equal(flowA.view().stage, "ready");
  assert.equal(flowB.view().stage, "ready");
  telemetry.automaticActivationAuthorizations = [flowA, flowB].filter(
    (flow) => flow.view().activationSignatureSent,
  ).length;
  assert.equal(telemetry.setupPlayerClicks, 0, "setup did not ask either player to click");
  assert.equal(telemetry.automaticActivationAuthorizations, 2);
  assert.equal(flowA.view().phase, GamePhase.AWAITING_ACTIVATION);
  assert.equal(flowB.view().phase, GamePhase.AWAITING_ACTIVATION);
  assert.ok(sameBytes(flowA.view().pendingBroadcast.transaction, ACTIVATION_TRANSACTION));
  assert.ok(sameBytes(flowB.view().pendingBroadcast.transaction, ACTIVATION_TRANSACTION));

  const activationFact = {
    type: GameEventType.SPEND_CONFIRMED,
    profileId: nodeId(0xf0),
    spentOutpoint: { displayTxid: nodeId(0xaa), vout: 0 },
    spendingDisplayTxid: nodeId(0xac),
    spendingTransaction: Uint8Array.from(ACTIVATION_TRANSACTION),
    inputIndex: 0,
    confirmedIn: { height: 101, displayHash: nodeId(0x01) },
    observedTip: { height: 101, displayHash: nodeId(0x01) },
  };
  await flowA.confirmSpend(activationFact);
  await flowB.confirmSpend(activationFact);
  assert.equal(flowA.view().phase, GamePhase.ACTIVE);
  assert.equal(flowB.view().phase, GamePhase.ACTIVE);
  assert.deepEqual(flowA.view().cards.localHole, [null, null]);
  assert.deepEqual(flowB.view().cards.localHole, [null, null]);
  assert.deepEqual(gameA.currentProjection().status.tableBalances, POST_BLIND_BALANCES);
  assert.deepEqual(gameB.currentProjection().status.tableBalances, POST_BLIND_BALANCES);

  return {
    hub,
    games: [gameA, gameB],
    flows: [flowA, flowB],
    updates: [updatesA, updatesB],
    telemetry,
    nextHeight: 102,
  };
}

function runtimeEdge(marker, kind, authorization) {
  return {
    childNodeId: nodeId(marker),
    kind,
    authorization,
    sighash: nodeId(0x40 + (marker % 32)),
  };
}

function actionEdges(marker, actor, legalActions) {
  return legalActions.map((action, index) => runtimeEdge(
    marker + index,
    { name: "action", action },
    { name: "betting-action", actor },
  ));
}

function clickablePokerEdges(edges, localRole) {
  return edges.filter((edge) =>
    edge.kind.name === "action" && localRoleMayAuthorizeEdge(edge, localRole)
  );
}

function assertTableBalances(pair, expected) {
  assert.equal(
    expected.aliceStackSat + expected.bobStackSat + expected.potSat,
    DEPLOYMENT.game.startingStackSat * 2,
    "public stacks and pot conserve all poker chips",
  );
  for (const [role, game] of pair.games.entries()) {
    const projected = game.currentProjection().status.tableBalances;
    assert.deepEqual(projected, expected, `role ${role} receives exact Rust table balances`);
    assert.deepEqual(
      tableBalancesForViewer(projected, role, DEPLOYMENT.game.startingStackSat),
      role === 0
        ? {
            localStackSat: expected.aliceStackSat,
            opponentStackSat: expected.bobStackSat,
            potSat: expected.potSat,
          }
        : {
            localStackSat: expected.bobStackSat,
            opponentStackSat: expected.aliceStackSat,
            potSat: expected.potSat,
          },
      `role ${role} maps canonical stacks to the correct seats`,
    );
  }
}

function gameplayPublishState(pending, submitted) {
  const pendingTxid = pending?.txid ? bytesToHex(pending.txid) : null;
  return {
    ownsSeat: true,
    halted: false,
    busy: false,
    retryReady: true,
    originRefunded: false,
    pendingPurpose: pending?.purpose,
    pendingTransactionPresent: Boolean(pending?.transaction),
    pendingTxid,
    submitted,
  };
}

async function confirmRuntimeStep(pair, {
  edges,
  authorizer,
  resultingBalances,
  cards,
  selectedAction,
  automatic = false,
  terminal = false,
  timeoutMaturesAt,
  timeoutClaim = false,
}) {
  assert.ok(Array.isArray(edges) && edges.length > 0);
  for (const game of pair.games) {
    game.setRuntime(edges, { terminal, timeoutMaturesAt, resultingBalances });
  }
  for (const role of [0, 1]) {
    pair.hub.workers.get(role).expectConfirmedCards(cardsFor(role, cards));
  }
  await pair.flows[0].updateProjection(pair.games[0].currentProjection());
  await pair.flows[1].updateProjection(pair.games[1].currentProjection());

  let selected;
  if (automatic) {
    for (const role of [0, 1]) {
      assert.deepEqual(
        clickablePokerEdges(pair.flows[role].view().legalEdges, role),
        [],
        "protocol-only transitions never become poker buttons",
      );
    }
    selected = selectAutomaticGameEdge(pair.flows[authorizer].view().legalEdges, {
      localRole: authorizer,
      cards: pair.flows[authorizer].view().cards,
    });
    assert.ok(selected, "the obligated participant selects the automatic transition");
    assert.equal(selectAutomaticGameEdge(pair.flows[1 - authorizer].view().legalEdges, {
      localRole: 1 - authorizer,
      cards: pair.flows[1 - authorizer].view().cards,
    }), null, "the other participant cannot run this automatic transition");
    pair.telemetry.automaticEdges.push(bytesToHex(selected.childNodeId));
  } else if (timeoutClaim) {
    selected = edges.find((edge) => edge.kind.name === "timeout");
    assert.ok(selected);
    assert.equal(localRoleMayAuthorizeEdge(selected, authorizer), true);
    assert.equal(localRoleMayAuthorizeEdge(selected, 1 - authorizer), false);
  } else {
    assert.ok(Number.isSafeInteger(selectedAction), "a poker decision names its selected action");
    const actorChoices = clickablePokerEdges(pair.flows[authorizer].view().legalEdges, authorizer);
    assert.deepEqual(
      actorChoices.map((edge) => edge.kind.action),
      edges.map((edge) => edge.kind.action),
      "the acting player can click every and only reducer-authorized poker choice",
    );
    assert.deepEqual(
      clickablePokerEdges(pair.flows[1 - authorizer].view().legalEdges, 1 - authorizer),
      [],
      "the non-actor has no clickable poker choice",
    );
    assert.equal(selectAutomaticGameEdge(edges, {
      localRole: authorizer,
      cards: pair.flows[authorizer].view().cards,
    }), null, "strategic poker decisions are never auto-selected");
    selected = actorChoices.find((edge) => edge.kind.action === selectedAction);
    assert.ok(selected, "the chosen action is in the reducer-authorized set");
    pair.telemetry.playerDecisions.push(selectedAction);
  }

  pair.games[authorizer].selectRuntimeEdge(selected.childNodeId);
  await pair.flows[authorizer].authorizeEdge(bytesToHex(selected.childNodeId));
  const pending = pair.flows[authorizer].view().pendingBroadcast;
  assert.ok(pending?.transaction, "Rust/Wasm reducer returned an opaque transaction");
  assert.ok(sameBytes(pending.txid, selected.childNodeId));
  assert.equal(
    pair.flows[1 - authorizer].view().pendingBroadcast,
    undefined,
    "only the authorizing browser receives the opaque transaction",
  );

  const publishAction = nextGameplayPublishAction(gameplayPublishState(pending, false));
  assert.equal(publishAction?.pendingTxid, bytesToHex(selected.childNodeId));
  pair.telemetry.publishedTransactions.push(publishAction.pendingTxid);
  assert.equal(
    nextGameplayPublishAction(gameplayPublishState(pending, true)),
    null,
    "the automatic publisher submits each transaction once",
  );

  const height = pair.nextHeight;
  pair.nextHeight += 1;
  const fact = {
    type: GameEventType.SPEND_CONFIRMED,
    profileId: nodeId(0xf0),
    spentOutpoint: { displayTxid: nodeId(0xbb), vout: 0 },
    spendingDisplayTxid: Uint8Array.from(pending.txid),
    spendingTransaction: Uint8Array.from(pending.transaction),
    inputIndex: 0,
    confirmedIn: { height, displayHash: nodeId(0x02) },
    observedTip: { height, displayHash: nodeId(0x02) },
  };
  await pair.flows[0].confirmSpend(fact);
  await pair.flows[1].confirmSpend(fact);
  pair.telemetry.confirmedTransactions.push({
    txid: bytesToHex(fact.spendingDisplayTxid),
    height,
  });
  assert.equal(pair.flows[0].view().phase, terminal ? GamePhase.SETTLED : GamePhase.ACTIVE);
  assert.equal(pair.flows[1].view().phase, terminal ? GamePhase.SETTLED : GamePhase.ACTIVE);
  assertTableBalances(pair, resultingBalances);
  for (const role of [0, 1]) {
    assert.deepEqual(pair.flows[role].view().cards, cardsFor(role, cards));
  }
}

assert.equal(
  DEPLOYMENT.game.startingStackSat / (DEPLOYMENT.game.unitSat * 2),
  100,
  "the browser contract exercises exact 100-big-blind stacks",
);

const showdown = await activatedPair("showdown");
const fullHand = [
  // Hole-card delivery is automatic and reveals only the receiving player's hand.
  { edges: [runtimeEdge(1, { name: "hole-card-reveal", revealer: 1 }, { name: "reveal-preimages", revealer: 1 })], authorizer: 1, resultingBalances: POST_BLIND_BALANCES, cards: { aliceHoleDelivered: true }, automatic: true },
  { edges: [runtimeEdge(2, { name: "hole-card-reveal", revealer: 0 }, { name: "reveal-preimages", revealer: 0 })], authorizer: 0, resultingBalances: POST_BLIND_BALANCES, cards: { aliceHoleDelivered: true, bobHoleDelivered: true }, automatic: true },

  // Preflop: Alice completes the blind and Bob takes the check option.
  { edges: actionEdges(10, 0, [0, 2, 4]), authorizer: 0, selectedAction: 2, resultingBalances: { aliceStackSat: 19_800, bobStackSat: 19_800, potSat: 400 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true } },
  { edges: actionEdges(14, 1, [1, 4]), authorizer: 1, selectedAction: 1, resultingBalances: { aliceStackSat: 19_800, bobStackSat: 19_800, potSat: 400 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true } },

  // Flop reveal order is Alice then Bob. The board appears only after both shares.
  { edges: [runtimeEdge(20, { name: "community-reveal", street: 1, revealer: 0 }, { name: "reveal-preimages", revealer: 0 })], authorizer: 0, resultingBalances: { aliceStackSat: 19_800, bobStackSat: 19_800, potSat: 400 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true }, automatic: true },
  { edges: [runtimeEdge(21, { name: "community-reveal", street: 1, revealer: 1 }, { name: "reveal-preimages", revealer: 1 })], authorizer: 1, resultingBalances: { aliceStackSat: 19_800, bobStackSat: 19_800, potSat: 400 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 3 }, automatic: true },
  { edges: actionEdges(30, 1, [1, 3]), authorizer: 1, selectedAction: 1, resultingBalances: { aliceStackSat: 19_800, bobStackSat: 19_800, potSat: 400 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 3 } },
  { edges: actionEdges(34, 0, [1, 3]), authorizer: 0, selectedAction: 3, resultingBalances: { aliceStackSat: 19_600, bobStackSat: 19_800, potSat: 600 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 3 } },
  { edges: actionEdges(38, 1, [0, 2, 4]), authorizer: 1, selectedAction: 4, resultingBalances: { aliceStackSat: 19_600, bobStackSat: 19_400, potSat: 1_000 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 3 } },
  { edges: actionEdges(42, 0, [0, 2, 4]), authorizer: 0, selectedAction: 2, resultingBalances: { aliceStackSat: 19_400, bobStackSat: 19_400, potSat: 1_200 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 3 } },

  // Turn reveal order is Bob then Alice; the big-bet increment is ₿400.
  { edges: [runtimeEdge(50, { name: "community-reveal", street: 2, revealer: 1 }, { name: "reveal-preimages", revealer: 1 })], authorizer: 1, resultingBalances: { aliceStackSat: 19_400, bobStackSat: 19_400, potSat: 1_200 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 3 }, automatic: true },
  { edges: [runtimeEdge(51, { name: "community-reveal", street: 2, revealer: 0 }, { name: "reveal-preimages", revealer: 0 })], authorizer: 0, resultingBalances: { aliceStackSat: 19_400, bobStackSat: 19_400, potSat: 1_200 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 4 }, automatic: true },
  { edges: actionEdges(54, 1, [1, 3]), authorizer: 1, selectedAction: 3, resultingBalances: { aliceStackSat: 19_400, bobStackSat: 19_000, potSat: 1_600 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 4 } },
  { edges: actionEdges(58, 0, [0, 2, 4]), authorizer: 0, selectedAction: 2, resultingBalances: { aliceStackSat: 19_000, bobStackSat: 19_000, potSat: 2_000 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 4 } },

  // River reveal order is Alice then Bob, followed by one final bet and call.
  { edges: [runtimeEdge(66, { name: "community-reveal", street: 3, revealer: 0 }, { name: "reveal-preimages", revealer: 0 })], authorizer: 0, resultingBalances: { aliceStackSat: 19_000, bobStackSat: 19_000, potSat: 2_000 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 4 }, automatic: true },
  { edges: [runtimeEdge(67, { name: "community-reveal", street: 3, revealer: 1 }, { name: "reveal-preimages", revealer: 1 })], authorizer: 1, resultingBalances: { aliceStackSat: 19_000, bobStackSat: 19_000, potSat: 2_000 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 5 }, automatic: true },
  { edges: actionEdges(70, 1, [1, 3]), authorizer: 1, selectedAction: 1, resultingBalances: { aliceStackSat: 19_000, bobStackSat: 19_000, potSat: 2_000 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 5 } },
  { edges: actionEdges(74, 0, [1, 3]), authorizer: 0, selectedAction: 3, resultingBalances: { aliceStackSat: 18_600, bobStackSat: 19_000, potSat: 2_400 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 5 } },
  { edges: actionEdges(78, 1, [0, 2, 4]), authorizer: 1, selectedAction: 2, resultingBalances: { aliceStackSat: 18_600, bobStackSat: 18_600, potSat: 2_800 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 5 } },

  // Alice's score proof and the only outcome-matched Bob payout are automatic.
  { edges: [runtimeEdge(86, { name: "alice-showdown" }, { name: "alice-score" })], authorizer: 0, resultingBalances: { aliceStackSat: 18_600, bobStackSat: 18_600, potSat: 2_800 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 5, aliceShown: true }, automatic: true },
  { edges: [0, 2, 1].map((outcome, index) => runtimeEdge(90 + index, { name: "bob-payout", outcome }, { name: "bob-live-payout" })), authorizer: 1, resultingBalances: { aliceStackSat: 21_400, bobStackSat: 18_600, potSat: 0 }, cards: { aliceHoleDelivered: true, bobHoleDelivered: true, boardCards: 5, aliceShown: true, bobShown: true }, automatic: true, terminal: true },
];
for (const step of fullHand) await confirmRuntimeStep(showdown, step);

assert.deepEqual(
  [...new Set(showdown.telemetry.playerDecisions)].sort(),
  [1, 2, 3, 4],
  "the full hand selects Check, Call, Bet, and Raise",
);
assert.equal(showdown.telemetry.automaticEdges.length, 10);
assert.equal(showdown.telemetry.publishedTransactions.length, fullHand.length);
assert.deepEqual(
  showdown.telemetry.confirmedTransactions.map(({ height }) => height),
  Array.from({ length: fullHand.length }, (_, index) => 102 + index),
  "every opaque gameplay transaction confirms once, in order, before the next edge",
);
assert.deepEqual(
  showdown.telemetry.confirmedTransactions.map(({ txid }) => txid),
  showdown.telemetry.publishedTransactions,
  "the confirmed transaction sequence exactly matches the auto-published sequence",
);

const fold = await activatedPair("fold");
await confirmRuntimeStep(fold, {
  edges: actionEdges(100, 0, [0, 2, 4]),
  authorizer: 0,
  selectedAction: 0,
  resultingBalances: { aliceStackSat: 19_900, bobStackSat: 20_100, potSat: 0 },
  cards: {},
  terminal: true,
});

const timeout = await activatedPair("timeout");
const timeoutHeight = 144;
const tipEvent = {
  type: GameEventType.TIP_OBSERVED,
  profileId: nodeId(0xf0),
  block: { height: timeoutHeight, displayHash: nodeId(0x03) },
};
await timeout.flows[0].observeTip(tipEvent);
await timeout.flows[1].observeTip(tipEvent);
await confirmRuntimeStep(timeout, {
  edges: [runtimeEdge(110, { name: "timeout", timeoutKind: 0 }, { name: "timeout", beneficiary: 1 })],
  authorizer: 1,
  resultingBalances: { aliceStackSat: 19_900, bobStackSat: 20_100, potSat: 0 },
  cards: {},
  terminal: true,
  timeoutMaturesAt: timeoutHeight,
  timeoutClaim: true,
});

const allPairs = [showdown, fold, timeout];
for (const pair of allPairs) {
  for (const role of [0, 1]) {
    const calls = pair.hub.workers.get(role).calls;
    for (const required of [
      "init",
      "signDescriptor",
      "makeRootCommitment",
      "openRoot",
      "makePreauthorizationCommitment",
      "openPreauthorizations",
      "attestInventory",
      "makeInventoryReady",
      "signActivation",
      "confirmActivation",
    ]) {
      assert.ok(calls.includes(required), `${pair.hub.label} role ${role} called ${required}`);
    }
    assert.ok(
      calls.some((value) => value.startsWith("acceptSessionEvent:")),
      `${pair.hub.label} role ${role} used the opaque SessionEvent ingress`,
    );
    assert.ok(calls.includes("confirmChild"), `${pair.hub.label} role ${role} confirmed a child`);
  }
}

for (const pair of allPairs) {
  const bobCalls = pair.hub.workers.get(1).calls;
  assert.ok(
    bobCalls.indexOf(`acceptPackage:${ChainExchangePackage.LAMPORT_PUBLIC_BUNDLE}`) <
      bobCalls.indexOf("makeLamportBundle"),
    `${pair.hub.label} Bob materializes before handing the graph compile to Alice`,
  );
}

const showdownCalls = [...showdown.hub.workers.values()].flatMap((worker) => worker.calls);
for (const builder of [
  "buildAction",
  "buildReveal",
  "buildAliceShowdown",
  "buildBobPayout",
]) {
  assert.ok(showdownCalls.includes(builder), `100-BB full hand exercised ${builder}`);
}
assert.ok(fold.hub.workers.get(0).calls.includes("action:0"), "fold action reached Rust/Wasm");
assert.ok(timeout.hub.workers.get(1).calls.includes("buildTimeout"), "timeout builder reached Rust/Wasm");

await Promise.all(allPairs.flatMap((pair) => pair.flows.map((flow) => flow.cancel())));

process.stdout.write(
  "browser CHAIN coordinator actual-order mock: automatic setup + full 100-BB hand + fold + timeout ok\n",
);
