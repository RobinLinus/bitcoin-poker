import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const {
  BrowserGameFlow,
  MemoryGameStore,
  compactProcessedGameFrame,
} = await import("./game-client.js");
const { GameEventType } = await import("../game/game-runtime.js");

const BODY = new Uint8Array(646).fill(0x42);
const NETWORK_ID =
  "e3bc9730af93197380e11b43ca00d6b516d83321f46b8b9f53a22a4fae89e680";
const GAME_EXCHANGE_KIND = "test.game.exchange";
const DEPLOYMENT = Object.freeze({
  deploymentId: "test",
  deploymentDigestHex: "77".repeat(32),
  protocolProfile: "headsUpFixedLimitV1",
  protocolProfileCode: 1,
  relay: Object.freeze({
    maxPayloadBase64Bytes: 22_369_624,
    kinds: Object.freeze({ gameExchange: GAME_EXCHANGE_KIND }),
  }),
  chain: Object.freeze({
    network: "signet",
    bitcoinNetworkCode: 2,
    profileIdHex: NETWORK_ID,
    confirmations: Object.freeze({ origin: 1, gameplay: 1 }),
  }),
  game: Object.freeze({
    originValueSat: 53_500,
    activationFeeSat: 500,
    button: "alice",
    revealOrder: Object.freeze({ flopFirst: "alice", turnFirst: "bob", riverFirst: "alice" }),
    splitRemainderRecipient: "bob",
  }),
});
const SMALL_KEY = "11".repeat(32);
const LARGE_KEY = "ee".repeat(32);

class FakeWorker {
  constructor(kind, role) {
    this.kind = kind;
    this.role = role;
    this.listeners = { message: [], error: [] };
    this.terminated = false;
    this.game = { phase: 0, sequence: 0, signatures: new Set() };
    this.deal = {
      sequence: 0,
      duplicateEnvelopes: 0,
      localSigned: false,
      peerSigned: false,
      accepted: false,
    };
  }

  addEventListener(type, listener) {
    this.listeners[type].push(listener);
  }

  postMessage(message) {
    queueMicrotask(() => {
      if (this.terminated) return;
      try {
        const result = this.kind === "game" ? this.#game(message) : this.#deal(message);
        this.#emit("message", { data: { id: message.id, ok: true, ...result } });
      } catch (error) {
        this.#emit("message", { data: { id: message.id, ok: false, error: error.message } });
      }
    });
  }

  terminate() {
    this.terminated = true;
  }

  #emit(type, value) {
    for (const listener of this.listeners[type]) listener(value);
  }

  #game(message) {
    switch (message.type) {
      case "init":
        this.role = message.config.localRole;
        assert.equal(message.config.protocolProfile, DEPLOYMENT.protocolProfileCode);
        assert.equal(message.config.bitcoinNetwork, DEPLOYMENT.chain.bitcoinNetworkCode);
        return { projection: this.#projection() };
      case "replay": {
        const saved = message.snapshot;
        this.game = {
          phase: saved.phase,
          sequence: saved.sequence,
          signatures: new Set(saved.signatures),
        };
        return { projection: this.#projection() };
      }
      case "apply-event": {
        if (message.source === 0) {
          this.game.phase = 1;
        } else if (message.event?.type === GameEventType.DEAL_VERIFICATION_ATTESTED) {
          assert.ok(new Uint8Array(message.event.attestation).byteLength > 0);
          this.game.phase = 2;
        }
        return { projection: this.#projection() };
      }
      case "apply-preauthorization-receipt": {
        assert.ok(new Uint8Array(message.receipt).byteLength > 0);
        return { projection: this.#projection() };
      }
      case "apply-exchange-event": {
        const event = new Uint8Array(message.event);
        let dealDispatch = { kind: "none" };
        if (this.game.sequence < 16) {
          const length = new DataView(event.buffer, event.byteOffset, event.byteLength)
            .getUint32(1, true);
          const envelope = event.slice(5, 5 + length);
          this.game.sequence += 1;
          dealDispatch = { kind: "deal-envelope", envelope };
        } else {
          assert.equal(
            this.game.phase,
            2,
            "accepted-deal signatures require a locally attested terminal deal",
          );
          this.game.signatures.add(event[1]);
          if (this.game.signatures.size === 2) this.game.phase = 3;
          dealDispatch = {
            kind: "accepted-deal-signature",
            role: event[1],
            signature: event.slice(2),
          };
        }
        return { projection: this.#projection(), dealDispatch };
      }
      case "snapshot":
        return {
          snapshot: {
            phase: this.game.phase,
            sequence: this.game.sequence,
            signatures: [...this.game.signatures],
          },
        };
      case "clear":
        return {};
      default:
        throw new Error(`unexpected fake game request ${message.type}`);
    }
  }

  #projection() {
    const status = {
      phase: this.game.phase,
      tableBalances: {
        aliceStackSat: 20_000,
        bobStackSat: 20_000,
        potSat: 0,
      },
      dealGameId: new Uint8Array(32).fill(0x55),
      sharedConfigHash: new Uint8Array(32).fill(0x56),
      dealAttempt: 0,
      dealEnvelopes: this.game.sequence,
    };
    let intents = [];
    if (this.game.phase === 0) {
      intents = [{ name: "observe-origin" }];
    } else if (this.game.phase === 1) {
      intents = [{
        name: "deal-envelope-due",
        attempt: 0,
        sequence: this.game.sequence,
        sender: this.game.sequence % 2,
      }];
    } else if (this.game.phase === 2 && !this.game.signatures.has(this.role)) {
      intents = [{ name: "sign-accepted-deal", body: BODY }];
    } else if (this.game.phase === 3) {
      intents = [{ name: "sign-descriptor", descriptor: new Uint8Array([1]) }];
    }
    return { status, intents, appendDisposition: 2 };
  }

  #deal(message) {
    const snapshot = () => ({
      status: this.deal.accepted
        ? "accepted"
        : this.deal.sequence === 16
          ? this.deal.localSigned
            ? "peer-acceptance-signature"
            : "local-acceptance-signature"
          : this.deal.sequence % 2 === this.role
            ? "local-envelope"
            : "peer-envelope",
      localRole: this.role,
      attempt: 0,
      nextSequence: this.deal.sequence,
      hasRetainedPreimages: this.deal.accepted,
      wasmMiB: 1,
    });
    switch (message.type) {
      case "init":
        return { snapshot: snapshot() };
      case "snapshot":
        return { snapshot: snapshot() };
      case "prepare-bundle":
        return { snapshot: snapshot() };
      case "generate-envelope": {
        const envelope = Uint8Array.of(this.deal.sequence, this.role, 0xa5);
        this.deal.sequence += 1;
        return { envelope: envelope.buffer, snapshot: snapshot() };
      }
      case "accept-envelope": {
        const sequence = new Uint8Array(message.envelope)[0];
        if (sequence < this.deal.sequence) {
          this.deal.duplicateEnvelopes += 1;
          return { snapshot: snapshot() };
        }
        assert.equal(sequence, this.deal.sequence);
        this.deal.sequence += 1;
        return { snapshot: snapshot() };
      }
      case "export-accepted-body":
        return { body: BODY.buffer.slice(0), snapshot: snapshot() };
      case "make-acceptance-signature": {
        assert.deepEqual(new Uint8Array(message.body), BODY);
        this.deal.localSigned = true;
        return { signature: new Uint8Array(64).fill(this.role + 1).buffer, snapshot: snapshot() };
      }
      case "accept-acceptance-signature":
        assert.equal(message.role, 1 - this.role);
        this.deal.peerSigned = true;
        this.deal.accepted = this.deal.localSigned;
        return { snapshot: snapshot() };
      case "export":
        return {
          body: BODY.buffer.slice(0),
          deal: new Uint8Array(774).fill(0x71).buffer,
          attestation: new Uint8Array([0x41, 0x54, 0x54]).buffer,
          snapshot: snapshot(),
        };
      case "export-verification-attestation":
        return {
          attestation: new Uint8Array([0x41, 0x54, 0x54]).buffer,
          snapshot: snapshot(),
        };
      case "seal-preimages":
        assert.equal(new Uint8Array(message.storageKey).byteLength, 32);
        return { sealedPreimages: new Uint8Array([0x53, 0x45, 0x41, 0x4c]).buffer };
      case "clear":
        return {};
      default:
        throw new Error(`unexpected fake DEAL request ${message.type}`);
    }
  }
}

function workerFactory(role, workers = []) {
  return (url) => {
    const worker = new FakeWorker(url.includes("/game/") ? "game" : "deal", role);
    workers.push(worker);
    return worker;
  };
}

class TamperableMemoryGameStore extends MemoryGameStore {
  constructor() {
    super();
    this.tamperAcceptedRead = false;
  }

  async load(key) {
    const record = await super.load(key);
    if (this.tamperAcceptedRead && record?.accepted) {
      asMutableBytes(record.accepted.attestation)[0] ^= 0xff;
    }
    return record;
  }
}

class FailAcceptedOnceGameStore extends MemoryGameStore {
  failed = false;

  async save(key, value) {
    if (!this.failed && value?.accepted) {
      this.failed = true;
      throw new Error("simulated accepted-package crash");
    }
    await super.save(key, value);
  }
}

function asMutableBytes(value) {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

class RelayHub {
  constructor() {
    this.queue = [];
    this.cursor = 0;
    this.flows = [];
  }

  sender(role) {
    return async (frame) => {
      const existing = this.queue.find((value) => value.messageId === frame.messageId);
      if (existing) {
        assert.equal(existing.payload, frame.payload);
        return;
      }
      this.cursor += 1;
      this.queue.push({ ...frame, sender: role, cursor: this.cursor });
    };
  }

  async drain() {
    let index = 0;
    while (index < this.queue.length) {
      const message = this.queue[index++];
      for (const flow of this.flows) await flow.acceptRelayMessage(message);
    }
  }
}

const storeA = new TamperableMemoryGameStore();
const storeB = new MemoryGameStore();
const hub = new RelayHub();
const chain = {
  async originFact() {
    return {
      profileId: Uint8Array.from(Buffer.from(NETWORK_ID, "hex")),
      outpoint: { displayTxid: Uint8Array.from(Buffer.from("aa".repeat(32), "hex")), vout: 0 },
      valueSat: 53_500n,
      scriptPubkey: new Uint8Array(34),
      creatingDisplayTxid: Uint8Array.from(Buffer.from("aa".repeat(32), "hex")),
      creatingTransaction: new Uint8Array([1]),
      confirmedIn: { height: 100, displayHash: new Uint8Array(32).fill(1) },
      observedTip: { height: 100, displayHash: new Uint8Array(32).fill(1) },
    };
  },
};

function context(transportRole, localKey, peerKey, secretMarker, updates) {
  return {
    deploymentConfig: DEPLOYMENT,
    roomId: "09".repeat(32),
    sessionNonceHex: "08".repeat(32),
    transportRole,
    localSecretKeyHex: secretMarker.repeat(64),
    localXOnlyKeyHex: localKey,
    peerXOnlyKeyHex: peerKey,
    origin: {
      displayTxid: "aa".repeat(32),
      vout: 0,
      valueSat: 53_500,
      scriptPubkeyHex: "00".repeat(34),
      witnessScriptHex: "00".repeat(104),
    },
    chain,
    sendExchange: hub.sender(transportRole),
    onUpdate: (view) => updates.push(view),
  };
}

const updatesA = [];
const updatesB = [];
const workersA = [];
const workersB = [];
// Deliberately reverse transport and canonical roles.
const flowA = new BrowserGameFlow(context("bob", SMALL_KEY, LARGE_KEY, "1", updatesA), {
  store: storeA,
  workerFactory: workerFactory(0, workersA),
  gameWasm: new Uint8Array(8),
  dealWasm: new Uint8Array(8),
});
const flowB = new BrowserGameFlow(context("alice", LARGE_KEY, SMALL_KEY, "2", updatesB), {
  store: storeB,
  workerFactory: workerFactory(1, workersB),
  gameWasm: new Uint8Array(8),
  dealWasm: new Uint8Array(8),
});
hub.flows.push(flowA, flowB);

await Promise.all([flowA.start(), flowB.start()]);
await hub.drain();
assert.equal(flowA.view().canonicalRole, 0);
assert.equal(flowB.view().canonicalRole, 1);
assert.deepEqual(flowA.view().tableBalances, {
  aliceStackSat: 20_000,
  bobStackSat: 20_000,
  potSat: 0,
});
assert.equal(flowA.view().dealEnvelopes, 16);
assert.equal(flowB.view().dealEnvelopes, 16);
assert.equal(flowA.view().privateDealComplete, true);
assert.equal(flowB.view().privateDealComplete, true);
assert.equal(hub.queue.length, 18);

const durableDealRecordA = [...storeA.records.values()][0];
assert.equal(durableDealRecordA.outbox.length, 0);
assert.ok(durableDealRecordA.frames.every((frame) =>
  frame.processed && frame.disposition === "game" &&
  typeof frame.payload === "undefined" && /^[0-9a-f]{64}$/.test(frame.payloadSha256)
));

assert.deepEqual(compactProcessedGameFrame({
  cursor: 1,
  messageId: "ab".repeat(32),
  sender: "alice",
}, {
  payloadSha256: "cd".repeat(32),
  disposition: "verified-receipt",
  chainCheckpointReceipt: "ef".repeat(32),
  gameRevision: 2,
}), {
  cursor: 1,
  messageId: "ab".repeat(32),
  sender: "alice",
  payloadSha256: "cd".repeat(32),
  disposition: "verified-receipt",
  processed: true,
  gameRevision: 2,
  chainCheckpointReceipt: "ef".repeat(32),
});
assert.throws(() => compactProcessedGameFrame({
  cursor: 1,
  messageId: "ab".repeat(32),
  sender: "alice",
}, {
  payloadSha256: "cd".repeat(32),
  disposition: "verified-receipt",
  dealRecoveryRevision: 1,
  gameRevision: 2,
}), /durable bindings/);

// An exact relay replay is idempotent at the orchestration boundary.
await flowA.acceptRelayMessage(hub.queue[0]);
assert.equal(flowA.view().dealEnvelopes, 16);

const dealWorkerA = workersA.find((worker) => worker.kind === "deal");
assert.ok(dealWorkerA);
assert.equal(dealWorkerA.deal.duplicateEnvelopes, 8);

// Accepted durability closes DEAL immediately. A later corrupt read-back is
// still rejected before any bytes can reach CHAIN.
storeA.tamperAcceptedRead = true;
await assert.rejects(
  () => flowA.handoffAcceptedDeal(async () => true),
  /durable accepted-DEAL recovery record failed its byte check/,
);
assert.equal(dealWorkerA.terminated, true);
storeA.tamperAcceptedRead = false;

// Once read-back succeeds, DEAL is terminated before CHAIN allocation begins.
// A failed CHAIN consumer can retry entirely from the sealed durable package.
await assert.rejects(
  () => flowA.handoffAcceptedDeal(async () => {
    assert.equal(dealWorkerA.terminated, true);
    throw new Error("simulated CHAIN initialization failure");
  }),
  /simulated CHAIN initialization failure/,
);
assert.equal(dealWorkerA.terminated, true);

await flowA.cancel();
await assert.rejects(() => flowA.acceptRelayMessage(hub.queue[0]), /cancelled/);

const recoveredWorkersA = [];
const recoveredFlowA = new BrowserGameFlow(
  context("bob", SMALL_KEY, LARGE_KEY, "1", updatesA),
  {
    store: storeA,
    workerFactory: workerFactory(0, recoveredWorkersA),
    gameWasm: new Uint8Array(8),
    dealWasm: new Uint8Array(8),
  },
);
await recoveredFlowA.start();
const recoveredDealWorkerA = recoveredWorkersA.find((worker) => worker.kind === "deal");
assert.equal(recoveredDealWorkerA, undefined);

let handedOff = false;
await recoveredFlowA.handoffAcceptedDeal(async (recovery) => {
  assert.equal(recovery.deal.byteLength, 774);
  assert.equal(recovery.storageKey.byteLength, 32);
  assert.equal(recoveredWorkersA.filter((worker) => worker.kind === "deal").length, 0);
  handedOff = true;
  return { accepted: true };
});
assert.equal(handedOff, true);

await recoveredFlowA.cancel();
await flowB.cancel();

// A crash before the accepted package commits must leave DEAL alive. Replaying
// the same relay bytes retries the atomic commit, verifies its read-back, and
// only then retires the disposable Worker.
const dealCrashHub = new RelayHub();
const dealCrashStoreA = new FailAcceptedOnceGameStore();
const dealCrashStoreB = new MemoryGameStore();
const dealCrashWorkersA = [];
const dealCrashWorkersB = [];
const dealCrashFlowA = new BrowserGameFlow(
  {
    ...context("bob", SMALL_KEY, LARGE_KEY, "1", []),
    sendExchange: dealCrashHub.sender("bob"),
  },
  {
    store: dealCrashStoreA,
    workerFactory: workerFactory(0, dealCrashWorkersA),
    gameWasm: new Uint8Array(8),
    dealWasm: new Uint8Array(8),
  },
);
const dealCrashFlowB = new BrowserGameFlow(
  {
    ...context("alice", LARGE_KEY, SMALL_KEY, "2", []),
    sendExchange: dealCrashHub.sender("alice"),
  },
  {
    store: dealCrashStoreB,
    workerFactory: workerFactory(1, dealCrashWorkersB),
    gameWasm: new Uint8Array(8),
    dealWasm: new Uint8Array(8),
  },
);
dealCrashHub.flows.push(dealCrashFlowA, dealCrashFlowB);
await Promise.all([dealCrashFlowA.start(), dealCrashFlowB.start()]);
await assert.rejects(() => dealCrashHub.drain(), /simulated accepted-package crash/);
const disposableAfterCrash = dealCrashWorkersA.find((worker) => worker.kind === "deal");
assert.equal(disposableAfterCrash.terminated, false);
assert.equal([...dealCrashStoreA.records.values()][0].accepted, undefined);
await dealCrashHub.drain();
assert.ok([...dealCrashStoreA.records.values()][0].accepted?.attestation);
assert.equal(disposableAfterCrash.terminated, true);
await Promise.all([dealCrashFlowA.cancel(), dealCrashFlowB.cancel()]);

assert.ok(updatesA.some((value) => value.stage === "preparing-proof"));
assert.ok(updatesB.some((value) => value.stage === "private-deal-complete"));
assert.ok(hub.queue.every((value) => value.kind === GAME_EXCHANGE_KIND));

process.stdout.write("browser game flow mocked two-peer orchestration ok\n");
