import {
  ChainExchangePackage,
  ChainRuntime,
  ChainSetupKind,
  bytesToHex,
  chainRelayMessageIdMaterial,
  decodeAcceptedSessionEvent,
  decodeChainExchange,
  transferBytes,
} from "./chain-runtime.js?v=4";
import { serializeAsync } from "../worker/serial-dispatch.js";
import {
  generateLamportBatches,
  generatePreauthorizationBatches,
  preauthorizationWorkerCount,
  verifyPreauthorizationBatches,
} from "./preauthorization-verifier-pool.js";
import {
  shouldDeferUntilGraph,
  shouldGenerateLocalLamport,
} from "./setup-schedule.js?v=4";

const DATABASE = "bp52-chain-secret-v1";
const STORE = "checkpoints";
const CHECKPOINT_MAGIC = new TextEncoder().encode("BP52CS04");
const CHECKPOINT_VERSION = 4;

let runtime;
let chainWasmModule;
let checkpointKey;
let checkpointRecord;
let transportRole;
let chainExchangeKind;
let relayRoomId;
let localIdentity;
const readyRoles = new Set();

function respond(id, payload, transfer = []) {
  self.postMessage({ id, ok: true, ...payload }, transfer);
}

function fail(id, error, operation) {
  console.error("[BP52 CHAIN Worker]", {
    operation,
    error: error instanceof Error ? error.message : String(error),
  });
  self.postMessage({
    id,
    ok: false,
    error: error instanceof Error ? error.message : String(error),
  });
}

function reportBatchTiming(operation, startedAt, workerCount, itemCount) {
  console.debug("[BP52 CHAIN] batch complete", {
    operation,
    elapsedMs: Math.round(performance.now() - startedAt),
    workerCount,
    itemCount,
  });
}

function openDatabase() {
  if (!self.indexedDB) throw new Error("IndexedDB is required for CHAIN secret durability");
  return new Promise((resolve, reject) => {
    const request = self.indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE)) request.result.createObjectStore(STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("failed to open CHAIN checkpoint store"));
  });
}

async function checkpointTransaction(mode, operation) {
  const database = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE, mode);
      const request = operation(transaction.objectStore(STORE));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error ?? new Error("CHAIN checkpoint operation failed"));
      transaction.onabort = () => reject(transaction.error ?? new Error("CHAIN checkpoint transaction aborted"));
    });
  } finally {
    database.close();
  }
}

function checkpointCounter(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  if (bytes.byteLength < 18) throw new Error("CHAIN checkpoint is truncated");
  if (!CHECKPOINT_MAGIC.every((byte, index) => bytes[index] === byte)) {
    throw new Error("CHAIN checkpoint has the wrong magic");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint16(8, true) !== CHECKPOINT_VERSION) {
    throw new Error("CHAIN checkpoint has an unsupported version");
  }
  const counter = view.getBigUint64(10, true);
  if (counter === 0n) throw new Error("CHAIN checkpoint has a zero counter");
  return counter;
}

function recordedCounter(record) {
  if (!record?.checkpoint) return 0n;
  const header = checkpointCounter(record.checkpoint);
  if (record.counter === undefined || BigInt(record.counter) !== header) {
    throw new Error("CHAIN checkpoint anchor differs from its authenticated header");
  }
  return header;
}

async function putCheckpoint(value) {
  const counter = checkpointCounter(value);
  const previous = recordedCounter(checkpointRecord);
  if (counter !== previous + 1n) {
    throw new Error("CHAIN checkpoint counter did not advance exactly once");
  }
  checkpointRecord = {
    ...checkpointRecord,
    checkpoint: value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength),
    counter: counter.toString(10),
  };
  await checkpointTransaction("readwrite", (store) => store.put(checkpointRecord, checkpointKey));
}

async function getCheckpointRecord() {
  return checkpointTransaction("readonly", (store) => store.get(checkpointKey));
}

function equalBytes(left, right) {
  const a = new Uint8Array(left);
  const b = new Uint8Array(right);
  return a.byteLength === b.byteLength && a.every((value, index) => value === b[index]);
}

async function persistAndReadBack() {
  const checkpoint = runtime.sealCheckpoint();
  let readback;
  try {
    await putCheckpoint(checkpoint);
    const stored = await getCheckpointRecord();
    readback = stored?.checkpoint;
    if (
      !readback ||
      recordedCounter(stored) !== checkpointCounter(checkpoint) ||
      !equalBytes(checkpoint, readback)
    ) {
      throw new Error("durable CHAIN checkpoint readback differs from the sealed state");
    }
    const receipt = runtime.verifyCheckpoint(readback);
    return bytesToHex(receipt);
  } finally {
    checkpoint.fill(0);
    if (readback) new Uint8Array(readback).fill(0);
  }
}

async function durable(operation) {
  const value = operation();
  const checkpointReceipt = await persistAndReadBack();
  return { value, checkpointReceipt };
}

function configuredCheckpointKey(config) {
  if (config?.localRole !== 0 && config?.localRole !== 1) {
    throw new Error("CHAIN config.localRole must be canonical role 0 or 1");
  }
  const displayTxid = typeof config.origin?.displayTxid === "string"
    ? config.origin.displayTxid
    : bytesToHex(config.origin?.displayTxid);
  return [
    bytesToHex(config.deploymentDigest),
    bytesToHex(config.configHash),
    bytesToHex(config.relayRoomId),
    bytesToHex(config.sessionNonce),
    displayTxid,
    String(config.origin?.vout),
    String(config.localRole),
  ].join("/");
}

function randomSecret() {
  if (!self.crypto || typeof self.crypto.getRandomValues !== "function") {
    throw new Error("WebCrypto is required for CHAIN secret generation and randomized verification");
  }
  const value = new Uint8Array(32);
  self.crypto.getRandomValues(value);
  return value;
}

async function wrapSnapshotKey(rawKey, wrappingKey) {
  const key = await self.crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  return self.crypto.subtle.wrapKey("raw", key, wrappingKey, "AES-KW");
}

async function unwrapSnapshotKey(record) {
  const key = await self.crypto.subtle.unwrapKey(
    "raw",
    record.wrappedSnapshotKey,
    record.wrappingKey,
    "AES-KW",
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  return new Uint8Array(await self.crypto.subtle.exportKey("raw", key));
}

async function provisionSnapshotKey(configured, supplied) {
  checkpointKey = configuredCheckpointKey(configured);
  checkpointRecord = await checkpointTransaction("readonly", (store) => store.get(checkpointKey));
  if (checkpointRecord) {
    const restored = await unwrapSnapshotKey(checkpointRecord);
    if (supplied && !equalBytes(restored, supplied)) {
      restored.fill(0);
      throw new Error("supplied CHAIN snapshot key conflicts with durable key custody");
    }
    return restored;
  }
  const raw = supplied ? Uint8Array.from(supplied) : randomSecret();
  const wrappingKey = await self.crypto.subtle.generateKey(
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
  const wrappedSnapshotKey = await wrapSnapshotKey(raw, wrappingKey);
  checkpointRecord = { wrappingKey, wrappedSnapshotKey, checkpoint: null, counter: "0" };
  await checkpointTransaction("readwrite", (store) => store.add(checkpointRecord, checkpointKey));
  return raw;
}

function transferable(value) {
  return value instanceof Uint8Array ? transferBytes(value) : value;
}

function senderRole(message) {
  if (message?.sender !== "alice" && message?.sender !== "bob") {
    throw new Error("CHAIN relay message has an invalid sender");
  }
  const local = message.sender === transportRole;
  return local ? runtime.localRole() : 1 - runtime.localRole();
}

async function exchangeWithMessageId(exchange) {
  if (!relayRoomId || !localIdentity) throw new Error("CHAIN relay identity is unavailable");
  const material = chainRelayMessageIdMaterial(exchange.payload, relayRoomId, localIdentity);
  const digest = await self.crypto.subtle.digest("SHA-256", material);
  return { ...exchange, messageId: bytesToHex(new Uint8Array(digest)) };
}

async function acceptRelayMessage(message) {
  if (!message || message.kind !== chainExchangeKind || typeof message.payload !== "string") {
    throw new Error("relay message does not use the configured CHAIN exchange kind");
  }
  const decoded = decodeChainExchange(message.payload);
  const context = runtime.publicContext();
  const graphRootMissing = !context.graphRoot.some((byte) => byte !== 0);
  const deferredForGraph = shouldDeferUntilGraph({
    packageId: decoded.package,
    hasGraph: context.hasGraph && !graphRootMissing,
  });
  if (decoded.package !== ChainExchangePackage.LAMPORT_PUBLIC_BUNDLE && deferredForGraph) {
    console.warn("[BP52 CHAIN] graph-bound replay", {
      package: decoded.package,
      deferredForGraph,
      hasGraph: context.hasGraph,
      graphRootBytes: context.graphRoot.byteLength,
    });
  }
  decodeChainExchange(message.payload, deferredForGraph
    ? { ...context, graphRoot: decoded.graphRoot }
    : context);
  if (decoded.role !== senderRole(message)) {
    throw new Error("CHAIN exchange role does not match authenticated relay sender");
  }
  if (deferredForGraph) {
    return {
      accepted: false,
      deferred: true,
      package: decoded.package,
      role: decoded.role,
      readyForActivation: false,
      activationTransaction: null,
    };
  }
  if (decoded.package === ChainExchangePackage.ACTIVATION_SIGNATURE && readyRoles.size !== 2) {
    return {
      accepted: false,
      deferred: true,
      package: decoded.package,
      role: decoded.role,
      readyForActivation: false,
      activationTransaction: null,
    };
  }
  let value;
  if (
    decoded.package === ChainExchangePackage.PREAUTHORIZATION_OPENING &&
    decoded.role !== runtime.localRole()
  ) {
    const workerCount = preauthorizationWorkerCount(self.navigator?.hardwareConcurrency);
    const plan = runtime.preparePeerPreauthorizationVerification(
      decoded.role,
      decoded.artifact,
      workerCount,
    );
    if (plan.complete) {
      decoded.setup = decodeAcceptedSessionEvent(plan.result);
    } else {
      const startedAt = performance.now();
      await verifyPreauthorizationBatches({
        wasmModule: chainWasmModule,
        batches: plan.batches,
        expectedTotal: plan.total,
      });
      reportBatchTiming("verify peer preauthorizations", startedAt, plan.batches.length, plan.total);
      decoded.setup = runtime.completePeerPreauthorizationVerification();
    }
    value = decoded;
  } else {
    value = runtime.acceptExchange(message.payload);
  }
  const checkpointReceipt = await persistAndReadBack();
  const persisted = { value, checkpointReceipt };
  if (decoded.package === ChainExchangePackage.INVENTORY_READY) readyRoles.add(decoded.role);
  const activation = decoded.package === ChainExchangePackage.ACTIVATION_SIGNATURE
    ? runtime.assembleActivation()
    : null;
  return {
    accepted: true,
    deferred: false,
    package: decoded.package,
    role: decoded.role,
    readyForActivation: readyRoles.size === 2,
    activationTransaction: activation,
    setup: persisted.value.setup ?? null,
    checkpointReceipt: persisted.checkpointReceipt,
  };
}

async function handleMessage(event) {
  const { id, type } = event.data ?? {};
  try {
    if (type === "init") {
      if (runtime) throw new Error("CHAIN Worker is already initialized");
      const request = event.data.request;
      try {
        transportRole = request?.config?.transportRole;
        if (transportRole !== "alice" && transportRole !== "bob") {
          throw new Error("CHAIN config.transportRole must be alice or bob");
        }
        chainExchangeKind = request?.config?.chainExchangeKind;
        if (
          typeof chainExchangeKind !== "string" ||
          !/^[a-z0-9][a-z0-9._-]{0,31}$/.test(chainExchangeKind)
        ) {
          throw new Error("CHAIN config.chainExchangeKind is malformed");
        }
        relayRoomId = Uint8Array.from(request.config.relayRoomId);
        localIdentity = Uint8Array.from(request.config.identities[request.config.localRole]);
        const suppliedSnapshotKey = request.snapshotKey;
        request.snapshotKey = await provisionSnapshotKey(request.config, suppliedSnapshotKey);
        if (!request.entropy) request.entropy = randomSecret();
        suppliedSnapshotKey?.fill?.(0);
        chainWasmModule = await WebAssembly.compile(event.data.wasm);
        runtime = await ChainRuntime.create(chainWasmModule);
        const acknowledgement = runtime.initialize(request);
        if (acknowledgement.localRole !== request.config.localRole) {
          throw new Error("CHAIN config.localRole differs from the identity secret's canonical role");
        }
        let recovered = false;
        let restoredCounter = 0n;
        if (checkpointRecord?.checkpoint) {
          const recoveryCheckpoint = Uint8Array.from(new Uint8Array(checkpointRecord.checkpoint));
          try {
            const restored = runtime.restoreCheckpoint(recoveryCheckpoint);
            const anchored = recordedCounter(checkpointRecord);
            if (restored.counter !== anchored) {
              throw new Error("restored CHAIN counter differs from the durable anchor");
            }
            restoredCounter = restored.counter;
            recovered = true;
          } finally {
            recoveryCheckpoint.fill(0);
          }
        }
        const status = runtime.runtimeStatus();
        readyRoles.clear();
        for (const role of status.readyRoles) readyRoles.add(role);
        const checkpointReceipt = await persistAndReadBack();
        const inventoryAttestation = status.inventoryAttestation
          ? transferable(status.inventoryAttestation)
          : null;
        status.inventoryAttestation = inventoryAttestation;
        respond(id, {
          ...acknowledgement,
          phase: status.phase,
          recovered,
          restoredCounter: restoredCounter.toString(10),
          runtimeStatus: status,
          checkpointReceipt,
        }, inventoryAttestation ? [inventoryAttestation] : []);
      } finally {
        request?.identitySecret?.fill?.(0);
        request?.entropy?.fill?.(0);
        request?.snapshotKey?.fill?.(0);
        request?.deal?.storageKey?.fill?.(0);
      }
      return;
    }
    if (!runtime) throw new Error("CHAIN Worker is not initialized");
    switch (type) {
      case "sign-descriptor": {
        const result = await durable(() => runtime.signDescriptor(event.data.descriptor));
        const signature = transferable(result.value);
        respond(id, { signature, checkpointReceipt: result.checkpointReceipt }, [signature]);
        break;
      }
      case "accept-session-event": {
        const value = runtime.acceptSessionEvent(
          event.data.senderRole,
          event.data.event,
        );
        if (shouldGenerateLocalLamport({
          ...value,
          hasDescriptor: runtime.publicContext().hasDescriptor,
        })) {
          const workerCount = preauthorizationWorkerCount(self.navigator?.hardwareConcurrency);
          const plan = runtime.prepareLocalLamportGeneration(workerCount);
          if (plan.complete) {
            value.localLamportBundle = plan.artifact;
          } else {
            const startedAt = performance.now();
            const results = await generateLamportBatches({
              wasmModule: chainWasmModule,
              batches: plan.batches,
            });
            try {
              value.localLamportBundle = runtime.completeLocalLamportGeneration(results);
              value.phase = runtime.phase();
              reportBatchTiming("generate Lamport keys", startedAt, plan.batches.length, plan.total);
            } finally {
              for (const result of results) result.fill(0);
            }
          }
        }
        const checkpointReceipt = await persistAndReadBack();
        const localLamportBundle = transferable(value.localLamportBundle);
        const verificationReceipt = transferable(value.verificationReceipt);
        respond(id, {
          setupKind: value.setupKind,
          applicable: value.applicable,
          duplicate: value.duplicate,
          phase: value.phase,
          localLamportBundle,
          verificationReceipt,
          checkpointReceipt,
        }, [localLamportBundle, verificationReceipt]);
        break;
      }
      case "make-root-commitment": {
        const result = await durable(() => runtime.makeRootCommitmentExchange());
        respond(id, { exchange: await exchangeWithMessageId(result.value), checkpointReceipt: result.checkpointReceipt });
        break;
      }
      case "open-root": {
        const result = await durable(() => runtime.makeRootOpeningExchange());
        respond(id, { exchange: await exchangeWithMessageId(result.value), checkpointReceipt: result.checkpointReceipt });
        break;
      }
      case "make-preauthorization-commitment": {
        const workerCount = preauthorizationWorkerCount(self.navigator?.hardwareConcurrency);
        const plan = runtime.prepareLocalPreauthorizationGeneration(workerCount);
        let artifact;
        if (plan.complete) {
          artifact = plan.artifact;
        } else {
          const startedAt = performance.now();
          const results = await generatePreauthorizationBatches({
            wasmModule: chainWasmModule,
            batches: plan.batches,
          });
          try {
            artifact = runtime.completeLocalPreauthorizationGeneration(results);
            reportBatchTiming("generate preauthorizations", startedAt, plan.batches.length, 52_000);
          } finally {
            for (const result of results) result.fill(0);
          }
        }
        const exchange = runtime.preauthorizationCommitmentExchange(artifact);
        const checkpointReceipt = await persistAndReadBack();
        respond(id, {
          exchange: await exchangeWithMessageId(exchange),
          checkpointReceipt,
        });
        break;
      }
      case "open-preauthorizations": {
        const result = await durable(() => runtime.makePreauthorizationOpeningExchange());
        respond(id, { exchange: await exchangeWithMessageId(result.value), checkpointReceipt: result.checkpointReceipt });
        break;
      }
      case "make-lamport-bundle": {
        const result = await durable(() => runtime.makeLamportBundleExchange(event.data.bundle));
        respond(id, { exchange: await exchangeWithMessageId(result.value), checkpointReceipt: result.checkpointReceipt });
        break;
      }
      case "attest-inventory": {
        const result = await durable(() => runtime.attestInventory());
        const signature = transferable(result.value);
        const graphReceipt = transferable(runtime.graphPreparedReceipt());
        respond(id, {
          role: runtime.localRole(),
          signature,
          graphReceipt,
          checkpointReceipt: result.checkpointReceipt,
        }, [signature, graphReceipt]);
        break;
      }
      case "make-inventory-ready": {
        const result = await durable(() => runtime.makeInventoryReadyExchange());
        readyRoles.add(runtime.localRole());
        respond(id, { exchange: await exchangeWithMessageId(result.value), checkpointReceipt: result.checkpointReceipt });
        break;
      }
      case "accept-relay-message": {
        const result = await acceptRelayMessage(event.data.message);
        if (result.activationTransaction) {
          const activationTransaction = transferable(result.activationTransaction);
          result.activationTransaction = activationTransaction;
          respond(id, result, [activationTransaction]);
        } else {
          respond(id, result);
        }
        break;
      }
      case "sign-activation": {
        if (readyRoles.size !== 2) {
          throw new Error("activation signing waits for both readiness handshakes");
        }
        const result = await durable(() => runtime.signActivation(event.data.unsignedTransaction));
        respond(id, { exchange: await exchangeWithMessageId(result.value), checkpointReceipt: result.checkpointReceipt });
        break;
      }
      case "confirm-activation": {
        const result = await durable(() => runtime.confirmActivation(event.data));
        const stateReceipt = transferable(runtime.confirmedStateReceipt());
        respond(id, {
          cards: result.value,
          stateReceipt,
          checkpointReceipt: result.checkpointReceipt,
        }, [stateReceipt]);
        break;
      }
      case "observe-tip": {
        const result = await durable(() => runtime.observeTip(event.data.height));
        respond(id, { checkpointReceipt: result.checkpointReceipt });
        break;
      }
      case "build-action":
      case "build-edge":
      case "build-reveal":
      case "build-alice-showdown":
      case "build-bob-payout":
      case "build-timeout": {
        const operations = {
          "build-action": () => runtime.buildAction(event.data.action),
          "build-edge": () => runtime.buildEdge(event.data),
          "build-reveal": () => runtime.buildReveal(),
          "build-alice-showdown": () => runtime.buildAliceShowdown(event.data),
          "build-bob-payout": () => runtime.buildBobPayout(event.data),
          "build-timeout": () => runtime.buildTimeout(),
        };
        const result = await durable(operations[type]);
        const witness = transferable(result.value);
        const runtimeReceipt = transferable(runtime.runtimeAuthorizationReceipt());
        respond(id, {
          witness,
          runtimeReceipt,
          checkpointReceipt: result.checkpointReceipt,
        }, [witness, runtimeReceipt]);
        break;
      }
      case "confirm-child": {
        const result = await durable(() => runtime.confirmChild(event.data));
        const signature = transferable(result.value);
        const stateReceipt = transferable(runtime.confirmedStateReceipt());
        respond(id, {
          signature,
          stateReceipt,
          cards: runtime.projectCards(),
          checkpointReceipt: result.checkpointReceipt,
        }, [signature, stateReceipt]);
        break;
      }
      case "project-cards":
        respond(id, { cards: runtime.projectCards() });
        break;
      case "status":
        respond(id, {
          ...runtime.runtimeStatus(),
          readyForActivation: readyRoles.size === 2,
          cards: runtime.phase() >= 4 ? runtime.projectCards() : null,
        });
        break;
      case "clear":
        runtime.clear();
        runtime = undefined;
        chainWasmModule = undefined;
        chainExchangeKind = undefined;
        relayRoomId?.fill(0);
        localIdentity?.fill(0);
        relayRoomId = undefined;
        localIdentity = undefined;
        respond(id, {});
        self.close();
        break;
      default:
        throw new Error(`unknown CHAIN Worker request: ${String(type)}`);
    }
  } catch (error) {
    fail(id, error, type);
  }
}

self.addEventListener("message", serializeAsync(handleMessage));
