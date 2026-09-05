const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const INIT_MAGIC = textEncoder.encode("BP52CH05");
const CONTEXT_MAGIC = textEncoder.encode("BP52CT01");
const CARD_MAGIC = textEncoder.encode("BP52CP01");
const EXCHANGE_MAGIC = textEncoder.encode("BP52CX01");
const RUNTIME_STATUS_MAGIC = textEncoder.encode("BP52RS01");
const DISPUTE_PACKAGE_MAGIC = textEncoder.encode("BP52DP01");
const SESSION_EVENT_RESULT_MAGIC = textEncoder.encode("BP52SE02");
const PREAUTHORIZATION_PLAN_MAGIC = textEncoder.encode("BP52PP01");
const PREAUTHORIZATION_GENERATION_PLAN_MAGIC = textEncoder.encode("BP52PG01");
const PREAUTHORIZATION_GENERATION_RESULT_MAGIC = textEncoder.encode("BP52GR01");
const LAMPORT_GENERATION_PLAN_MAGIC = textEncoder.encode("BP52LG01");
const LAMPORT_GENERATION_RESULT_MAGIC = textEncoder.encode("BP52LR01");
const RELAY_MESSAGE_ID_TAG = textEncoder.encode("BP52/browser-chain-relay/v1");
const MAX_U32 = 0xffff_ffff;
const MAX_INPUT_BYTES = 32 * 1024 * 1024;
const MAX_ARTIFACT_BYTES = 12 * 1024 * 1024;
const ORIGIN_SCRIPT_BYTES = 104;
const EXCHANGE_HEADER_BYTES = 210;

/** Canonical package selectors inside the deployment-configured CHAIN relay kind. */
export const ChainExchangePackage = Object.freeze({
  INVENTORY_READY: 1,
  ACTIVATION_SIGNATURE: 2,
  LAMPORT_PUBLIC_BUNDLE: 3,
  GRAPH_ROOT_COMMITMENT: 4,
  GRAPH_ROOT_OPENING: 5,
  PREAUTHORIZATION_COMMITMENT: 6,
  PREAUTHORIZATION_OPENING: 7,
  ACTION_SIGNATURE_REQUEST: 8,
  ACTION_SIGNATURE_RESPONSE: 9,
  OFFCHAIN_TRANSITION: 10,
});

/** Secret Worker phase codes. */
export const ChainPhase = Object.freeze({
  EMPTY: 0,
  ACCEPTED_DEAL: 1,
  DESCRIPTOR_CANDIDATE: 2,
  LAMPORT_READY: 3,
  GRAPH_READY: 4,
  ROOT_AGREED: 5,
  PREAUTHORIZATIONS_READY: 6,
  INVENTORY_VERIFIED: 7,
  ACTIVE: 8,
  SETTLED: 9,
  HALTED: 10,
});

/** Rust-decoded setup-event selectors returned by `acceptSessionEvent`. */
export const ChainSetupKind = Object.freeze({
  DESCRIPTOR_SIGNATURE: 0,
  LAMPORT_PUBLIC_BUNDLE: 1,
  GRAPH_ROOT_COMMITMENT: 2,
  GRAPH_ROOT_OPENING: 3,
  PREAUTHORIZATION_COMMITMENT: 4,
  PREAUTHORIZATION_OPENING: 5,
  NOT_APPLICABLE: 0xff,
});

function asBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new Error(`${label} must be bytes`);
}

function exactBytes(value, length, label) {
  const result = typeof value === "string" ? hexToBytes(value, length, label) : asBytes(value, label);
  if (result.byteLength !== length) {
    throw new Error(`${label} must contain exactly ${length} bytes`);
  }
  return result;
}

function hexToBytes(value, length, label) {
  if (
    typeof value !== "string" ||
    !new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value)
  ) {
    throw new Error(`${label} must be ${length} canonical lowercase hex bytes`);
  }
  return Uint8Array.from(value.match(/../g), (pair) => Number.parseInt(pair, 16));
}

export function bytesToHex(value) {
  return Array.from(asBytes(value, "hex value"), (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

function sameBytes(left, right) {
  const a = asBytes(left, "left bytes");
  const b = asBytes(right, "right bytes");
  return a.byteLength === b.byteLength && a.every((value, index) => value === b[index]);
}

function allZero(value) {
  return asBytes(value, "zero-checked bytes").every((byte) => byte === 0);
}

function concatBytes(...values) {
  const arrays = values.map((value) => asBytes(value, "concatenated bytes"));
  const result = new Uint8Array(arrays.reduce((total, value) => total + value.byteLength, 0));
  let offset = 0;
  for (const value of arrays) {
    result.set(value, offset);
    offset += value.byteLength;
  }
  return result;
}

function wasmLastError(exports) {
  const length = exports.bp52_chain_last_error_len();
  const pointer = exports.bp52_chain_last_error_ptr();
  if (length === 0 || pointer === 0) return "unknown CHAIN Wasm error";
  return textDecoder.decode(new Uint8Array(exports.memory.buffer, pointer, length));
}

function checkWasm(exports, code) {
  if (code !== 0) throw new Error(`BP52 CHAIN Wasm error ${code}: ${wasmLastError(exports)}`);
}

function invokeWasm(instance, exportName, input = new Uint8Array()) {
  const exports = instance.exports;
  const operation = exports[exportName];
  if (typeof operation !== "function") throw new Error(`CHAIN Wasm export is missing: ${exportName}`);
  const bytes = asBytes(input, `${exportName} input`);
  if (bytes.byteLength > MAX_INPUT_BYTES) throw new Error("CHAIN Wasm input exceeds its fixed bound");
  checkWasm(exports, exports.bp52_chain_begin_input(bytes.byteLength));
  const inputPointer = exports.bp52_chain_input_ptr();
  if (bytes.byteLength > 0 && inputPointer === 0) {
    throw new Error("CHAIN Wasm returned a null input pointer");
  }
  new Uint8Array(exports.memory.buffer, inputPointer, bytes.byteLength).set(bytes);
  checkWasm(exports, operation());
  const length = exports.bp52_chain_output_len();
  const outputPointer = exports.bp52_chain_output_ptr();
  if (length > 0 && outputPointer === 0) throw new Error("CHAIN Wasm returned a null output pointer");
  const output = Uint8Array.from(new Uint8Array(exports.memory.buffer, outputPointer, length));
  exports.bp52_chain_clear_output();
  return output;
}

function u32(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_U32) {
    throw new Error(`${label} must be a u32 integer`);
  }
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, value, true);
  return result;
}

function u8(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xff) {
    throw new Error(`${label} must be a u8 integer`);
  }
  return Uint8Array.of(value);
}

function vector(value, maximum, label) {
  const bytes = asBytes(value, label);
  if (bytes.byteLength > maximum || bytes.byteLength > MAX_U32) {
    throw new Error(`${label} exceeds its fixed bound`);
  }
  return concatBytes(u32(bytes.byteLength, `${label} length`), bytes);
}

function canonicalIdentities(values) {
  if (!Array.isArray(values) || values.length !== 2) {
    throw new Error("identities must contain canonical Alice and Bob x-only keys");
  }
  const identities = values.map((value, index) =>
    Uint8Array.from(exactBytes(value, 32, `identities[${index}]`))
  );
  if (sameBytes(identities[0], identities[1])) {
    throw new Error("CHAIN identities must be distinct");
  }
  if (bytesToHex(identities[0]) >= bytesToHex(identities[1])) {
    throw new Error("identities must be in canonical Alice/Bob x-only order");
  }
  return identities;
}

/** Reverse an explorer/display txid exactly once into consensus byte order. */
export function displayTxidToConsensus(value) {
  return Uint8Array.from(exactBytes(value, 32, "origin display txid")).reverse();
}

/** Encode the profile-bound `BP52CH05` initialization frame. */
export function encodeChainInit(request) {
  if (!request || typeof request !== "object") throw new Error("CHAIN init request is required");
  const { config, deal } = request;
  if (!config || !deal) throw new Error("CHAIN config and accepted DEAL package are required");
  const configHash = exactBytes(config.configHash, 32, "configHash");
  const protocolProfile = u8(config.protocolProfile, "protocolProfile");
  if (protocolProfile[0] !== 1 && protocolProfile[0] !== 2) {
    throw new Error("protocolProfile is unsupported");
  }
  const bitcoinNetwork = u8(config.bitcoinNetwork, "bitcoinNetwork");
  if (bitcoinNetwork[0] > 3) throw new Error("bitcoinNetwork is unsupported");
  const networkId = exactBytes(config.networkId, 32, "networkId");
  const relayRoomId = exactBytes(config.relayRoomId, 32, "relayRoomId");
  const sessionNonce = exactBytes(config.sessionNonce, 32, "sessionNonce");
  const identities = canonicalIdentities(config.identities);
  const identitySecret = exactBytes(request.identitySecret, 32, "identitySecret");
  const entropy = exactBytes(request.entropy, 32, "entropy");
  const snapshotKey = exactBytes(request.snapshotKey, 32, "snapshotKey");
  const witnessScript = exactBytes(config.origin?.witnessScript, ORIGIN_SCRIPT_BYTES, "origin witnessScript");
  const consensusTxid = displayTxidToConsensus(config.origin?.displayTxid);
  if (
    config.origin?.consensusTxid !== undefined &&
    !sameBytes(consensusTxid, exactBytes(config.origin.consensusTxid, 32, "origin consensusTxid"))
  ) {
    throw new Error("origin display and consensus txids are not exact reversals");
  }
  const outpoint = concatBytes(consensusTxid, u32(config.origin?.vout, "origin vout"));
  const certificate = asBytes(deal.certificate, "accepted DEAL certificate");
  const attestation = asBytes(deal.attestation, "DEAL verification attestation");
  const sealedPreimages = asBytes(deal.sealedPreimages, "sealed DEAL preimages");
  const storageKey = exactBytes(deal.storageKey, 32, "DEAL storageKey");
  return concatBytes(
    INIT_MAGIC,
    protocolProfile,
    configHash,
    bitcoinNetwork,
    networkId,
    relayRoomId,
    sessionNonce,
    outpoint,
    identities[0],
    identities[1],
    identitySecret,
    entropy,
    witnessScript,
    vector(certificate, 1_024, "accepted DEAL certificate"),
    vector(attestation, 2 * 1024, "DEAL verification attestation"),
    vector(sealedPreimages, 1_024, "sealed DEAL preimages"),
    storageKey,
    snapshotKey,
  );
}

class Reader {
  constructor(value, label) {
    this.bytes = asBytes(value, label);
    this.offset = 0;
    this.label = label;
  }

  take(length) {
    if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.bytes.byteLength) {
      throw new Error(`${this.label} is truncated`);
    }
    const result = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return result;
  }

  u8() {
    return this.take(1)[0];
  }

  u16() {
    const bytes = this.take(2);
    return new DataView(bytes.buffer, bytes.byteOffset, 2).getUint16(0, true);
  }

  u32() {
    const bytes = this.take(4);
    return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
  }

  u64() {
    const bytes = this.take(8);
    return new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, true);
  }

  vector(maximum) {
    const length = this.u32();
    if (length > maximum) throw new Error(`${this.label} vector exceeds its fixed bound`);
    return this.take(length);
  }

  finish() {
    if (this.offset !== this.bytes.byteLength) throw new Error(`${this.label} has trailing bytes`);
  }
}

/** Decode a self-contained, ordered path that can enforce the latest state on Bitcoin. */
export function decodeOffchainDisputePackage(value) {
  const reader = new Reader(value, "off-chain dispute package");
  if (!sameBytes(reader.take(8), DISPUTE_PACKAGE_MAGIC)) {
    throw new Error("off-chain dispute package has the wrong magic");
  }
  const activation = reader.vector(MAX_INPUT_BYTES);
  const count = reader.u16();
  if (count > 1_024) throw new Error("off-chain dispute path exceeds its fixed bound");
  const transactions = [];
  for (let index = 0; index < count; index += 1) {
    transactions.push(reader.vector(MAX_INPUT_BYTES));
  }
  const headNodeId = reader.take(32);
  reader.finish();
  return { activation, transactions, headNodeId };
}

/** Decode the public context exported by the secret Wasm runtime. */
export function decodeChainContext(value) {
  const reader = new Reader(value, "CHAIN public context");
  if (!sameBytes(reader.take(8), CONTEXT_MAGIC)) throw new Error("CHAIN context has the wrong magic");
  const context = {
    networkId: reader.take(32),
    relayRoomId: reader.take(32),
    originOutpoint: reader.take(36),
    dealGameId: reader.take(32),
  };
  const graph = reader.u8();
  context.chainGameId = reader.take(32);
  context.graphRoot = reader.take(32);
  context.role = reader.u8();
  if (context.role > 1 || graph > 1) throw new Error("CHAIN context has a noncanonical tag");
  context.hasGraph = graph === 1;
  if (!context.hasGraph && !allZero(context.graphRoot)) {
    throw new Error("CHAIN context has a graph root before graph compilation");
  }
  context.hasDescriptor = !allZero(context.chainGameId);
  reader.finish();
  return context;
}

function validateExchangePackage(packageId, artifact) {
  if (packageId === ChainExchangePackage.INVENTORY_READY) {
    if (artifact.byteLength !== 64) throw new Error("inventory-ready artifact must be 64 bytes");
  } else if (packageId === ChainExchangePackage.ACTIVATION_SIGNATURE) {
    if (artifact.byteLength < 9 || artifact.byteLength > 73 || artifact.at(-1) !== 1) {
      throw new Error("activation artifact must be bounded DER plus SIGHASH_ALL");
    }
  } else if (
    packageId >= ChainExchangePackage.LAMPORT_PUBLIC_BUNDLE &&
    packageId <= ChainExchangePackage.PREAUTHORIZATION_OPENING
  ) {
    if (artifact.byteLength === 0) throw new Error("CHAIN setup artifact must not be empty");
  } else if (packageId === ChainExchangePackage.ACTION_SIGNATURE_REQUEST) {
    if (artifact.byteLength !== 130) throw new Error("action-signature request must be 130 bytes");
  } else if (packageId === ChainExchangePackage.ACTION_SIGNATURE_RESPONSE) {
    if (artifact.byteLength !== 194) throw new Error("action-signature response must be 194 bytes");
  } else if (packageId === ChainExchangePackage.OFFCHAIN_TRANSITION) {
    if (artifact.byteLength === 0) throw new Error("off-chain transition witness must not be empty");
  } else {
    throw new Error("unknown CHAIN exchange package");
  }
}

/** Encode one strictly context-bound `chain.exchange.v1` binary payload. */
export function encodeChainExchange({ context, package: packageId, role, artifact }) {
  const setupPackage =
    packageId >= ChainExchangePackage.LAMPORT_PUBLIC_BUNDLE &&
    packageId <= ChainExchangePackage.PREAUTHORIZATION_OPENING;
  if (!context?.hasGraph && !(setupPackage && context?.hasDescriptor)) {
    throw new Error("CHAIN exchange requires a verified descriptor");
  }
  if (role !== 0 && role !== 1) throw new Error("CHAIN exchange role must be 0 or 1");
  const artifactBytes = asBytes(artifact, "CHAIN exchange artifact");
  if (artifactBytes.byteLength > MAX_ARTIFACT_BYTES) throw new Error("CHAIN exchange artifact is too large");
  validateExchangePackage(packageId, artifactBytes);
  return concatBytes(
    EXCHANGE_MAGIC,
    Uint8Array.of(packageId, role),
    exactBytes(context.networkId, 32, "networkId"),
    exactBytes(context.relayRoomId, 32, "relayRoomId"),
    exactBytes(context.originOutpoint, 36, "originOutpoint"),
    exactBytes(context.dealGameId, 32, "dealGameId"),
    exactBytes(context.chainGameId, 32, "chainGameId"),
    exactBytes(context.graphRoot, 32, "graphRoot"),
    u32(artifactBytes.byteLength, "artifact length"),
    artifactBytes,
  );
}

/** Decode and optionally compare a `chain.exchange.v1` payload to local context. */
export function decodeChainExchange(value, expectedContext) {
  const bytes = typeof value === "string" ? base64ToBytes(value) : asBytes(value, "CHAIN exchange");
  if (bytes.byteLength < EXCHANGE_HEADER_BYTES) throw new Error("CHAIN exchange is truncated");
  const reader = new Reader(bytes, "CHAIN exchange");
  if (!sameBytes(reader.take(8), EXCHANGE_MAGIC)) throw new Error("CHAIN exchange has the wrong magic");
  const result = {
    package: reader.u8(),
    role: reader.u8(),
    networkId: reader.take(32),
    relayRoomId: reader.take(32),
    originOutpoint: reader.take(36),
    dealGameId: reader.take(32),
    chainGameId: reader.take(32),
    graphRoot: reader.take(32),
    artifact: reader.vector(MAX_ARTIFACT_BYTES),
  };
  reader.finish();
  if (result.role > 1) throw new Error("CHAIN exchange has an unknown role");
  validateExchangePackage(result.package, result.artifact);
  if (expectedContext) {
    for (const field of ["networkId", "relayRoomId", "originOutpoint", "dealGameId", "chainGameId", "graphRoot"]) {
      // Alice intentionally compiles second. Her Lamport bundle can therefore
      // be wrapped after she knows the graph root while Bob still does not.
      // The signed bundle is chain-game-bound; graph binding begins with the
      // following root-commitment package.
      if (field === "graphRoot" && result.package === ChainExchangePackage.LAMPORT_PUBLIC_BUNDLE) {
        continue;
      }
      if (!sameBytes(result[field], expectedContext[field])) {
        const received = bytesToHex(result[field]);
        const local = bytesToHex(expectedContext[field]);
        throw new Error(
          `CHAIN exchange ${field} differs from the local graph (received ${received}, local ${local}, hasGraph ${String(expectedContext.hasGraph)})`,
        );
      }
    }
  }
  return result;
}

function encodeSetupExchangeInput(role, packageId, artifact) {
  const kind = packageId - ChainExchangePackage.ACTIVATION_SIGNATURE;
  if (kind < ChainSetupKind.LAMPORT_PUBLIC_BUNDLE || kind > ChainSetupKind.PREAUTHORIZATION_OPENING) {
    throw new Error("CHAIN package is not a setup exchange");
  }
  return concatBytes(
    EXCHANGE_MAGIC,
    u8(role, "setup sender role"),
    u8(kind, "setup package kind"),
    vector(artifact, MAX_ARTIFACT_BYTES, "setup artifact"),
  );
}

/** Convert canonical bytes to padded base64 for the relay JSON envelope. */
export function bytesToBase64(value) {
  const bytes = asBytes(value, "base64 input");
  let binary = "";
  for (let offset = 0; offset < bytes.byteLength; offset += 32 * 1024) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 32 * 1024));
  }
  return btoa(binary);
}

/** Strict canonical padded-base64 decoder. */
export function base64ToBytes(value) {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0) {
    throw new Error("CHAIN exchange payload is not canonical padded base64");
  }
  let binary;
  try {
    binary = atob(value);
  } catch (_) {
    throw new Error("CHAIN exchange payload is not valid base64");
  }
  if (binary.length > MAX_ARTIFACT_BYTES + EXCHANGE_HEADER_BYTES) {
    throw new Error("CHAIN exchange payload exceeds its fixed bound");
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytesToBase64(bytes) !== value) throw new Error("CHAIN exchange payload is noncanonical base64");
  return bytes;
}

/** Build the public idempotency preimage inside the CHAIN Worker. */
export function chainRelayMessageIdMaterial(payload, relayRoomId, localIdentity) {
  return concatBytes(
    RELAY_MESSAGE_ID_TAG,
    exactBytes(relayRoomId, 32, "relay room id"),
    exactBytes(localIdentity, 32, "local identity"),
    base64ToBytes(payload),
  );
}

function card(value) {
  if (value === 255) return null;
  if (value > 51) throw new Error("verified card projection contains an invalid card id");
  return value;
}

function optionalHand(reader) {
  const present = reader.u8();
  const subset = reader.u8();
  const score = reader.u32();
  if (present === 0) {
    if (subset !== 0 || score !== 0) throw new Error("absent hand projection has nonzero data");
    return null;
  }
  if (present !== 1 || subset > 20 || score > 0x00ff_ffff) {
    throw new Error("verified hand projection is noncanonical");
  }
  return { subset, score };
}

/** Decode the card-only public UI projection; it never contains preimages. */
export function decodeCardProjection(value) {
  const reader = new Reader(value, "verified card projection");
  if (!sameBytes(reader.take(8), CARD_MAGIC)) throw new Error("card projection has the wrong magic");
  const role = reader.u8();
  if (role > 1) throw new Error("card projection has an unknown role");
  const cards = (count) => Array.from(reader.take(count), card);
  const result = {
    role,
    localHole: cards(2),
    board: cards(5),
    aliceHole: cards(2),
    bobHole: cards(2),
    aliceHand: optionalHand(reader),
    bobHand: optionalHand(reader),
  };
  const outcome = reader.u8();
  if (![0, 1, 2, 255].includes(outcome)) throw new Error("card projection has an invalid outcome");
  result.outcome = outcome === 255 ? null : outcome;
  reader.finish();
  return result;
}

/** Decode the public, secret-free recovery/status projection. */
export function decodeRuntimeStatus(value) {
  const reader = new Reader(value, "CHAIN runtime status");
  if (!sameBytes(reader.take(8), RUNTIME_STATUS_MAGIC)) {
    throw new Error("CHAIN runtime status has the wrong magic");
  }
  const phase = reader.u8();
  const localRole = reader.u8();
  const inventoryVerified = reader.u8();
  const attestationPresent = reader.u8();
  let inventoryAttestation = null;
  if (attestationPresent === 1) inventoryAttestation = reader.take(64);
  else if (attestationPresent !== 0) throw new Error("CHAIN runtime status has a noncanonical attestation tag");
  const readyMask = reader.u8();
  const authorizationCached = reader.u8();
  const erasureCached = reader.u8();
  if (
    phase > ChainPhase.HALTED ||
    localRole > 1 ||
    inventoryVerified > 1 ||
    readyMask > 3 ||
    authorizationCached > 1 ||
    erasureCached > 1
  ) {
    throw new Error("CHAIN runtime status contains a noncanonical tag");
  }
  if ((inventoryVerified === 1) !== (inventoryAttestation !== null)) {
    throw new Error("CHAIN runtime status inventory fields disagree");
  }
  reader.finish();
  return {
    phase,
    localRole,
    inventoryVerified: inventoryVerified === 1,
    inventoryAttestation,
    readyRoles: [0, 1].filter((role) => (readyMask & (1 << role)) !== 0),
    authorizationCached: authorizationCached === 1,
    erasureCached: erasureCached === 1,
  };
}

function decodeRestoreReceipt(value) {
  const reader = new Reader(value, "CHAIN checkpoint restore receipt");
  const counter = reader.u64();
  const receipt = reader.take(32);
  reader.finish();
  if (counter === 0n) throw new Error("CHAIN checkpoint restore returned a zero counter");
  return { counter, receipt };
}

function decodePreauthorizationVerificationPlan(value) {
  const reader = new Reader(value, "preauthorization verification plan");
  if (!sameBytes(reader.take(8), PREAUTHORIZATION_PLAN_MAGIC)) {
    throw new Error("preauthorization verification plan has the wrong magic");
  }
  const status = reader.u8();
  if (status === 0) {
    const result = reader.vector(MAX_ARTIFACT_BYTES);
    reader.finish();
    return { complete: true, result, total: 0, batches: [] };
  }
  if (status !== 1) throw new Error("preauthorization verification plan has an unknown status");
  const total = reader.u32();
  const count = reader.u8();
  if (total === 0 || count === 0 || count > 8 || count > total) {
    throw new Error("preauthorization verification plan has invalid bounds");
  }
  const batches = Array.from({ length: count }, () => reader.vector(MAX_ARTIFACT_BYTES));
  reader.finish();
  return { complete: false, result: null, total, batches };
}

function decodePreauthorizationGenerationPlan(value) {
  const bytes = asBytes(value, "preauthorization generation plan");
  try {
    const reader = new Reader(bytes, "preauthorization generation plan");
    if (!sameBytes(reader.take(8), PREAUTHORIZATION_GENERATION_PLAN_MAGIC)) {
      throw new Error("preauthorization generation plan has the wrong magic");
    }
    const status = reader.u8();
    if (status === 0) {
      const artifact = reader.vector(MAX_ARTIFACT_BYTES);
      reader.finish();
      return { complete: true, artifact, total: 0, batches: [] };
    }
    if (status !== 1) throw new Error("preauthorization generation plan has an unknown status");
    const total = reader.u32();
    const count = reader.u8();
    if (total === 0 || count === 0 || count > 8 || count > total) {
      throw new Error("preauthorization generation plan has invalid bounds");
    }
    const batches = Array.from({ length: count }, () => reader.vector(MAX_ARTIFACT_BYTES));
    reader.finish();
    return { complete: false, artifact: null, total, batches };
  } finally {
    bytes.fill(0);
  }
}

function encodePreauthorizationGenerationResults(results) {
  if (!Array.isArray(results) || results.length === 0 || results.length > 8) {
    throw new Error("preauthorization generation results are out of bounds");
  }
  return concatBytes(
    PREAUTHORIZATION_GENERATION_RESULT_MAGIC,
    u8(results.length, "preauthorization generation result count"),
    ...results.map((result) => vector(result, MAX_ARTIFACT_BYTES, "preauthorization signing result")),
  );
}

function decodeLamportGenerationPlan(value) {
  const bytes = asBytes(value, "Lamport generation plan");
  try {
    const reader = new Reader(bytes, "Lamport generation plan");
    if (!sameBytes(reader.take(8), LAMPORT_GENERATION_PLAN_MAGIC)) {
      throw new Error("Lamport generation plan has the wrong magic");
    }
    const status = reader.u8();
    if (status === 0) {
      const artifact = reader.vector(MAX_ARTIFACT_BYTES);
      reader.finish();
      return { complete: true, artifact, total: 0, batches: [] };
    }
    if (status !== 1) throw new Error("Lamport generation plan has an unknown status");
    const total = reader.u32();
    const count = reader.u8();
    if (total === 0 || count === 0 || count > 8 || count > total) {
      throw new Error("Lamport generation plan has invalid bounds");
    }
    const batches = Array.from({ length: count }, () => reader.vector(MAX_ARTIFACT_BYTES));
    reader.finish();
    return { complete: false, artifact: null, total, batches };
  } finally {
    bytes.fill(0);
  }
}

function encodeLamportGenerationResults(results) {
  if (!Array.isArray(results) || results.length === 0 || results.length > 8) {
    throw new Error("Lamport generation results are out of bounds");
  }
  return concatBytes(
    LAMPORT_GENERATION_RESULT_MAGIC,
    u8(results.length, "Lamport generation result count"),
    ...results.map((result) => vector(result, MAX_ARTIFACT_BYTES, "Lamport generation shard")),
  );
}

/** Decode metadata emitted only after Rust strictly accepts a whole SessionEvent. */
export function decodeAcceptedSessionEvent(value) {
  const reader = new Reader(value, "CHAIN accepted SessionEvent result");
  if (!sameBytes(reader.take(8), SESSION_EVENT_RESULT_MAGIC)) {
    throw new Error("CHAIN accepted SessionEvent result has the wrong magic");
  }
  const setupKind = reader.u8();
  const status = reader.u8();
  const phase = reader.u8();
  const artifact = reader.vector(MAX_ARTIFACT_BYTES);
  const applicable = setupKind <= ChainSetupKind.PREAUTHORIZATION_OPENING && status <= 1;
  const notApplicable = setupKind === ChainSetupKind.NOT_APPLICABLE && status === 2;
  if ((!applicable && !notApplicable) || phase > ChainPhase.HALTED) {
    throw new Error("CHAIN accepted SessionEvent result has a noncanonical tag");
  }
  const exposesLamportBundle = applicable &&
    setupKind === ChainSetupKind.DESCRIPTOR_SIGNATURE;
  const exposesVerificationReceipt = applicable &&
    setupKind === ChainSetupKind.PREAUTHORIZATION_OPENING;
  if (exposesVerificationReceipt ? artifact.byteLength === 0 :
      !exposesLamportBundle && artifact.byteLength !== 0) {
    throw new Error("CHAIN accepted SessionEvent result exposes an artifact for the wrong setup kind");
  }
  reader.finish();
  return {
    setupKind,
    applicable,
    duplicate: applicable && status === 1,
    phase,
    localLamportBundle: exposesLamportBundle ? artifact : new Uint8Array(),
    verificationReceipt: exposesVerificationReceipt ? artifact : new Uint8Array(),
  };
}

/** One secret-bearing Wasm instance. Keep this object inside a dedicated Worker. */
export class ChainRuntime {
  static async create(wasmSource) {
    const result = await WebAssembly.instantiate(wasmSource, {});
    const instance = result instanceof WebAssembly.Instance ? result : result.instance;
    return new ChainRuntime(instance);
  }

  constructor(instance) {
    this.instance = instance;
    this.exports = instance.exports;
    if (this.exports.bp52_chain_abi_version() !== 5) {
      throw new Error("unsupported BP52 CHAIN Wasm ABI");
    }
    this.activationSignatures = [undefined, undefined];
    this.chainExchangeKind = undefined;
  }

  initialize(request) {
    const chainExchangeKind = request?.config?.chainExchangeKind;
    if (
      typeof chainExchangeKind !== "string" ||
      !/^[a-z0-9][a-z0-9._-]{0,31}$/.test(chainExchangeKind)
    ) {
      throw new Error("CHAIN config.chainExchangeKind is malformed");
    }
    this.chainExchangeKind = chainExchangeKind;
    const frame = encodeChainInit(request);
    try {
      this.#invoke("bp52_chain_init", frame);
      return {
        acknowledged: true,
        phase: this.phase(),
        localRole: this.localRole(),
        cards: null,
        wasmMiB: this.memoryMiB(),
      };
    } finally {
      frame.fill(0);
      request.identitySecret?.fill?.(0);
      request.entropy?.fill?.(0);
      request.snapshotKey?.fill?.(0);
      request.deal?.storageKey?.fill?.(0);
    }
  }

  signDescriptor(descriptor) { return this.#invoke("bp52_chain_sign_descriptor", descriptor); }
  prepareLocalLamportGeneration(workerCount) {
    return decodeLamportGenerationPlan(this.#invoke(
      "bp52_chain_prepare_local_lamport_generation",
      u8(workerCount, "Lamport worker count"),
    ));
  }
  completeLocalLamportGeneration(results) {
    const frame = encodeLamportGenerationResults(results);
    try {
      return this.#invoke("bp52_chain_complete_local_lamport_generation", frame);
    } finally {
      frame.fill(0);
    }
  }
  makeRootCommitment() { return this.#invoke("bp52_chain_make_root_commitment"); }
  openRoot() { return this.#invoke("bp52_chain_open_root"); }
  makePreauthorizationCommitment() { return this.#invoke("bp52_chain_make_preauthorization_commitment"); }
  prepareLocalPreauthorizationGeneration(workerCount) {
    return decodePreauthorizationGenerationPlan(this.#invoke(
      "bp52_chain_prepare_local_preauthorization_generation",
      u8(workerCount, "preauthorization worker count"),
    ));
  }
  completeLocalPreauthorizationGeneration(results) {
    const frame = encodePreauthorizationGenerationResults(results);
    try {
      return this.#invoke("bp52_chain_complete_local_preauthorization_generation", frame);
    } finally {
      frame.fill(0);
    }
  }
  openPreauthorizations() { return this.#invoke("bp52_chain_open_preauthorizations"); }
  preparePeerPreauthorizationVerification(role, artifact, workerCount) {
    return decodePreauthorizationVerificationPlan(this.#invoke(
      "bp52_chain_prepare_peer_preauthorization_verification",
      concatBytes(
        u8(workerCount, "preauthorization worker count"),
        encodeSetupExchangeInput(role, ChainExchangePackage.PREAUTHORIZATION_OPENING, artifact),
      ),
    ));
  }
  completePeerPreauthorizationVerification() {
    return decodeAcceptedSessionEvent(this.#invoke(
      "bp52_chain_complete_peer_preauthorization_verification",
    ));
  }
  acceptSessionEvent(senderRole, event) {
    if (senderRole !== 0 && senderRole !== 1) {
      throw new Error("SessionEvent sender role must be canonical Alice or Bob");
    }
    return decodeAcceptedSessionEvent(this.#invoke(
      "bp52_chain_accept_session_event",
      concatBytes(Uint8Array.of(senderRole), asBytes(event, "canonical SessionEvent")),
    ));
  }
  attestInventory() { return this.#invoke("bp52_chain_attest_inventory"); }
  graphPreparedReceipt() { return this.#invoke("bp52_chain_graph_prepared_receipt"); }
  runtimeAuthorizationReceipt() {
    return this.#invoke("bp52_chain_runtime_authorization_receipt");
  }
  confirmedStateReceipt() { return this.#invoke("bp52_chain_confirmed_state_receipt"); }

  makeLamportBundleExchange(artifact) {
    return this.#relayEnvelope(ChainExchangePackage.LAMPORT_PUBLIC_BUNDLE, artifact);
  }

  makeRootCommitmentExchange() {
    return this.#relayEnvelope(
      ChainExchangePackage.GRAPH_ROOT_COMMITMENT,
      this.makeRootCommitment(),
    );
  }

  makeRootOpeningExchange() {
    return this.#relayEnvelope(ChainExchangePackage.GRAPH_ROOT_OPENING, this.openRoot());
  }

  makePreauthorizationCommitmentExchange() {
    return this.#relayEnvelope(
      ChainExchangePackage.PREAUTHORIZATION_COMMITMENT,
      this.makePreauthorizationCommitment(),
    );
  }

  preauthorizationCommitmentExchange(artifact) {
    return this.#relayEnvelope(ChainExchangePackage.PREAUTHORIZATION_COMMITMENT, artifact);
  }

  makePreauthorizationOpeningExchange() {
    return this.#relayEnvelope(
      ChainExchangePackage.PREAUTHORIZATION_OPENING,
      this.openPreauthorizations(),
    );
  }

  makeInventoryReadyExchange() {
    const artifact = this.#invoke("bp52_chain_make_inventory_ready");
    return this.#relayEnvelope(ChainExchangePackage.INVENTORY_READY, artifact);
  }

  signActivation(unsignedTransaction) {
    const transaction = unsignedTransaction ?? this.activationTemplate();
    const signature = this.#invoke("bp52_chain_sign_activation", transaction);
    this.activationSignatures[this.localRole()] = signature;
    return this.#relayEnvelope(ChainExchangePackage.ACTIVATION_SIGNATURE, signature);
  }

  acceptExchange(value) {
    const decoded = decodeChainExchange(value, this.publicContext());
    if (decoded.package === ChainExchangePackage.INVENTORY_READY) {
      this.#invoke("bp52_chain_accept_inventory_ready", concatBytes(Uint8Array.of(decoded.role), decoded.artifact));
    } else if (decoded.package === ChainExchangePackage.ACTIVATION_SIGNATURE) {
      this.#invoke("bp52_chain_verify_activation_artifact", concatBytes(Uint8Array.of(decoded.role), decoded.artifact));
      const prior = this.activationSignatures[decoded.role];
      if (prior && !sameBytes(prior, decoded.artifact)) {
        throw new Error("conflicting activation signature from one role");
      }
      this.activationSignatures[decoded.role] = decoded.artifact;
    } else {
      decoded.setup = decodeAcceptedSessionEvent(this.#invoke(
        "bp52_chain_accept_setup_exchange",
        encodeSetupExchangeInput(decoded.role, decoded.package, decoded.artifact),
      ));
    }
    return decoded;
  }

  activationTemplate() { return this.#invoke("bp52_chain_activation_template"); }

  assembleActivation() {
    if (!this.activationSignatures[0] || !this.activationSignatures[1]) return null;
    return this.#invoke(
      "bp52_chain_assemble_activation",
      concatBytes(
        vector(this.activationTemplate(), MAX_INPUT_BYTES, "activation template"),
        vector(this.activationSignatures[0], 80, "Alice activation signature"),
        vector(this.activationSignatures[1], 80, "Bob activation signature"),
      ),
    );
  }

  confirmActivation({ confirmedHeight, tipHeight, transaction }) {
    const result = this.#invoke(
      "bp52_chain_confirm_activation",
      concatBytes(
        u32(confirmedHeight, "activation confirmation height"),
        u32(tipHeight, "activation tip height"),
        vector(transaction, MAX_INPUT_BYTES, "confirmed activation transaction"),
      ),
    );
    return result.byteLength === 0 ? null : decodeCardProjection(result);
  }

  openOffchainRoot(transaction) {
    return decodeCardProjection(this.#invoke(
      "bp52_chain_open_offchain_root",
      asBytes(transaction, "off-chain activation transaction"),
    ));
  }

  offchainStateReceipt() {
    return this.#invoke("bp52_chain_offchain_state_receipt");
  }

  offchainDisputePackage() {
    return decodeOffchainDisputePackage(this.#invoke("bp52_chain_offchain_dispute_package"));
  }

  commitOffchainWitness(witness) {
    return this.#invoke("bp52_chain_advance_offchain_witness", asBytes(witness, "off-chain witness"));
  }

  offchainTransition(witness) {
    return this.#relayEnvelope(
      ChainExchangePackage.OFFCHAIN_TRANSITION,
      asBytes(witness, "off-chain transition witness"),
    );
  }

  observeTip(height) {
    this.#invoke("bp52_chain_observe_tip", u32(height, "tip height"));
  }

  buildAction(action) { return this.#invoke("bp52_chain_build_action", Uint8Array.of(action)); }
  beginSelectedAction({ childNodeId, action }) {
    return this.#relayEnvelope(
      ChainExchangePackage.ACTION_SIGNATURE_REQUEST,
      this.#invoke(
        "bp52_chain_begin_selected_action",
        concatBytes(exactBytes(childNodeId, 32, "selected action childNodeId"), u8(action, "selected action")),
      ),
    );
  }
  acceptSelectedActionRequest(artifact) {
    return this.#invoke("bp52_chain_accept_selected_action_request", exactBytes(artifact, 130, "action-signature request"));
  }
  selectedActionResponse(artifact) {
    return this.#relayEnvelope(
      ChainExchangePackage.ACTION_SIGNATURE_RESPONSE,
      exactBytes(artifact, 194, "action-signature response"),
    );
  }
  acceptSelectedActionResponse(artifact) {
    return this.#invoke("bp52_chain_accept_selected_action_response", exactBytes(artifact, 194, "action-signature response"));
  }
  buildEdge({ childNodeId }) {
    return this.#invoke(
      "bp52_chain_build_advance",
      exactBytes(childNodeId, 32, "advance childNodeId"),
    );
  }
  buildReveal() { return this.#invoke("bp52_chain_build_reveal"); }
  buildAliceShowdown({ subset, score }) {
    return this.#invoke("bp52_chain_build_alice_showdown", concatBytes(Uint8Array.of(subset), u32(score, "Alice score")));
  }
  buildBobPayout({ subset, score, outcome }) {
    return this.#invoke("bp52_chain_build_bob_payout", concatBytes(Uint8Array.of(subset), u32(score, "Bob score"), Uint8Array.of(outcome)));
  }
  buildTimeout() { return this.#invoke("bp52_chain_build_timeout"); }

  confirmChild({ confirmedHeight, tipHeight, transaction }) {
    return this.#invoke(
      "bp52_chain_confirm_child",
      concatBytes(
        u32(confirmedHeight, "child confirmation height"),
        u32(tipHeight, "child tip height"),
        vector(transaction, MAX_INPUT_BYTES, "confirmed child transaction"),
      ),
    );
  }

  projectCards() { return decodeCardProjection(this.#invoke("bp52_chain_project_cards")); }
  publicContext() { return decodeChainContext(this.#invoke("bp52_chain_public_context")); }
  runtimeStatus() { return decodeRuntimeStatus(this.#invoke("bp52_chain_public_runtime_status")); }
  sealCheckpoint() { return this.#invoke("bp52_chain_seal_checkpoint"); }
  verifyCheckpoint(checkpoint) { return this.#invoke("bp52_chain_verify_checkpoint", checkpoint); }
  restoreCheckpoint(checkpoint) {
    return decodeRestoreReceipt(this.#invoke("bp52_chain_restore_checkpoint", checkpoint));
  }
  phase() { return this.exports.bp52_chain_phase(); }
  localRole() { return this.exports.bp52_chain_local_role(); }
  memoryMiB() { return this.exports.memory.buffer.byteLength / 1_048_576; }

  clear() {
    this.exports.bp52_chain_clear();
    this.activationSignatures = [undefined, undefined];
  }

  #relayEnvelope(packageId, artifact) {
    const bytes = encodeChainExchange({
      context: this.publicContext(),
      package: packageId,
      role: this.localRole(),
      artifact,
    });
    if (!this.chainExchangeKind) throw new Error("CHAIN relay kind is unavailable before initialization");
    return { kind: this.chainExchangeKind, payload: bytesToBase64(bytes) };
  }

  #invoke(exportName, input = new Uint8Array()) {
    return invokeWasm(this.instance, exportName, input);
  }
}

/** Stateless public-data verifier used by parallel child Workers. */
export class PreauthorizationBatchVerifier {
  static async create(wasmModule) {
    const result = await WebAssembly.instantiate(wasmModule, {});
    const instance = result instanceof WebAssembly.Instance ? result : result.instance;
    if (instance.exports.bp52_chain_abi_version() !== 5) {
      throw new Error("unsupported BP52 CHAIN Wasm ABI");
    }
    return new PreauthorizationBatchVerifier(instance);
  }

  constructor(instance) {
    this.instance = instance;
  }

  verify(batch) {
    const output = invokeWasm(
      this.instance,
      "bp52_chain_verify_preauthorization_batch",
      batch,
    );
    if (output.byteLength !== 4) throw new Error("preauthorization verifier returned invalid output");
    return new DataView(output.buffer, output.byteOffset, 4).getUint32(0, true);
  }


  generate(batch) {
    return invokeWasm(
      this.instance,
      "bp52_chain_generate_preauthorization_batch",
      batch,
    );
  }

  generateLamport(batch) {
    return invokeWasm(this.instance, "bp52_chain_generate_lamport_batch", batch);
  }
}

/** Create a transferable copy of a byte view. */
export function transferBytes(value) {
  const input = asBytes(value, "transfer value");
  return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength);
}
