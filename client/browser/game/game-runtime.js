const CONFIG_MAGIC = new TextEncoder().encode("BP52GM02");
const APPLY_MAGIC = new TextEncoder().encode("BP52GA01");
const RECOVERY_MAGIC = new TextEncoder().encode("BP52GR01");
const PROJECTION_MAGIC = new TextEncoder().encode("BP52GP07");
const EXCHANGE_RESULT_MAGIC = new TextEncoder().encode("BP52GX01");
const ORIGIN_WITNESS_SCRIPT_LENGTH = 104;
const MAX_U16 = 0xffff;
const MAX_U32 = 0xffffffff;
const MAX_VECTOR_BYTES = 64 * 1024 * 1024;
export const MAX_EVENT_ARTIFACT_BYTES = 32 * 1024 * 1024;

export const GamePhase = Object.freeze({
  AWAITING_ORIGIN: 0,
  DEALING: 1,
  ACCEPTING_DEAL: 2,
  SIGNING_DESCRIPTOR: 3,
  PREPARING_GRAPH: 4,
  AUTHORIZING_ACTIVATION: 5,
  AWAITING_ACTIVATION: 6,
  ACTIVE: 7,
  SETTLED: 8,
  HALTED: 9,
});

export const AppendDisposition = Object.freeze({
  NOT_APPLICABLE: 0,
  DUPLICATE: 1,
  APPENDED: 2,
});

export const GameEventSource = Object.freeze({
  AUTHENTICATED_CHAIN: 0,
  AUTHENTICATED_EXCHANGE: 1,
  LOCAL_SECRET_RUNTIME: 2,
  LOCAL_WALLET: 3,
});

export const GameEventType = Object.freeze({
  ORIGIN_CONFIRMED: "origin-confirmed",
  DEAL_ENVELOPE: "deal-envelope",
  DEAL_VERIFICATION_ATTESTED: "deal-verification-attested",
  ACCEPTED_DEAL_SIGNATURE: "accepted-deal-signature",
  DEAL_RETRY_SIGNATURE: "deal-retry-signature",
  DESCRIPTOR_SIGNATURE: "descriptor-signature",
  ACTIVATION_AUTHORIZED: "activation-authorized",
  TIP_OBSERVED: "tip-observed",
  SPEND_CONFIRMED: "spend-confirmed",
});

const INTENT_NAMES = Object.freeze([
  "observe-origin",
  "deal-envelope-due",
  "approve-deal-retry",
  "sign-accepted-deal",
  "sign-descriptor",
  "prepare-graph",
  "authorize-activation",
  "broadcast-transaction",
  "observe-state",
  "choose-runtime-edge",
  "settlement-confirmed",
  "halted",
  "settlement-offchain",
]);

function bytes(value, label) {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new Error(`${label} must be a byte array`);
}

function exactBytes(value, length, label) {
  const result = bytes(value, label);
  if (result.byteLength !== length) {
    throw new Error(`${label} must contain exactly ${length} bytes`);
  }
  return result;
}

function exactInteger(value, maximum, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new Error(`${label} is outside its canonical integer range`);
  }
  return value;
}

function role(value, label) {
  if (value !== 0 && value !== 1) {
    throw new Error(`${label} must be canonical role 0 or 1`);
  }
  return value;
}

function bigint(value, label) {
  const result = typeof value === "bigint" ? value : BigInt(value);
  if (result < 0n || result > 0xffffffffffffffffn) {
    throw new Error(`${label} is outside the unsigned 64-bit range`);
  }
  return result;
}

function sameBytes(left, right) {
  return left.byteLength === right.byteLength && left.every((value, index) => value === right[index]);
}

function writeU64(view, offset, value) {
  view.setBigUint64(offset, bigint(value, "u64 value"), true);
}

function compareLexicographically(left, right) {
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) {
      return left[index] - right[index];
    }
  }
  return 0;
}

function displayToConsensus(value, label) {
  return Uint8Array.from(exactBytes(value, 32, label)).reverse();
}

class Encoder {
  constructor(label, maximum = MAX_VECTOR_BYTES) {
    this.label = label;
    this.maximum = maximum;
    this.chunks = [];
    this.length = 0;
  }

  append(value) {
    const chunk = bytes(value, this.label);
    const next = this.length + chunk.byteLength;
    if (!Number.isSafeInteger(next) || next > this.maximum) {
      throw new Error(`${this.label} exceeds its fixed bound`);
    }
    this.chunks.push(chunk);
    this.length = next;
  }

  u8(value) {
    this.append(Uint8Array.of(exactInteger(value, 0xff, `${this.label} u8`)));
  }

  u16(value) {
    const encoded = new Uint8Array(2);
    new DataView(encoded.buffer).setUint16(0, exactInteger(value, MAX_U16, `${this.label} u16`), true);
    this.append(encoded);
  }

  u32(value) {
    const encoded = new Uint8Array(4);
    new DataView(encoded.buffer).setUint32(0, exactInteger(value, MAX_U32, `${this.label} u32`), true);
    this.append(encoded);
  }

  u64(value) {
    const encoded = new Uint8Array(8);
    writeU64(new DataView(encoded.buffer), 0, bigint(value, `${this.label} u64`));
    this.append(encoded);
  }

  vector(value, maximum) {
    const encoded = bytes(value, `${this.label} vector`);
    if (encoded.byteLength > maximum || encoded.byteLength > MAX_U32) {
      throw new Error(`${this.label} vector exceeds its fixed bound`);
    }
    this.u32(encoded.byteLength);
    this.append(encoded);
  }

  finish() {
    const output = new Uint8Array(this.length);
    let offset = 0;
    for (const chunk of this.chunks) {
      output.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return output;
  }
}

function profileId(value) {
  return exactBytes(value, 32, "event profileId");
}

function encodeEventOutpoint(encoder, value, label) {
  encoder.append(displayToConsensus(value?.displayTxid, `${label}.displayTxid`));
  encoder.u32(value?.vout);
}

function encodeBlock(encoder, value, label) {
  encoder.u32(value?.height);
  encoder.append(displayToConsensus(value?.displayHash, `${label}.displayHash`));
}

/** Strictly encode one public game-session event for the Wasm reducer. */
export function encodeSessionEvent(event) {
  if (!event || typeof event !== "object") {
    throw new Error("session event must be a structured object");
  }
  const encoder = new Encoder("session event", MAX_EVENT_ARTIFACT_BYTES + 256);
  switch (event.type) {
    case GameEventType.ORIGIN_CONFIRMED:
      encoder.u8(0);
      encoder.append(profileId(event.profileId));
      encodeEventOutpoint(encoder, event.outpoint, "origin outpoint");
      encoder.u64(event.valueSat);
      encoder.vector(event.scriptPubkey, 10_000);
      encoder.append(displayToConsensus(event.creatingDisplayTxid, "creatingDisplayTxid"));
      encoder.vector(event.creatingTransaction, MAX_VECTOR_BYTES);
      if (bytes(event.creatingTransaction, "creatingTransaction").byteLength === 0) {
        throw new Error("creatingTransaction must not be empty");
      }
      encodeBlock(encoder, event.confirmedIn, "confirmedIn");
      encodeBlock(encoder, event.observedTip, "observedTip");
      break;
    case GameEventType.DEAL_ENVELOPE:
      encoder.u8(1);
      encoder.vector(event.envelope, MAX_EVENT_ARTIFACT_BYTES);
      break;
    case GameEventType.DEAL_VERIFICATION_ATTESTED:
      encoder.u8(2);
      encoder.vector(event.attestation, MAX_EVENT_ARTIFACT_BYTES);
      break;
    case GameEventType.ACCEPTED_DEAL_SIGNATURE:
      encoder.u8(3);
      encoder.u8(role(event.role, "accepted-deal signature role"));
      encoder.append(exactBytes(event.signature, 64, "accepted-deal signature"));
      break;
    case GameEventType.DEAL_RETRY_SIGNATURE:
      encoder.u8(4);
      encoder.u32(event.nextAttempt);
      encoder.u8(role(event.role, "DEAL retry signature role"));
      encoder.append(exactBytes(event.signature, 64, "DEAL retry signature"));
      break;
    case GameEventType.DESCRIPTOR_SIGNATURE:
      encoder.u8(5);
      encoder.u8(role(event.role, "descriptor signature role"));
      encoder.vector(event.descriptor, MAX_EVENT_ARTIFACT_BYTES);
      encoder.append(exactBytes(event.signature, 64, "descriptor signature"));
      break;
    case GameEventType.ACTIVATION_AUTHORIZED:
      encoder.u8(7);
      encoder.vector(event.transaction, MAX_VECTOR_BYTES);
      if (bytes(event.transaction, "activation transaction").byteLength === 0) {
        throw new Error("activation transaction must not be empty");
      }
      break;
    case GameEventType.TIP_OBSERVED:
      encoder.u8(8);
      encoder.append(profileId(event.profileId));
      encodeBlock(encoder, event.block, "tip block");
      break;
    case GameEventType.SPEND_CONFIRMED:
      encoder.u8(10);
      encoder.append(profileId(event.profileId));
      encodeEventOutpoint(encoder, event.spentOutpoint, "spent outpoint");
      encoder.append(displayToConsensus(event.spendingDisplayTxid, "spendingDisplayTxid"));
      encoder.vector(event.spendingTransaction, MAX_VECTOR_BYTES);
      if (bytes(event.spendingTransaction, "spendingTransaction").byteLength === 0) {
        throw new Error("spendingTransaction must not be empty");
      }
      encoder.u32(event.inputIndex);
      encodeBlock(encoder, event.confirmedIn, "confirmedIn");
      encodeBlock(encoder, event.observedTip, "observedTip");
      break;
    default:
      throw new Error(`unknown game-session event type: ${String(event.type)}`);
  }
  return encoder.finish();
}

/** Encode the only game-session configuration accepted by this prototype. */
export function encodeGameConfig(config) {
  const protocolProfile = exactInteger(config.protocolProfile, 0xff, "protocolProfile");
  const bitcoinNetwork = exactInteger(config.bitcoinNetwork, 3, "bitcoinNetwork");
  const networkId = exactBytes(config.networkId, 32, "networkId");
  const originDisplayTxid = exactBytes(
    config.originOutpoint?.displayTxid,
    32,
    "originOutpoint.displayTxid",
  );
  const originConsensusTxid = Uint8Array.from(originDisplayTxid).reverse();
  const originVout = exactInteger(config.originOutpoint?.vout, MAX_U32, "originOutpoint.vout");
  const roomId = exactBytes(config.relayRoomId, 32, "relayRoomId");
  const nonce = exactBytes(config.dealSessionNonce, 32, "dealSessionNonce");
  if (!Array.isArray(config.identityKeys) || config.identityKeys.length !== 2) {
    throw new Error("identityKeys must contain canonical Alice and Bob x-only keys");
  }
  const alice = exactBytes(config.identityKeys[0], 32, "identityKeys[0]");
  const bob = exactBytes(config.identityKeys[1], 32, "identityKeys[1]");
  if (compareLexicographically(alice, bob) >= 0) {
    throw new Error("identityKeys must be distinct and ordered Alice then Bob");
  }
  const localRole = role(config.localRole, "localRole");
  const originDepth = exactInteger(
    config.originConfirmationDepth,
    MAX_U16,
    "originConfirmationDepth",
  );
  const gameplayDepth = exactInteger(
    config.gameplayConfirmationDepth,
    MAX_U16,
    "gameplayConfirmationDepth",
  );
  if (originDepth === 0 || gameplayDepth === 0) {
    throw new Error("confirmation depths must be nonzero");
  }
  const button = role(config.button, "button");
  const revealOrder = config.revealOrder;
  if (!Array.isArray(revealOrder) || revealOrder.length !== 3) {
    throw new Error("revealOrder must contain flop, turn, and river first revealers");
  }
  const splitRecipient = role(config.splitRemainderRecipient, "splitRemainderRecipient");
  const originValue = bigint(config.originValueSat, "originValueSat");
  const activationFee = bigint(config.activationFeeSat, "activationFeeSat");
  const witnessScript = exactBytes(
    config.originWitnessScript,
    ORIGIN_WITNESS_SCRIPT_LENGTH,
    "originWitnessScript",
  );
  if (
    witnessScript[0] !== 32 || witnessScript[33] !== 0x75 ||
    witnessScript[34] !== 33 || witnessScript[68] !== 0xad ||
    witnessScript[69] !== 33 || witnessScript[103] !== 0xac ||
    (witnessScript[35] !== 2 && witnessScript[35] !== 3) ||
    (witnessScript[70] !== 2 && witnessScript[70] !== 3) ||
    !sameBytes(witnessScript.slice(36, 68), alice) ||
    !sameBytes(witnessScript.slice(71, 103), bob)
  ) {
    throw new Error("originWitnessScript does not encode the canonical identity keys/opcodes");
  }

  const output = new Uint8Array(368);
  const view = new DataView(output.buffer);
  let offset = 0;
  for (const value of [
    CONFIG_MAGIC,
    Uint8Array.of(protocolProfile, bitcoinNetwork),
    networkId,
    originDisplayTxid,
    originConsensusTxid,
  ]) {
    output.set(value, offset);
    offset += value.byteLength;
  }
  view.setUint32(offset, originVout, true);
  offset += 4;
  for (const value of [roomId, nonce, alice, bob, Uint8Array.of(localRole)]) {
    output.set(value, offset);
    offset += value.byteLength;
  }
  view.setUint16(offset, originDepth, true);
  offset += 2;
  view.setUint16(offset, gameplayDepth, true);
  offset += 2;
  output[offset] = button;
  offset += 1;
  for (const value of revealOrder) {
    output[offset] = role(value, "revealOrder role");
    offset += 1;
  }
  output[offset] = splitRecipient;
  offset += 1;
  writeU64(view, offset, originValue);
  offset += 8;
  writeU64(view, offset, activationFee);
  offset += 8;
  output.set(witnessScript, offset);
  offset += witnessScript.byteLength;
  if (offset !== output.byteLength) {
    throw new Error("internal game config length invariant failed");
  }
  return output;
}

function encodeRecovery(config, snapshot) {
  if (config.byteLength > MAX_U32 || snapshot.byteLength > MAX_U32) {
    throw new Error("game recovery component is too large");
  }
  const output = new Uint8Array(16 + config.byteLength + snapshot.byteLength);
  const view = new DataView(output.buffer);
  output.set(RECOVERY_MAGIC, 0);
  view.setUint32(8, config.byteLength, true);
  view.setUint32(12, snapshot.byteLength, true);
  output.set(config, 16);
  output.set(snapshot, 16 + config.byteLength);
  return output;
}

function encodeApply(source, event) {
  exactInteger(source, GameEventSource.LOCAL_WALLET, "game event source");
  const eventBytes = bytes(event, "session event");
  if (eventBytes.byteLength > MAX_U32) {
    throw new Error("session event is too large");
  }
  const output = new Uint8Array(13 + eventBytes.byteLength);
  const view = new DataView(output.buffer);
  output.set(APPLY_MAGIC, 0);
  output[8] = source;
  view.setUint32(9, eventBytes.byteLength, true);
  output.set(eventBytes, 13);
  return output;
}

class Reader {
  constructor(value, label) {
    this.bytes = bytes(value, label);
    this.view = new DataView(this.bytes.buffer, this.bytes.byteOffset, this.bytes.byteLength);
    this.offset = 0;
    this.label = label;
  }

  take(length) {
    exactInteger(length, MAX_VECTOR_BYTES, `${this.label} read length`);
    const end = this.offset + length;
    if (!Number.isSafeInteger(end) || end > this.bytes.byteLength) {
      throw new Error(`${this.label} is truncated`);
    }
    const result = this.bytes.slice(this.offset, end);
    this.offset = end;
    return result;
  }

  u8() {
    return this.take(1)[0];
  }

  u16() {
    const offset = this.offset;
    this.take(2);
    return this.view.getUint16(offset, true);
  }

  u32() {
    const offset = this.offset;
    this.take(4);
    return this.view.getUint32(offset, true);
  }

  u64() {
    const offset = this.offset;
    this.take(8);
    const value = this.view.getBigUint64(offset, true);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`${this.label} u64 exceeds JavaScript's exact integer range`);
    }
    return Number(value);
  }

  vector(maximum = MAX_VECTOR_BYTES) {
    const length = this.u32();
    if (length > maximum) {
      throw new Error(`${this.label} vector exceeds its fixed bound`);
    }
    return this.take(length);
  }

  optionalFixed(length) {
    const tag = this.u8();
    if (tag === 0) {
      return undefined;
    }
    if (tag !== 1) {
      throw new Error(`${this.label} has a noncanonical option tag`);
    }
    return this.take(length);
  }

  finish() {
    if (this.offset !== this.bytes.byteLength) {
      throw new Error(`${this.label} contains trailing bytes`);
    }
  }
}

function decodeText(reader) {
  return new TextDecoder("utf-8", { fatal: true }).decode(reader.vector(2 * 1024));
}

function decodeOutpoint(reader) {
  return { txid: reader.take(32), vout: reader.u32() };
}

function decodeEdgeKind(encoded) {
  const reader = new Reader(encoded, "edge kind");
  const tag = reader.u8();
  let value;
  switch (tag) {
    case 0:
      value = { tag, name: "advance", phase: reader.u8() };
      break;
    case 1:
      value = { tag, name: "action", action: reader.u8() };
      break;
    case 2:
      value = { tag, name: "hole-card-reveal", revealer: role(reader.u8(), "revealer") };
      break;
    case 3:
      value = {
        tag,
        name: "community-reveal",
        street: reader.u8(),
        revealer: role(reader.u8(), "revealer"),
      };
      break;
    case 4:
      value = { tag, name: "alice-showdown" };
      break;
    case 5:
      value = { tag, name: "bob-payout", outcome: reader.u8() };
      break;
    case 6:
      value = { tag, name: "timeout", timeoutKind: reader.u8() };
      break;
    default:
      throw new Error("edge kind has an unknown tag");
  }
  reader.finish();
  return value;
}

function decodeAuthorization(encoded) {
  const reader = new Reader(encoded, "authorization policy");
  const tag = reader.u8();
  let value;
  switch (tag) {
    case 0:
      value = { tag, name: "both-presigned" };
      break;
    case 1:
      value = { tag, name: "betting-action", actor: role(reader.u8(), "actor") };
      break;
    case 2:
      value = { tag, name: "reveal-preimages", revealer: role(reader.u8(), "revealer") };
      break;
    case 3:
      value = { tag, name: "alice-score" };
      break;
    case 4:
      value = { tag, name: "bob-live-payout" };
      break;
    case 5:
      value = { tag, name: "timeout", beneficiary: role(reader.u8(), "beneficiary") };
      break;
    default:
      throw new Error("authorization policy has an unknown tag");
  }
  reader.finish();
  return value;
}

function decodeIntent(encoded) {
  const reader = new Reader(encoded, "session intent");
  const tag = reader.u8();
  if (tag >= INTENT_NAMES.length) {
    throw new Error("session intent has an unknown tag");
  }
  let value = { tag, name: INTENT_NAMES[tag] };
  switch (tag) {
    case 0:
    case 8:
      value.outpoint = decodeOutpoint(reader);
      break;
    case 1:
      Object.assign(value, {
        attempt: reader.u32(),
        sequence: reader.u32(),
        round: reader.u16(),
        sender: role(reader.u8(), "DEAL sender"),
        payloadType: reader.u16(),
        previousMessageHash: reader.take(32),
      });
      break;
    case 2:
      value.nextAttempt = reader.u32();
      value.digest = reader.take(32);
      break;
    case 3:
      value.body = reader.vector();
      value.digest = reader.take(32);
      break;
    case 4:
      value.descriptor = reader.vector();
      value.digest = reader.take(32);
      break;
    case 5:
      break;
    case 6:
      value.unsignedTransaction = reader.vector();
      break;
    case 7:
      value.txid = reader.take(32);
      value.transaction = reader.vector();
      value.purpose = reader.u8();
      break;
    case 9: {
      value.nodeId = reader.take(32);
      value.nodeKind = reader.u8();
      const count = reader.u32();
      value.edges = [];
      for (let index = 0; index < count; index += 1) {
        value.edges.push({
          childNodeId: reader.take(32),
          kind: decodeEdgeKind(reader.vector(16)),
          authorization: decodeAuthorization(reader.vector(16)),
          sighash: reader.take(32),
        });
      }
      const timeoutTag = reader.u8();
      if (timeoutTag === 1) {
        value.timeoutMaturesAt = reader.u32();
      } else if (timeoutTag !== 0) {
        throw new Error("runtime-edge timeout has a noncanonical option tag");
      }
      break;
    }
    case 10:
      value.nodeId = reader.take(32);
      value.txid = reader.take(32);
      break;
    case 11:
      value.reason = decodeText(reader);
      break;
    case 12:
      value.nodeId = reader.take(32);
      break;
    default:
      break;
  }
  reader.finish();
  return value;
}

/** Decode and strictly validate one reducer projection frame. */
export function decodeGameProjection(encoded) {
  const reader = new Reader(encoded, "game projection");
  if (!sameBytes(reader.take(8), PROJECTION_MAGIC)) {
    throw new Error("game projection has the wrong magic");
  }
  const appendDisposition = reader.u8();
  if (appendDisposition > AppendDisposition.APPENDED) {
    throw new Error("game projection has an unknown append disposition");
  }
  const phase = reader.u8();
  if (phase > GamePhase.HALTED) {
    throw new Error("game projection has an unknown phase");
  }
  const status = {
    phase,
    dealGameId: reader.take(32),
    sharedConfigHash: reader.take(32),
    dealAttempt: reader.u32(),
    dealEnvelopes: reader.u32(),
    chainGameId: reader.optionalFixed(32),
    graphRoot: reader.optionalFixed(32),
    activationTxid: reader.optionalFixed(32),
    nodeId: reader.optionalFixed(32),
    tableBalances: {
      aliceStackSat: reader.u64(),
      bobStackSat: reader.u64(),
      potSat: reader.u64(),
    },
  };
  const reasonTag = reader.u8();
  if (reasonTag === 1) {
    status.haltReason = decodeText(reader);
  } else if (reasonTag !== 0) {
    throw new Error("game projection halt reason has a noncanonical option tag");
  }
  const count = reader.u16();
  const intents = [];
  for (let index = 0; index < count; index += 1) {
    intents.push(decodeIntent(reader.vector()));
  }
  reader.finish();
  return { appendDisposition, status, intents };
}

/** Decode Rust-validated private-DEAL dispatch after an Exchange event applies. */
export function decodeGameExchangeResult(encoded) {
  const reader = new Reader(encoded, "game Exchange result");
  if (!sameBytes(reader.take(8), EXCHANGE_RESULT_MAGIC)) {
    throw new Error("game Exchange result has the wrong magic");
  }
  const projection = decodeGameProjection(reader.vector(MAX_VECTOR_BYTES));
  const kind = reader.u8();
  let dealDispatch;
  switch (kind) {
    case 0:
      dealDispatch = { kind: "none" };
      break;
    case 1:
      dealDispatch = {
        kind: "deal-envelope",
        envelope: reader.vector(MAX_EVENT_ARTIFACT_BYTES),
      };
      break;
    case 2:
      dealDispatch = {
        kind: "accepted-deal-signature",
        role: role(reader.u8(), "accepted-DEAL signature role"),
        signature: reader.take(64),
      };
      break;
    case 3:
      dealDispatch = {
        kind: "deal-retry-signature",
        nextAttempt: reader.u32(),
        role: role(reader.u8(), "DEAL retry signature role"),
        signature: reader.take(64),
      };
      break;
    default:
      throw new Error("game Exchange result has an unknown DEAL dispatch kind");
  }
  reader.finish();
  return { projection, dealDispatch };
}

/** One Worker-local Wasm reducer instance. */
export class GameWasmSession {
  static async create(wasmSource) {
    const result = await WebAssembly.instantiate(wasmSource, {});
    const instance = result instanceof WebAssembly.Instance ? result : result.instance;
    return new GameWasmSession(instance);
  }

  constructor(instance) {
    this.instance = instance;
    this.exports = instance.exports;
    if (this.exports.bp52_game_abi_version() !== 9) {
      throw new Error("unsupported BP52 game-session Wasm ABI");
    }
    this.configFrame = undefined;
  }

  initialize(config) {
    const configFrame = encodeGameConfig(config);
    const result = this.#timed(() => {
      this.#stageInput(configFrame);
      this.#check(this.exports.bp52_game_init());
      return decodeGameProjection(this.#readOutput());
    });
    this.configFrame = Uint8Array.from(configFrame);
    return { projection: result.value, metrics: result.metrics };
  }

  replay({ config, snapshot }) {
    const configFrame = encodeGameConfig(config);
    const snapshotBytes = bytes(snapshot, "snapshot");
    const recovery = encodeRecovery(configFrame, snapshotBytes);
    const result = this.#timed(() => {
      this.#stageInput(recovery);
      this.#check(this.exports.bp52_game_replay());
      return decodeGameProjection(this.#readOutput());
    });
    this.configFrame = Uint8Array.from(configFrame);
    return { projection: result.value, metrics: result.metrics };
  }

  applyEvent(source, event) {
    if (source === GameEventSource.AUTHENTICATED_EXCHANGE) {
      throw new Error("Exchange events require the authenticated opaque ingress");
    }
    const eventBytes =
      event && typeof event === "object" && !(event instanceof ArrayBuffer) &&
      !ArrayBuffer.isView(event)
        ? encodeSessionEvent(event)
        : bytes(event, "session event");
    const frame = encodeApply(source, eventBytes);
    const result = this.#timed(() => {
      this.#stageInput(frame);
      this.#check(this.exports.bp52_game_apply());
      return decodeGameProjection(this.#readOutput());
    });
    return { projection: result.value, metrics: result.metrics };
  }

  applyExchangeEvent(senderRole, event) {
    const sender = role(senderRole, "authenticated Exchange sender role");
    const eventBytes = bytes(event, "canonical Exchange SessionEvent");
    if (eventBytes.byteLength === 0 || eventBytes.byteLength > MAX_EVENT_ARTIFACT_BYTES + 256) {
      throw new Error("Exchange SessionEvent exceeds its fixed bound");
    }
    const input = new Uint8Array(1 + eventBytes.byteLength);
    input[0] = sender;
    input.set(eventBytes, 1);
    return this.#timed(() => {
      this.#stageInput(input);
      this.#check(this.exports.bp52_game_apply_exchange());
      return decodeGameExchangeResult(this.#readOutput());
    });
  }

  #applyChainReceipt(receipt, label, operation) {
    const receiptBytes = bytes(receipt, label);
    if (receiptBytes.byteLength === 0 || receiptBytes.byteLength > MAX_EVENT_ARTIFACT_BYTES) {
      throw new Error(`${label} exceeds its fixed bound`);
    }
    return this.#timed(() => {
      this.#stageInput(receiptBytes);
      this.#check(this.exports[operation]());
      return decodeGameProjection(this.#readOutput());
    });
  }

  applyGraphPreparedReceipt(receipt) {
    return this.#applyChainReceipt(
      receipt,
      "graph-prepared receipt",
      "bp52_game_apply_graph_prepared_receipt",
    );
  }

  applyRuntimeAuthorizationReceipt(receipt) {
    return this.#applyChainReceipt(
      receipt,
      "runtime-authorization receipt",
      "bp52_game_apply_runtime_authorization_receipt",
    );
  }

  applyConfirmedStateReceipt(receipt) {
    return this.#applyChainReceipt(
      receipt,
      "confirmed-state receipt",
      "bp52_game_apply_confirmed_state_receipt",
    );
  }

  applyOffchainStateReceipt(receipt) {
    return this.#applyChainReceipt(
      receipt,
      "off-chain state receipt",
      "bp52_game_apply_offchain_state_receipt",
    );
  }

  project() {
    this.#check(this.exports.bp52_game_project());
    return decodeGameProjection(this.#readOutput());
  }

  snapshot() {
    this.#check(this.exports.bp52_game_snapshot());
    return this.#readOutput();
  }

  memoryMiB() {
    return this.exports.memory.buffer.byteLength / 1_048_576;
  }

  clear() {
    this.exports.bp52_game_clear();
    this.configFrame = undefined;
  }

  #stageInput(value) {
    const input = bytes(value, "Wasm input");
    this.#check(this.exports.bp52_game_begin_input(input.byteLength));
    const pointer = this.exports.bp52_game_input_ptr();
    if (input.byteLength > 0 && pointer === 0) {
      throw new Error("BP52 game Wasm returned a null input pointer");
    }
    new Uint8Array(this.exports.memory.buffer, pointer, input.byteLength).set(input);
  }

  #readOutput() {
    const length = this.exports.bp52_game_output_len();
    const pointer = this.exports.bp52_game_output_ptr();
    if (length > 0 && pointer === 0) {
      throw new Error("BP52 game Wasm returned a null output pointer");
    }
    return Uint8Array.from(new Uint8Array(this.exports.memory.buffer, pointer, length));
  }

  #lastError() {
    const length = this.exports.bp52_game_last_error_len();
    const pointer = this.exports.bp52_game_last_error_ptr();
    if (length === 0 || pointer === 0) {
      return "unknown game-session Wasm error";
    }
    return new TextDecoder().decode(
      new Uint8Array(this.exports.memory.buffer, pointer, length),
    );
  }

  #check(code) {
    if (code !== 0) {
      throw new Error(`BP52 game-session Wasm error ${code}: ${this.#lastError()}`);
    }
  }

  #timed(operation) {
    const started = performance.now();
    const value = operation();
    return {
      value,
      metrics: {
        elapsedMs: performance.now() - started,
        wasmMiB: this.memoryMiB(),
      },
    };
  }
}

export function transferBytes(value) {
  const input = bytes(value, "transfer value");
  return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength);
}

function hexToBytes(hex) {
  if (hex.length % 2 !== 0) {
    throw new Error("hex input has odd length");
  }
  const output = new Uint8Array(hex.length / 2);
  for (let index = 0; index < output.length; index += 1) {
    output[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return output;
}
