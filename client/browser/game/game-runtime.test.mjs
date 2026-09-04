import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  GameEventSource,
  GameEventType,
  GameWasmSession,
  decodeGameExchangeResult,
  decodeGameProjection,
  encodeGameConfig,
  encodeSessionEvent,
} from "./game-runtime.js";

function hex(value) {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function hash(value) {
  return new Uint8Array(createHash("sha256").update(value).digest());
}

function taggedHash(tag, message) {
  const tagHash = hash(Buffer.from(tag));
  return hash(Buffer.concat([tagHash, tagHash, message]));
}

const networkId = hex("e3bc9730af93197380e11b43ca00d6b516d83321f46b8b9f53a22a4fae89e680");
const roomId = new Uint8Array(32).fill(5);
const nonce = new Uint8Array(32).fill(4);
const alice = hex("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f");
const bob = hex("024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766");
const context = taggedHash(
  "BP52/origin-context/v1",
  Buffer.concat([networkId, roomId, nonce]),
);
const script = new Uint8Array(104);
script[0] = 32;
script.set(context, 1);
script[33] = 0x75;
script[34] = 33;
script.set(alice, 35);
script[68] = 0xad;
script[69] = 33;
script.set(bob, 70);
script[103] = 0xac;
const displayTxid = Uint8Array.from({ length: 32 }, (_, index) => index);

const config = {
  protocolProfile: 1,
  bitcoinNetwork: 2,
  networkId,
  originOutpoint: { displayTxid, vout: 7 },
  relayRoomId: roomId,
  dealSessionNonce: nonce,
  identityKeys: [alice.slice(1), bob.slice(1)],
  localRole: 0,
  originConfirmationDepth: 1,
  gameplayConfirmationDepth: 2,
  button: 0,
  revealOrder: [0, 1, 0],
  splitRemainderRecipient: 1,
  originValueSat: 53_500n,
  activationFeeSat: 500n,
  originWitnessScript: script,
};

const encodedConfig = encodeGameConfig(config);
const configContractFixture = hex(readFileSync(
  new URL("../fixtures/game-config-v2.hex", import.meta.url),
  "utf8",
).trim());
assert.deepEqual(
  encodedConfig,
  configContractFixture,
  "the JS config encoder must remain byte-exact with the Rust decoder fixture",
);
assert.equal(encodedConfig.byteLength, 368);
assert.deepEqual(encodedConfig.slice(42, 74), displayTxid);
assert.deepEqual(encodedConfig.slice(74, 106), Uint8Array.from(displayTxid).reverse());
assert.equal(new DataView(encodedConfig.buffer).getUint32(106, true), 7);

const wrongScript = Uint8Array.from(script);
wrongScript[36] ^= 1;
assert.throws(
  () => encodeGameConfig({ ...config, originWitnessScript: wrongScript }),
  /canonical identity keys/,
);

const displayBlockHash = new Uint8Array(32).fill(0x42);
displayBlockHash[0] = 0x01;
displayBlockHash[31] = 0xfe;
const tip = encodeSessionEvent({
  type: GameEventType.TIP_OBSERVED,
  profileId: networkId,
  block: { height: 123, displayHash: displayBlockHash },
});
assert.equal(tip[0], 8);
assert.deepEqual(tip.slice(1, 33), networkId);
assert.equal(new DataView(tip.buffer).getUint32(33, true), 123);
assert.deepEqual(tip.slice(37), Uint8Array.from(displayBlockHash).reverse());

for (const [type, tag] of [
  [GameEventType.DEAL_ENVELOPE, 1],
  [GameEventType.DESCRIPTOR_SIGNATURE, 5],
]) {
  const field = type === GameEventType.DEAL_ENVELOPE
    ? { envelope: Uint8Array.of(1) }
    : { role: 0, descriptor: Uint8Array.of(1), signature: new Uint8Array(64) };
  assert.equal(encodeSessionEvent({ type, ...field })[0], tag);
}
assert.throws(
  () => encodeSessionEvent({ type: GameEventType.ACTIVATION_AUTHORIZED, transaction: new Uint8Array() }),
  /must not be empty/,
);

const projection = new Uint8Array(113);
projection.set(new TextEncoder().encode("BP52GP07"));
projection[8] = 2;
projection[9] = 1;
projection.fill(0x31, 10, 42);
projection.fill(0x32, 42, 74);
// dealAttempt/dealEnvelopes and all four optional ids remain zero.
// No ids, zero balances, no halt reason, and no projected intents.

// `apply-event` is forwarded directly by both real Worker entrypoints. Keep its
// public result shape aligned with init/replay so the coordinator never replaces
// its projection with `undefined` when applying the first local inventory event.
const memory = new WebAssembly.Memory({ initial: 1 });
const outputPointer = 2_048;
new Uint8Array(memory.buffer, outputPointer, projection.byteLength).set(projection);
const session = new GameWasmSession({
  exports: {
    memory,
    bp52_game_abi_version: () => 9,
    bp52_game_begin_input: () => 0,
    bp52_game_input_ptr: () => 512,
    bp52_game_apply: () => 0,
    bp52_game_apply_graph_prepared_receipt: () => 0,
    bp52_game_output_len: () => projection.byteLength,
    bp52_game_output_ptr: () => outputPointer,
  },
});
const applied = session.applyEvent(GameEventSource.AUTHENTICATED_CHAIN, {
  type: GameEventType.TIP_OBSERVED,
  profileId: networkId,
  block: { height: 123, displayHash: displayBlockHash },
});
assert.equal(applied.projection.status.phase, 1);
assert.deepEqual(applied.projection.intents, []);
assert.equal(Object.hasOwn(applied, "value"), false);
assert.equal(applied.metrics.wasmMiB, 1 / 16);
const receiptApplied = session.applyGraphPreparedReceipt(Uint8Array.of(7, 8, 9));
assert.equal(receiptApplied.value.status.phase, 1);
assert.deepEqual(new Uint8Array(memory.buffer, 512, 3), Uint8Array.of(7, 8, 9));

// ACTIVE recovery must retain the Rust-authenticated activation txid even
// though the current broadcast intent now names a gameplay child.
const activeProjection = new Uint8Array(145);
activeProjection.set(new TextEncoder().encode("BP52GP07"));
activeProjection[8] = 0;
activeProjection[9] = 9;
activeProjection.fill(0x31, 10, 42);
activeProjection.fill(0x32, 42, 74);
activeProjection[84] = 1;
activeProjection.fill(0xa5, 85, 117);
new DataView(activeProjection.buffer).setBigUint64(118, 2_843n, true);
new DataView(activeProjection.buffer).setBigUint64(126, 0n, true);
new DataView(activeProjection.buffer).setBigUint64(134, 8_529n, true);
const recoveredActive = decodeGameProjection(activeProjection);
assert.equal(recoveredActive.status.phase, 9);
assert.deepEqual(recoveredActive.status.activationTxid, new Uint8Array(32).fill(0xa5));
assert.deepEqual(recoveredActive.status.tableBalances, {
  aliceStackSat: 2_843,
  bobStackSat: 0,
  potSat: 8_529,
});

const exchangeResult = new Uint8Array(8 + 4 + projection.byteLength + 1 + 4 + 3);
exchangeResult.set(new TextEncoder().encode("BP52GX01"));
new DataView(exchangeResult.buffer).setUint32(8, projection.byteLength, true);
exchangeResult.set(projection, 12);
let resultOffset = 12 + projection.byteLength;
exchangeResult[resultOffset] = 1;
resultOffset += 1;
new DataView(exchangeResult.buffer).setUint32(resultOffset, 3, true);
resultOffset += 4;
exchangeResult.set([0xaa, 0xbb, 0xcc], resultOffset);
const decodedExchange = decodeGameExchangeResult(exchangeResult);
assert.equal(decodedExchange.projection.status.phase, 1);
assert.equal(decodedExchange.dealDispatch.kind, "deal-envelope");
assert.deepEqual(decodedExchange.dealDispatch.envelope, Uint8Array.of(0xaa, 0xbb, 0xcc));

process.stdout.write("game runtime canonical codec tests ok\n");
