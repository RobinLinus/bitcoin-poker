import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  ChainExchangePackage,
  ChainSetupKind,
  base64ToBytes,
  bytesToBase64,
  chainRelayMessageIdMaterial,
  decodeCardProjection,
  decodeAcceptedSessionEvent,
  decodeChainExchange,
  decodeRuntimeStatus,
  displayTxidToConsensus,
  encodeChainExchange,
  encodeChainInit,
} from "./chain-runtime.js";

const sequence = Uint8Array.from({ length: 32 }, (_, index) => index);
const alice = new Uint8Array(32).fill(1);
const bob = new Uint8Array(32).fill(2);

assert.deepEqual(
  Array.from(displayTxidToConsensus(sequence)),
  Array.from(sequence).reverse(),
  "display txid is reversed exactly once",
);

const init = encodeChainInit({
  config: {
    configHash: new Uint8Array(32).fill(3),
    protocolProfile: 2,
    bitcoinNetwork: 2,
    networkId: new Uint8Array(32).fill(20),
    relayRoomId: new Uint8Array(32).fill(4),
    sessionNonce: new Uint8Array(32).fill(21),
    origin: {
      displayTxid: sequence,
      consensusTxid: Uint8Array.from(sequence).reverse(),
      vout: 7,
      witnessScript: new Uint8Array(104).fill(5),
    },
    identities: [alice, bob],
  },
  identitySecret: new Uint8Array(32).fill(6),
  entropy: new Uint8Array(32).fill(7),
  snapshotKey: new Uint8Array(32).fill(8),
  deal: {
    certificate: Uint8Array.of(9),
    attestation: Uint8Array.of(10, 11),
    sealedPreimages: Uint8Array.of(12, 13, 14),
    storageKey: new Uint8Array(32).fill(15),
  },
});
assert.deepEqual(Array.from(init.slice(138, 170)), Array.from(sequence).reverse());
assert.equal(new DataView(init.buffer, init.byteOffset + 170, 4).getUint32(0, true), 7);

assert.throws(
  () => encodeChainInit({
    config: {
      configHash: new Uint8Array(32).fill(3),
      protocolProfile: 2,
      bitcoinNetwork: 2,
      networkId: new Uint8Array(32).fill(20),
      relayRoomId: new Uint8Array(32).fill(4),
      sessionNonce: new Uint8Array(32).fill(21),
      origin: {
        displayTxid: sequence,
        consensusTxid: sequence,
        vout: 7,
        witnessScript: new Uint8Array(104),
      },
      identities: [alice, bob],
    },
    identitySecret: new Uint8Array(32).fill(6),
    entropy: new Uint8Array(32).fill(7),
    snapshotKey: new Uint8Array(32).fill(8),
    deal: {
      certificate: Uint8Array.of(1),
      attestation: Uint8Array.of(1),
      sealedPreimages: Uint8Array.of(1),
      storageKey: new Uint8Array(32).fill(9),
    },
  }),
  /exact reversals/,
);

const context = {
  hasGraph: true,
  networkId: new Uint8Array(32).fill(20),
  relayRoomId: new Uint8Array(32).fill(21),
  originOutpoint: new Uint8Array(36).fill(22),
  dealGameId: new Uint8Array(32).fill(23),
  chainGameId: new Uint8Array(32).fill(24),
  graphRoot: new Uint8Array(32).fill(25),
};
const exchange = encodeChainExchange({
  context,
  package: ChainExchangePackage.INVENTORY_READY,
  role: 1,
  artifact: new Uint8Array(64).fill(26),
});
const base64 = bytesToBase64(exchange);
assert.deepEqual(base64ToBytes(base64), exchange);
const decoded = decodeChainExchange(base64, context);
assert.equal(decoded.package, ChainExchangePackage.INVENTORY_READY);
assert.equal(decoded.role, 1);
assert.deepEqual(decoded.artifact, new Uint8Array(64).fill(26));
const lamportExchange = encodeChainExchange({
  context,
  package: ChainExchangePackage.LAMPORT_PUBLIC_BUNDLE,
  role: 1,
  artifact: Uint8Array.of(1),
});
assert.doesNotThrow(() => decodeChainExchange(lamportExchange, {
  ...context,
  graphRoot: new Uint8Array(32),
}));
const wrongContext = { ...context, graphRoot: new Uint8Array(32).fill(99) };
assert.throws(() => decodeChainExchange(exchange, wrongContext), /graphRoot differs/);
const relayIdMaterial = chainRelayMessageIdMaterial(base64, context.relayRoomId, alice);
assert.ok(relayIdMaterial.byteLength > exchange.byteLength);
assert.notDeepEqual(
  chainRelayMessageIdMaterial(base64, context.relayRoomId, alice),
  chainRelayMessageIdMaterial(base64, context.relayRoomId, bob),
  "relay ids are bound to the authenticated local identity",
);

const cardFrame = new Uint8Array(33);
cardFrame.set(new TextEncoder().encode("BP52CP01"));
cardFrame[8] = 0;
cardFrame.set([0, 12, 1, 2, 3, 4, 5, 0, 12, 13, 25], 9);
cardFrame[20] = 1;
cardFrame[21] = 0;
new DataView(cardFrame.buffer).setUint32(22, 100, true);
cardFrame[26] = 1;
cardFrame[27] = 1;
new DataView(cardFrame.buffer).setUint32(28, 90, true);
cardFrame[32] = 0;
const cards = decodeCardProjection(cardFrame);
assert.deepEqual(cards.localHole, [0, 12]);
assert.deepEqual(cards.board, [1, 2, 3, 4, 5]);
assert.deepEqual(cards.aliceHand, { subset: 0, score: 100 });
assert.equal(cards.outcome, 0);

// A completed flop must not let the adjacent local-hole bytes bleed into the
// unrevealed turn and river positions.  255 is the Rust projection's only
// missing-card sentinel and decodes to null for the UI placeholders.
const flopOnlyFrame = new Uint8Array(33);
flopOnlyFrame.set(new TextEncoder().encode("BP52CP01"));
flopOnlyFrame[8] = 1;
flopOnlyFrame.set([17, 22], 9); // Bob's 6♦ J♦ hole cards.
flopOnlyFrame.set([23, 35, 30, 255, 255], 11); // Q♦ J♥ 6♥, then missing turn/river.
flopOnlyFrame.fill(255, 16, 20);
flopOnlyFrame[32] = 255;
const flopOnly = decodeCardProjection(flopOnlyFrame);
assert.deepEqual(flopOnly.localHole, [17, 22]);
assert.deepEqual(flopOnly.board, [23, 35, 30, null, null]);
assert.equal(flopOnly.aliceHand, null);
assert.equal(flopOnly.bobHand, null);
assert.equal(flopOnly.outcome, null);

const statusFrame = new Uint8Array(79);
statusFrame.set(new TextEncoder().encode("BP52RS01"));
statusFrame.set([7, 1, 1, 1], 8);
statusFrame.fill(42, 12, 76);
statusFrame.set([3, 1, 0], 76);
const status = decodeRuntimeStatus(statusFrame);
assert.equal(status.phase, 7);
assert.equal(status.localRole, 1);
assert.equal(status.inventoryVerified, true);
assert.deepEqual(status.inventoryAttestation, new Uint8Array(64).fill(42));
assert.deepEqual(status.readyRoles, [0, 1]);
assert.equal(status.authorizationCached, true);
assert.equal(status.erasureCached, false);
const inconsistentStatus = statusFrame.slice();
inconsistentStatus[10] = 0;
assert.throws(() => decodeRuntimeStatus(inconsistentStatus), /inventory fields disagree/);

function acceptedSessionEventFrame(setupKind, statusTag, phase, bundle = new Uint8Array()) {
  const frame = new Uint8Array(15 + bundle.byteLength);
  frame.set(new TextEncoder().encode("BP52SE02"));
  frame.set([setupKind, statusTag, phase], 8);
  new DataView(frame.buffer).setUint32(11, bundle.byteLength, true);
  frame.set(bundle, 15);
  return frame;
}

const acceptedDescriptor = decodeAcceptedSessionEvent(acceptedSessionEventFrame(
  ChainSetupKind.DESCRIPTOR_SIGNATURE,
  0,
  3,
  Uint8Array.of(1, 2, 3),
));
assert.equal(acceptedDescriptor.applicable, true);
assert.equal(acceptedDescriptor.duplicate, false);
assert.deepEqual(acceptedDescriptor.localLamportBundle, Uint8Array.of(1, 2, 3));
assert.equal(acceptedDescriptor.verificationReceipt.byteLength, 0);

const acceptedOpening = decodeAcceptedSessionEvent(acceptedSessionEventFrame(
  ChainSetupKind.PREAUTHORIZATION_OPENING,
  0,
  6,
  Uint8Array.of(7, 8, 9),
));
assert.equal(acceptedOpening.localLamportBundle.byteLength, 0);
assert.deepEqual(acceptedOpening.verificationReceipt, Uint8Array.of(7, 8, 9));

const ignoredRuntimeEvent = decodeAcceptedSessionEvent(acceptedSessionEventFrame(
  ChainSetupKind.NOT_APPLICABLE,
  2,
  3,
));
assert.equal(ignoredRuntimeEvent.applicable, false);
assert.equal(ignoredRuntimeEvent.duplicate, false);
assert.throws(
  () => decodeAcceptedSessionEvent(acceptedSessionEventFrame(
    ChainSetupKind.LAMPORT_PUBLIC_BUNDLE,
    0,
    3,
    Uint8Array.of(1),
  )),
  /wrong setup kind/,
);
assert.throws(
  () => decodeAcceptedSessionEvent(acceptedSessionEventFrame(
    ChainSetupKind.PREAUTHORIZATION_OPENING,
    0,
    6,
  )),
  /wrong setup kind/,
);

const chainWasm = await readFile(new URL(
  "../../crates/bp52-relay-server/web/wasm/chain.wasm",
  import.meta.url,
));
const instantiated = await WebAssembly.instantiate(chainWasm, {});
const wasm = instantiated instanceof WebAssembly.Instance
  ? instantiated.exports
  : instantiated.instance.exports;
assert.equal(wasm.bp52_chain_abi_version(), 5);
assert.equal(wasm.bp52_chain_verifier_entropy_len, undefined);
assert.equal(wasm.bp52_chain_set_verifier_entropy_byte, undefined);
assert.doesNotThrow(() => wasm.bp52_chain_init(), "malformed init is a typed error, not a Wasm trap");
assert.equal(wasm.bp52_chain_init(), -3, "malformed init remains retryable before initialization");

console.log("CHAIN browser codecs: ok");
