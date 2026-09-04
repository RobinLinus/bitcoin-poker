import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { Worker } from "node:worker_threads";

const artifact = new URL(
  process.argv[2] ?? "../../target/wasm32-unknown-unknown/release/bp52_browser_game_wasm.wasm",
  import.meta.url,
);
const wasm = await readFile(artifact);

function hash(bytes) {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

function taggedHash(tag, message) {
  const tagHash = hash(Buffer.from(tag, "utf8"));
  return hash(Buffer.concat([tagHash, tagHash, message]));
}

function hex(value) {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

const networkId = hex("e3bc9730af93197380e11b43ca00d6b516d83321f46b8b9f53a22a4fae89e680");
const relayRoomId = new Uint8Array(32).fill(0x05);
const dealSessionNonce = new Uint8Array(32).fill(0x04);
const aliceCompressed = hex("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f");
const bobCompressed = hex("024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766");
const contextCommitment = taggedHash(
  "BP52/origin-context/v1",
  Buffer.concat([networkId, relayRoomId, dealSessionNonce]),
);
const originWitnessScript = new Uint8Array(104);
originWitnessScript[0] = 32;
originWitnessScript.set(contextCommitment, 1);
originWitnessScript[33] = 0x75;
originWitnessScript[34] = 33;
originWitnessScript.set(aliceCompressed, 35);
originWitnessScript[68] = 0xad;
originWitnessScript[69] = 33;
originWitnessScript.set(bobCompressed, 70);
originWitnessScript[103] = 0xac;

const config = {
  protocolProfile: 2,
  bitcoinNetwork: 2,
  networkId,
  originOutpoint: {
    displayTxid: Uint8Array.from({ length: 32 }, (_, index) => index),
    vout: 0,
  },
  relayRoomId,
  dealSessionNonce,
  identityKeys: [aliceCompressed.slice(1), bobCompressed.slice(1)],
  localRole: 0,
  originConfirmationDepth: 1,
  gameplayConfirmationDepth: 1,
  button: 0,
  revealOrder: [0, 1, 0],
  splitRemainderRecipient: 1,
  originValueSat: 53_500n,
  activationFeeSat: 500n,
  originWitnessScript,
};
const expectedDealGameId = hex(
  "9f084f6769c3bc90a6c5b410ab0638d8a6fc3ba322a62088c3afa419ed771971",
);

class SessionWorker {
  constructor() {
    this.worker = new Worker(new URL("./node-game-worker.mjs", import.meta.url), {
      type: "module",
    });
    this.nextId = 1;
    this.pending = new Map();
    this.worker.on("message", (message) => {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.ok) pending.resolve(message);
      else pending.reject(new Error(message.error));
    });
    this.worker.on("error", (error) => {
      for (const pending of this.pending.values()) pending.reject(error);
      this.pending.clear();
    });
  }

  request(type, fields = {}) {
    const id = this.nextId;
    this.nextId += 1;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, type, ...fields });
    });
  }

  async stop() {
    try {
      await this.request("clear");
    } finally {
      await this.worker.terminate();
    }
  }
}

const first = new SessionWorker();
const initialized = await first.request("init", { wasm, config });
if (initialized.projection.status.phase !== 0) {
  throw new Error("fresh reducer did not await the origin");
}
if (!Buffer.from(initialized.projection.status.dealGameId).equals(Buffer.from(expectedDealGameId))) {
  throw new Error("reducer projection returned the wrong canonical DEAL game id");
}
if (initialized.projection.intents.length !== 1 || initialized.projection.intents[0].tag !== 0) {
  throw new Error("fresh reducer did not request the exact origin observation");
}
const before = new Uint8Array((await first.request("snapshot")).snapshot);

// A canonical tip event is structurally valid but invalid before origin
// confirmation. The reducer must reject it without changing the journal.
const prematureTip = new Uint8Array(1 + 32 + 4 + 32);
const tipView = new DataView(prematureTip.buffer);
prematureTip[0] = 12;
prematureTip.set(networkId, 1);
tipView.setUint32(33, 1, true);
prematureTip.fill(0x44, 37);
let rejected = false;
try {
  await first.request("apply-event", { source: 1, event: prematureTip });
} catch (error) {
  rejected = /Exchange events require the authenticated opaque ingress/.test(error.message);
}
if (!rejected) {
  throw new Error("relay-sourced chain fact was not fail-closed");
}
rejected = false;
try {
  await first.request("apply-event", { source: 0, event: prematureTip });
} catch (error) {
  rejected = /unexpected session event/.test(error.message);
}
if (!rejected) {
  throw new Error("premature authenticated tip event was not fail-closed");
}
const after = new Uint8Array((await first.request("snapshot")).snapshot);
if (!Buffer.from(before).equals(Buffer.from(after))) {
  throw new Error("rejected event mutated the canonical snapshot");
}
await first.stop();

const second = new SessionWorker();
const replayed = await second.request("replay", { wasm, config, snapshot: after });
if (replayed.projection.status.phase !== 0 || replayed.projection.intents[0]?.tag !== 0) {
  throw new Error("replayed reducer projection differs from the original");
}
if (!Buffer.from(replayed.projection.status.dealGameId).equals(Buffer.from(expectedDealGameId))) {
  throw new Error("replayed projection changed the canonical DEAL game id");
}
const roundTrip = new Uint8Array((await second.request("snapshot")).snapshot);
if (!Buffer.from(after).equals(Buffer.from(roundTrip))) {
  throw new Error("snapshot bytes changed across replay");
}
const wasmMiB = replayed.metrics.wasmMiB;
await second.stop();

process.stdout.write(
  `game-session Wasm smoke/replay ok: snapshot=${roundTrip.byteLength} bytes, wasm=${wasmMiB.toFixed(2)} MiB\n`,
);
