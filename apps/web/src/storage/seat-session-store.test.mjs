import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("./seat-session-store.js", import.meta.url), "utf8");
const moduleUrl = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const {
  createSeatSessionStore,
  gameResumeHash,
  parseResumeRoute,
  pendingResumeHash,
  randomResumeHandle,
} = await import(moduleUrl);

class MemoryStorage {
  constructor() {
    this.values = new Map();
    this.reads = [];
  }

  getItem(key) {
    this.reads.push(key);
    return this.values.has(key) ? this.values.get(key) : null;
  }

  setItem(key, value) {
    this.values.set(key, String(value));
  }

  removeItem(key) {
    this.values.delete(key);
  }

}

const digest = "ab".repeat(32);
const gameId = "12".repeat(32);
const hostHandle = "34".repeat(32);
const guestHandle = "56".repeat(32);
const host = {
  gameId,
  playerToken: "78".repeat(32),
  inviteSecret: "9a".repeat(32),
  role: "alice",
  cursor: 17,
  joined: true,
  localReady: true,
  peerReady: true,
  nonceShare: "bc".repeat(32),
};
const guest = {
  gameId,
  playerToken: "de".repeat(32),
  role: "bob",
  cursor: 12,
  joined: true,
};

assert.deepEqual(parseResumeRoute(gameResumeHash(gameId, hostHandle)), {
  kind: "game",
  gameId,
  handle: hostHandle,
});
assert.deepEqual(parseResumeRoute(pendingResumeHash(guestHandle)), {
  kind: "pending",
  handle: guestHandle,
});
assert.equal(parseResumeRoute(`#/game/${gameId}`), null);
assert.equal(parseResumeRoute(`#/game/${gameId}/resume/${"z".repeat(64)}`), null);

const storage = new MemoryStorage();
const store = createSeatSessionStore({ deploymentDigestHex: digest, storage });
store.saveSession(hostHandle, host);
store.saveSession(guestHandle, guest);
assert.equal(store.loadSession(hostHandle, gameId).playerToken, host.playerToken);
assert.equal(store.loadSession(guestHandle, gameId).playerToken, guest.playerToken);
assert.notEqual(store.loadSession(hostHandle).playerToken, store.loadSession(guestHandle).playerToken);
storage.reads.length = 0;
assert.equal(store.loadSession("ff".repeat(32)), null);
assert.deepEqual(storage.reads, [
  `bp52.relay.session.v3/${digest}/${"ff".repeat(32)}`,
]);
assert.throws(() => store.loadSession(hostHandle, "00".repeat(32)), /does not match/);

const pending = {
  kind: "join",
  gameId,
  playerToken: guest.playerToken,
  inviteSecret: "9a".repeat(32),
  role: "bob",
  cursor: 0,
};
store.savePending(guestHandle, pending);
assert.deepEqual(store.loadPending(guestHandle), {
  ...pending,
  deploymentDigestHex: digest,
});
store.removePending(guestHandle);
assert.equal(store.loadPending(guestHandle), null);

const deterministicCrypto = {
  getRandomValues(bytes) {
    bytes.fill(0xa5);
    return bytes;
  },
};
assert.equal(randomResumeHandle(deterministicCrypto), "a5".repeat(32));
assert.doesNotMatch(source, /SeatRecoveryCode|bp52-seat-v/u);

console.log("durable resume-store tests ok");
