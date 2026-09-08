import test from "node:test";
import assert from "node:assert/strict";
import { saveCheckpointParts, loadCheckpointParts } from "./checkpoint-parts.js";

function fixture() {
  const saved = new Map(), calls = [];
  const store = {
    async save(id, binding, value) { saved.set(id, { binding, value: value.slice() }); },
    async load(id, binding) {
      const value = saved.get(id);
      if (!value || value.binding !== binding) throw new Error("missing artifact");
      return value.value.slice();
    },
  };
  const wasm = { checkpointPartsVersion: 1, call(op) {
    calls.push(op);
    return Uint8Array.of(...(op === 51 ? [3, 4] : op === 50 ? [1, 2] : [1, 2, 3, 4]));
  } };
  return { saved, calls, store, wasm };
}
test("moves export only the journal and retain one immutable artifact", async () => {
  const f = fixture(), record = { prepared: true };
  await saveCheckpointParts(f.wasm, f.store, "room", record);
  const first = structuredClone(record);
  for (let i = 0; i < 10; i++) await saveCheckpointParts(f.wasm, f.store, "room", record);
  assert.equal(f.calls.filter((op) => op === 51).length, 1);
  assert.equal(f.calls.filter((op) => op === 16).length, 0);
  assert.equal(f.saved.size, 1);
  assert.deepEqual(record, first);
  assert.deepEqual(await loadCheckpointParts(f.store, "room", record), Uint8Array.of(1, 2, 3, 4));
});
test("artifact write failure leaves the previous journal reference intact", async () => {
  const f = fixture(), record = { prepared: true, checkpoint: "AQI=" };
  f.store.save = async () => { throw new Error("disk full"); };
  await assert.rejects(saveCheckpointParts(f.wasm, f.store, "room", record), /disk full/);
  assert.deepEqual(record, { prepared: true, checkpoint: "AQI=" });
});
test("lost or altered artifacts fail closed on reload", async () => {
  const f = fixture(), record = { prepared: true };
  await saveCheckpointParts(f.wasm, f.store, "room", record);
  f.saved.values().next().value.value[0] ^= 1;
  await assert.rejects(loadCheckpointParts(f.store, "room", record), /integrity/);
  f.saved.clear();
  await assert.rejects(loadCheckpointParts(f.store, "room", record), /missing/);
});
test("unprepared journals and old pinned engines remain restorable", async () => {
  const f = fixture(), record = {};
  await saveCheckpointParts(f.wasm, f.store, "room", record);
  assert.equal(f.saved.size, 0);
  assert.deepEqual(await loadCheckpointParts(f.store, "room", record), Uint8Array.of(1, 2));
  f.wasm.checkpointPartsVersion = 0;
  await saveCheckpointParts(f.wasm, f.store, "room", record);
  assert.equal(record.checkpointParts, undefined);
  assert.deepEqual(await loadCheckpointParts(f.store, "room", record), Uint8Array.of(1, 2, 3, 4));
});
test("prepared journal cannot silently omit its artifact", async () => {
  const f = fixture();
  await assert.rejects(loadCheckpointParts(f.store, "room", {
    prepared: true, checkpointParts: { version: 1, journal: "AQI=", artifact: null },
  }), /reference missing/);
});
