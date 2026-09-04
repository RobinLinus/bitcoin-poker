import assert from "node:assert/strict";

import { serializeAsync } from "./serial-dispatch.js";

const events = [];
let releaseFirst;
const firstGate = new Promise((resolve) => { releaseFirst = resolve; });
const dispatch = serializeAsync(async (value) => {
  events.push(`start:${value}`);
  if (value === 1) await firstGate;
  events.push(`end:${value}`);
  if (value === 2) throw new Error("expected failure");
  return value;
});

const first = dispatch(1);
const second = dispatch(2);
const third = dispatch(3);
await Promise.resolve();
assert.deepEqual(events, ["start:1"], "later operations wait for the active mutation");

releaseFirst();
assert.equal(await first, 1);
await assert.rejects(second, /expected failure/);
assert.equal(await third, 3, "a failed operation does not poison the queue");
assert.deepEqual(events, [
  "start:1", "end:1",
  "start:2", "end:2",
  "start:3", "end:3",
]);

assert.throws(() => serializeAsync(null), /serialized handler is required/);

console.log("Worker serial dispatch tests ok");
