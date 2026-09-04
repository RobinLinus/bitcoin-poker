import assert from "node:assert/strict";
import test from "node:test";

import { proofExecutionMode, scheduleProofSlots } from "./proof-schedule.js";

test("only the initial attempt pays for replayed parallel workers", () => {
  assert.equal(proofExecutionMode(0), "parallel");
  assert.equal(proofExecutionMode(1), "resident");
  assert.equal(proofExecutionMode(42), "resident");
  assert.throws(() => proofExecutionMode(-1), /non-negative safe integer/u);
});

test("proof scheduling reserves browser capacity and covers each slot once", () => {
  assert.deepEqual(scheduleProofSlots(10), [[0, 2, 4, 6, 8], [1, 3, 5, 7]]);
});

test("proof scheduling is bounded on small, missing, and oversized hosts", () => {
  assert.deepEqual(scheduleProofSlots(1, 3), [[0, 1, 2]]);
  assert.deepEqual(scheduleProofSlots(undefined, 3), [[0, 2], [1]]);
  assert.deepEqual(scheduleProofSlots(64, 3), [[0, 2], [1]]);
});

test("proof scheduling rejects invalid slot counts", () => {
  assert.throws(() => scheduleProofSlots(8, 0), /positive safe integer/u);
  assert.throws(() => scheduleProofSlots(8, 1.5), /positive safe integer/u);
});
