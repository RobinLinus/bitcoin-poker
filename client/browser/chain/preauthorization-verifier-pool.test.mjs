import assert from "node:assert/strict";
import test from "node:test";

import {
  generateLamportBatches,
  generatePreauthorizationBatches,
  preauthorizationWorkerCount,
  verifyPreauthorizationBatches,
} from "./preauthorization-verifier-pool.js";

class FakeWorker {
  constructor(verifiedCount) {
    this.verifiedCount = verifiedCount;
    this.listeners = new Map();
    this.terminated = false;
  }

  addEventListener(type, listener) {
    this.listeners.set(type, listener);
  }

  postMessage(message) {
    if (message.type === "verify") {
      queueMicrotask(() => this.listeners.get("message")?.({
        data: { id: message.id, ok: true, verifiedCount: this.verifiedCount },
      }));
    }
    if (message.type === "generate") {
      queueMicrotask(() => this.listeners.get("message")?.({
        data: { id: message.id, ok: true, result: Uint8Array.of(this.verifiedCount) },
      }));
    }
    if (message.type === "generate-lamport") {
      queueMicrotask(() => this.listeners.get("message")?.({
        data: { id: message.id, ok: true, result: Uint8Array.of(this.verifiedCount) },
      }));
    }
  }

  terminate() {
    this.terminated = true;
  }
}

test("verification pool reserves half the logical CPUs and stays bounded", () => {
  assert.equal(preauthorizationWorkerCount(undefined), 2);
  assert.equal(preauthorizationWorkerCount(1), 1);
  assert.equal(preauthorizationWorkerCount(8), 4);
  assert.equal(preauthorizationWorkerCount(64), 8);
});

test("verification pool runs every independent batch and checks the exact total", async () => {
  const module = new WebAssembly.Module(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
  const workers = [];
  const counts = [2, 3, 4];
  const verified = await verifyPreauthorizationBatches({
    wasmModule: module,
    batches: counts.map((count) => new Uint8Array(count)),
    expectedTotal: 9,
    workerFactory: () => {
      const worker = new FakeWorker(counts[workers.length]);
      workers.push(worker);
      return worker;
    },
  });
  assert.equal(verified, 9);
  assert.ok(workers.every((worker) => worker.terminated));
});

test("verification pool fails closed when workers do not cover the bound total", async () => {
  const module = new WebAssembly.Module(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
  await assert.rejects(
    verifyPreauthorizationBatches({
      wasmModule: module,
      batches: [new Uint8Array(1)],
      expectedTotal: 2,
      workerFactory: () => new FakeWorker(1),
    }),
    /differs from the bound opening/,
  );
});

test("generation pool preserves shard order and terminates secret Workers", async () => {
  const module = new WebAssembly.Module(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
  const workers = [];
  const results = await generatePreauthorizationBatches({
    wasmModule: module,
    batches: [new Uint8Array(1), new Uint8Array(1), new Uint8Array(1)],
    workerFactory: () => {
      const worker = new FakeWorker(workers.length + 1);
      workers.push(worker);
      return worker;
    },
  });
  assert.deepEqual(results.map((result) => result[0]), [1, 2, 3]);
  assert.ok(workers.every((worker) => worker.terminated));
});

test("Lamport pool preserves shard order and terminates secret Workers", async () => {
  const module = new WebAssembly.Module(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0));
  const workers = [];
  const results = await generateLamportBatches({
    wasmModule: module,
    batches: [new Uint8Array(1), new Uint8Array(1), new Uint8Array(1)],
    workerFactory: () => {
      const worker = new FakeWorker(workers.length + 1);
      workers.push(worker);
      return worker;
    },
  });
  assert.deepEqual(results.map((result) => result[0]), [1, 2, 3]);
  assert.ok(workers.every((worker) => worker.terminated));
});
