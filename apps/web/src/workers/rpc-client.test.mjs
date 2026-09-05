import assert from "node:assert/strict";

import { WorkerRpcClient } from "./rpc-client.js";

class FakeWorker {
  constructor() {
    this.listeners = { message: [], error: [] };
    this.sent = [];
    this.terminated = false;
    this.throwOnPost = false;
  }

  addEventListener(type, listener) {
    this.listeners[type].push(listener);
  }

  postMessage(message, transfer = []) {
    if (this.throwOnPost) throw new Error("post failed");
    this.sent.push({ message, transfer });
  }

  terminate() {
    this.terminated = true;
  }

  emit(type, event) {
    for (const listener of this.listeners[type]) listener(event);
  }
}

const worker = new FakeWorker();
const rpc = new WorkerRpcClient(worker, { timeoutMs: 100 });
const transferable = new ArrayBuffer(4);
const first = rpc.request("first", { value: 7 }, { transfer: [transferable] });
assert.equal(worker.sent[0].message.type, "first");
assert.equal(worker.sent[0].message.value, 7);
assert.equal(worker.sent[0].transfer[0], transferable);
worker.emit("message", { data: { id: worker.sent[0].message.id, ok: true, answer: 8 } });
assert.equal((await first).answer, 8);

const protectedCorrelation = rpc.request("authoritative", { id: 999, type: "shadowed" });
assert.notEqual(worker.sent.at(-1).message.id, 999);
assert.equal(worker.sent.at(-1).message.type, "authoritative");
worker.emit("message", {
  data: { id: worker.sent.at(-1).message.id, ok: true },
});
await protectedCorrelation;

const rejected = rpc.request("rejected");
const rejectedId = worker.sent.at(-1).message.id;
worker.emit("message", { data: { id: rejectedId, ok: false, error: "bad request" } });
await assert.rejects(rejected, /bad request/);

// Unknown and duplicate response ids cannot resolve an unrelated request.
const pending = rpc.request("pending");
const pendingId = worker.sent.at(-1).message.id;
worker.emit("message", { data: { id: pendingId + 100, ok: true } });
worker.emit("message", { data: { id: pendingId, ok: true, done: true } });
assert.equal((await pending).done, true);
worker.emit("message", { data: { id: pendingId, ok: false, error: "late duplicate" } });

const workerFailure = rpc.request("will-fail");
worker.emit("error", { error: new Error("worker crashed") });
await assert.rejects(workerFailure, /worker crashed/);

const wedged = rpc.request("wedged");
const cancelled = assert.rejects(wedged, /cancelled/);
await rpc.close();
await cancelled;
assert.equal(worker.sent.at(-1).message.type, "clear");
assert.equal(worker.terminated, true);
assert.equal(rpc.isClosed, true);
await assert.rejects(rpc.request("after-close"), /closed/);

const timeoutWorker = new FakeWorker();
const timeoutRpc = new WorkerRpcClient(timeoutWorker, { timeoutMs: 5 });
await assert.rejects(timeoutRpc.request("slow"), /timed out/);
await timeoutRpc.close();

const throwingWorker = new FakeWorker();
const throwingRpc = new WorkerRpcClient(throwingWorker);
throwingWorker.throwOnPost = true;
await assert.rejects(throwingRpc.request("post"), /post failed/);
// Closing remains authoritative even when the zeroization notification throws.
await throwingRpc.close();
assert.equal(throwingWorker.terminated, true);

process.stdout.write("generic Worker RPC transport tests ok\n");
