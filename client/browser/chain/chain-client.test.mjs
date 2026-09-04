import assert from "node:assert/strict";

import { BrowserChainWorker } from "./chain-client.js";

class HungWorker {
  constructor() {
    this.listeners = new Map();
    this.messages = [];
    this.terminated = false;
  }

  addEventListener(kind, listener) {
    this.listeners.set(kind, listener);
  }

  postMessage(message) {
    this.messages.push(message);
  }

  terminate() {
    this.terminated = true;
  }
}

const hung = new HungWorker();
const worker = new BrowserChainWorker({
  workerFactory: () => hung,
  transportRole: "alice",
  chainExchangeKind: "chain.exchange.v1",
  timeoutMs: 15 * 60 * 1_000,
});

const outstanding = worker.status();
const rejected = assert.rejects(outstanding, /cleared/);
await worker.clear();
await rejected;

assert.equal(hung.terminated, true, "cancellation terminates a wedged Worker immediately");
assert.equal(hung.messages.at(-1)?.type, "clear", "zeroization remains best effort");
await assert.rejects(worker.status(), /closed/);

console.log("CHAIN Worker cancellation tests ok");
