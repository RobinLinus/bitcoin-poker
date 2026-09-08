import { Rpc } from "./wasm-client.js";
/** Local-role workers share a bounded execution queue; verification runs first. */
export class CryptoPool {
  constructor(count) {
    this.queue = [];
    this.closed = false;
    this.workers = Array.from({ length: count }, () => ({
      rpc: new Rpc(new URL("./crypto-worker.js", import.meta.url)),
      busy: false,
    }));
  }
  async initialize(args) {
    const results = await Promise.all(
      this.workers.map((w) => w.rpc.call("init", args)),
    );
    return results[0];
  }
  run(method, bytes, transfer=false) {
    if (this.closed) return Promise.reject(new Error("Crypto pool closed"));
    return new Promise((resolve, reject) => {
      const job = { method, bytes, transfer, resolve, reject };
      method === "verify" ? this.queue.unshift(job) : this.queue.push(job);
      this.dispatch();
    });
  }
  dispatch() {
    for (const worker of this.workers) {
      if (this.closed || worker.busy || !this.queue.length) continue;
      const job = this.queue.shift();
      worker.busy = true;
      worker.rpc
        .call(job.method, { bytes: job.bytes }, job.transfer ? [job.bytes.buffer] : [])
        .then(job.resolve, job.reject)
        .finally(() => {
          worker.busy = false;
          this.dispatch();
        });
    }
  }
  close() {
    this.closed = true;
    for (const w of this.workers) w.rpc.close();
    for (const j of this.queue.splice(0))
      j.reject(new Error("Crypto pool closed"));
  }
}
