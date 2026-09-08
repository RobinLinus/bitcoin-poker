/** Bounded role-owned workers. Verification is prioritized over further signing. */
export class VerificationPool {
  constructor(url, {count = 4, createWorker = url => new Worker(url, {type: "module"})} = {}) {
    if (![2, 4, 8].includes(count)) throw new Error("Pool size must be 2, 4 or 8");
    this.queue = [[], []]; this.sequence = 0; this.closed = false;
    this.timings = {signMs: [0, 0], verifyMs: [0, 0]};
    this.workers = Array.from({length: count}, (_, index) => {
      const state = {worker: createWorker(url), role: index % 2, job: null, memoryBytes: 0};
      state.worker.onmessage = ({data}) => {
        const job = state.job;
        if (!job || data.id !== job.id) { this.fail(new Error("Unexpected worker response")); return; }
        state.job = null;
        if (data.error) { job.reject(new Error(data.error)); this.fail(new Error(data.error)); return; }
        state.memoryBytes = Math.max(state.memoryBytes, data.memoryBytes ?? 0);
        if (job.mode === "sign" || job.mode === "verify") this.timings[`${job.mode}Ms`][state.role] += data.elapsedMs;
        job.resolve(data.bytes); this.dispatch();
      };
      state.worker.onerror = event => this.fail(new Error(event.message));
      return state;
    });
  }
  async initialize(module, inventory, key) {
    await Promise.all(this.workers.map(state => new Promise((resolve, reject) => {
      state.job = {id: ++this.sequence, mode: "init", resolve, reject};
      state.worker.postMessage({id: state.job.id, mode: "init", role: state.role, module, inventory, key});
    })));
  }
  submit(role, mode, bytes) {
    if (this.closed || ![0, 1].includes(role) || !["sign", "verify"].includes(mode)) return Promise.reject(new Error("Invalid or closed pool"));
    return new Promise((resolve, reject) => {
      const job = {id: ++this.sequence, role, mode, bytes, resolve, reject};
      if (mode === "verify") this.queue[role].unshift(job); else this.queue[role].push(job);
      this.dispatch();
    });
  }
  dispatch() {
    if (this.closed) return;
    for (const state of this.workers) {
      if (state.job) continue;
      const job = this.queue[state.role].shift();
      if (!job) continue;
      state.job = job;
      state.worker.postMessage({id: job.id, mode: job.mode, bytes: job.bytes}, [job.bytes.buffer]);
    }
  }
  get memoryBytes() { return this.workers.reduce((sum, state) => sum + state.memoryBytes, 0); }
  fail(error) {
    if (this.closed) return;
    this.closed = true;
    for (const state of this.workers) { state.job?.reject(error); state.job = null; state.worker.terminate(); }
    for (const queue of this.queue) for (const job of queue.splice(0)) job.reject(error);
  }
  close() { this.fail(new Error("Worker pool closed")); }
}
