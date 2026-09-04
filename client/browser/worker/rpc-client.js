const DEFAULT_TIMEOUT_MS = 15 * 60 * 1_000;

/**
 * Generic request/response transport for a dedicated browser Worker.
 *
 * Protocol-specific clients own message contents. This class only owns ids,
 * transfer lists, timeouts, cancellation, and fan-out rejection.
 */
export class WorkerRpcClient {
  constructor(worker, {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    closedError = "protocol Worker is closed",
    cancelledError = "protocol Worker was cancelled",
    timeoutError = (type) => `${type} timed out in the protocol Worker`,
    rejectedError = "protocol Worker rejected the request",
    workerError = "protocol Worker failed",
  } = {}) {
    if (!worker || typeof worker.postMessage !== "function" ||
        typeof worker.addEventListener !== "function" ||
        typeof worker.terminate !== "function") {
      throw new Error("WorkerRpcClient requires a Worker-compatible transport");
    }
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
      throw new Error("WorkerRpcClient timeout must be a positive integer");
    }
    this.worker = worker;
    this.timeoutMs = timeoutMs;
    this.messages = { closedError, cancelledError, timeoutError, rejectedError, workerError };
    this.nextId = 1;
    this.pending = new Map();
    this.closed = false;
    worker.addEventListener("message", (event) => this.#receive(event.data));
    worker.addEventListener("error", (event) => {
      const error = event.error instanceof Error
        ? event.error
        : new Error(event.message || this.messages.workerError);
      this.#rejectAll(error);
    });
  }

  request(type, fields = {}, { transfer = [], timeoutMs = this.timeoutMs } = {}) {
    if (this.closed) return Promise.reject(new Error(this.messages.closedError));
    if (typeof type !== "string" || type.length === 0) {
      return Promise.reject(new Error("Worker request type is required"));
    }
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
      return Promise.reject(new Error("Worker request timeout must be a positive integer"));
    }
    if (!Array.isArray(transfer)) {
      return Promise.reject(new Error("Worker request transfer list must be an array"));
    }
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(this.messages.timeoutError(type)));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer, type });
      try {
        // Correlation fields are transport-owned and cannot be shadowed by a
        // protocol payload.
        this.worker.postMessage({ ...fields, id, type }, transfer);
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error);
      }
    });
  }

  get isClosed() {
    return this.closed;
  }

  /** Best-effort zeroization notification followed by authoritative termination. */
  async close({ notifyType = "clear" } = {}) {
    if (this.closed) return;
    this.closed = true;
    try {
      this.worker.postMessage({ id: this.nextId++, type: notifyType });
    } catch (_) {
      // Termination remains authoritative for a failed or wedged Worker.
    }
    try {
      this.worker.terminate();
    } finally {
      this.#rejectAll(new Error(this.messages.cancelledError));
    }
  }

  #receive(message) {
    const pending = this.pending.get(message?.id);
    if (!pending) return;
    this.pending.delete(message.id);
    clearTimeout(pending.timer);
    if (message.ok) pending.resolve(message);
    else pending.reject(new Error(
      `${pending.type}: ${message.error || this.messages.rejectedError}`,
    ));
  }

  #rejectAll(error) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }
}
