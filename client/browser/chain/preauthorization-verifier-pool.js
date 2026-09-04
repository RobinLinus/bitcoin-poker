import { WorkerRpcClient } from "../worker/rpc-client.js";

const MAX_WORKERS = 8;

/** Reserve half the logical CPUs for the other player and browser work. */
export function preauthorizationWorkerCount(hardwareConcurrency) {
  const logical = Number.isSafeInteger(hardwareConcurrency) && hardwareConcurrency > 0
    ? hardwareConcurrency
    : 4;
  return Math.max(1, Math.min(MAX_WORKERS, Math.floor(logical / 2)));
}

/** Verify independent signature batches concurrently in disposable Workers. */
export async function verifyPreauthorizationBatches({
  wasmModule,
  batches,
  expectedTotal,
  workerFactory = (url) => new Worker(url, { type: "module", name: "bp52-preauth-verify" }),
}) {
  if (!(wasmModule instanceof WebAssembly.Module)) {
    throw new Error("preauthorization verification requires a compiled Wasm module");
  }
  if (!Array.isArray(batches) || batches.length === 0 || batches.length > MAX_WORKERS) {
    throw new Error("preauthorization verification batches are out of bounds");
  }
  if (!Number.isSafeInteger(expectedTotal) || expectedTotal < batches.length) {
    throw new Error("preauthorization verification total is invalid");
  }
  const clients = batches.map(() => new WorkerRpcClient(
    workerFactory(new URL("./preauthorization-verifier-worker.js", import.meta.url)),
    {
      timeoutMs: 15 * 60 * 1_000,
      closedError: "preauthorization verifier is closed",
      cancelledError: "preauthorization verifier was cancelled",
      timeoutError: () => "preauthorization verification timed out",
      rejectedError: "preauthorization verifier rejected a batch",
      workerError: "preauthorization verifier failed",
    },
  ));
  try {
    const results = await Promise.all(clients.map((client, index) => {
      const batch = batches[index];
      return client.request("verify", { wasmModule, batch }, { transfer: [batch.buffer] });
    }));
    const verifiedTotal = results.reduce((total, result) => total + result.verifiedCount, 0);
    if (verifiedTotal !== expectedTotal) {
      throw new Error("preauthorization verifier count differs from the bound opening");
    }
    return verifiedTotal;
  } finally {
    await Promise.all(clients.map((client) => client.close()));
  }
}

/** Generate independent local signature shards in disposable secret Workers. */
export async function generatePreauthorizationBatches({
  wasmModule,
  batches,
  workerFactory = (url) => new Worker(url, { type: "module", name: "bp52-preauth-sign" }),
}) {
  if (!(wasmModule instanceof WebAssembly.Module)) {
    throw new Error("preauthorization generation requires a compiled Wasm module");
  }
  if (!Array.isArray(batches) || batches.length === 0 || batches.length > MAX_WORKERS) {
    throw new Error("preauthorization generation batches are out of bounds");
  }
  const clients = batches.map(() => new WorkerRpcClient(
    workerFactory(new URL("./preauthorization-verifier-worker.js", import.meta.url)),
    {
      timeoutMs: 15 * 60 * 1_000,
      closedError: "preauthorization signer is closed",
      cancelledError: "preauthorization signer was cancelled",
      timeoutError: () => "preauthorization generation timed out",
      rejectedError: "preauthorization signer rejected a batch",
      workerError: "preauthorization signer failed",
    },
  ));
  try {
    const responses = await Promise.all(clients.map((client, index) => {
      const batch = batches[index];
      return client.request("generate", { wasmModule, batch }, { transfer: [batch.buffer] });
    }));
    return responses.map(({ result }) => {
      if (!(result instanceof Uint8Array) || result.byteLength === 0) {
        throw new Error("preauthorization signer returned an invalid result");
      }
      return result;
    });
  } finally {
    await Promise.all(clients.map((client) => client.close()));
  }
}

/** Generate independent Lamport public-key shards in disposable secret Workers. */
export async function generateLamportBatches({
  wasmModule,
  batches,
  workerFactory = (url) => new Worker(url, { type: "module", name: "bp52-lamport-generate" }),
}) {
  if (!(wasmModule instanceof WebAssembly.Module)) {
    throw new Error("Lamport generation requires a compiled Wasm module");
  }
  if (!Array.isArray(batches) || batches.length === 0 || batches.length > MAX_WORKERS) {
    throw new Error("Lamport generation batches are out of bounds");
  }
  const clients = batches.map(() => new WorkerRpcClient(
    workerFactory(new URL("./preauthorization-verifier-worker.js", import.meta.url)),
    {
      timeoutMs: 15 * 60 * 1_000,
      closedError: "Lamport generator is closed",
      cancelledError: "Lamport generator was cancelled",
      timeoutError: () => "Lamport generation timed out",
      rejectedError: "Lamport generator rejected a batch",
      workerError: "Lamport generator failed",
    },
  ));
  try {
    const responses = await Promise.all(clients.map((client, index) => {
      const batch = batches[index];
      return client.request("generate-lamport", { wasmModule, batch }, { transfer: [batch.buffer] });
    }));
    return responses.map(({ result }) => {
      if (!(result instanceof Uint8Array) || result.byteLength === 0) {
        throw new Error("Lamport generator returned an invalid result");
      }
      return result;
    });
  } finally {
    await Promise.all(clients.map((client) => client.close()));
  }
}
