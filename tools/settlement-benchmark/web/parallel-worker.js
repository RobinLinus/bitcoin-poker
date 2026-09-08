import {wasmClient, joinBytes, hex} from "./wasm-client.js";
import {VerificationPool} from "/verification-pool.js";
import {PreparationCheckpointStore} from "/preparation-checkpoint-store.js";

function jobsFor(manifest) {
  const jobs = [], groups = [[], []], weights = [0, 0];
  const flush = role => {
    if (!groups[role].length) return;
    const indices = groups[role];
    const bytes = new Uint8Array(indices.length * 4), view = new DataView(bytes.buffer);
    indices.forEach((index, position) => view.setUint32(position * 4, index, true));
    jobs.push({role, count: indices.length, bytes}); groups[role] = []; weights[role] = 0;
  };
  for (let index = 0; index < manifest.length / 2; index++) {
    const role = manifest[index * 2], weight = manifest[index * 2 + 1] ? 64 : 1;
    if (weights[role] + weight > 512) flush(role);
    groups[role].push(index); weights[role] += weight;
  }
  flush(0); flush(1); return jobs;
}
function snapshotBatches(snapshot, manifest) {
  const view = new DataView(snapshot.buffer, snapshot.byteOffset, snapshot.byteLength);
  let offset = 12 + view.getUint32(8, true), previous = -1;
  const batches = [], groups = [[], []], sizes = [0, 0];
  const flush = role => { if (groups[role].length) { batches.push({role, bytes: joinBytes(...groups[role]), count: groups[role].length}); groups[role] = []; sizes[role] = 0; } };
  while (offset < snapshot.length) {
    if (offset + 8 > snapshot.length) throw new Error("Truncated snapshot");
    const index = view.getUint32(offset, true), length = view.getUint32(offset + 4, true), end = offset + 8 + length;
    if (index <= previous || index >= manifest.length / 2 || end > snapshot.length || ![64, 3412].includes(length)) throw new Error("Invalid snapshot entry");
    const role = 1 - manifest[index * 2];
    if (sizes[role] + end - offset > 64 * 1024) flush(role);
    groups[role].push(snapshot.slice(offset, end)); sizes[role] += end - offset; offset = end; previous = index;
  }
  flush(0); flush(1); return batches;
}
self.onmessage = async ({data: {full = true, workers = 4}}) => {
  let pool, owner, metadata = {full, workers, mode: "parallel"}, peakWasmBytes = 0;
  const started = performance.now(), timingsMs = {};
  const update = (phase, done = 0, total = 0) => {
    peakWasmBytes = Math.max(peakWasmBytes, (owner?.exports.memory.buffer.byteLength ?? 0) + (pool?.memoryBytes ?? 0));
    postMessage({type: "progress", ...metadata, phase, done, total, elapsedMs: performance.now() - started, timingsMs: {...timingsMs}, peakWasmBytes});
  };
  try {
    const wasm = await (await fetch("/benchmark.wasm")).arrayBuffer();
    const module = await WebAssembly.compile(wasm);
    metadata = {...metadata, wasmBytes: wasm.byteLength, wasmSha256: hex(new Uint8Array(await crypto.subtle.digest("SHA-256", wasm))), userAgent: navigator.userAgent, hardwareConcurrency: navigator.hardwareConcurrency, stackBytesPerWorker: 33554432};
    let phase, phaseStarted, importing = false;
    const instantiate = () => WebAssembly.instantiate(module, {benchmark: {now_ms: () => performance.now(), progress: (code, done, total) => {
      if (code !== phase) {
        if (phase) timingsMs[(importing ? "import_" : "") + {1: "dealerSetup", 2: "graphCompilation", 3: "transactionInventory"}[phase]] = performance.now() - phaseStarted;
        phase = code; phaseStarted = performance.now();
      }
      if (done === 0) update({1: "dealerSetup", 2: "graphCompilation", 3: "transactionInventory"}[code], done, total);
    }}});
    owner = wasmClient(await instantiate()); timingsMs.loadAndCompile = performance.now() - started;
    owner.call("tree_parallel_prepare", null, full ? 1 : 0);
    timingsMs.transactionInventory = performance.now() - phaseStarted;
    const key = crypto.getRandomValues(new Uint8Array(32)); owner.call("tree_parallel_key", key);
    const inventoryDigest = hex(new Uint8Array(owner.exports.memory.buffer, owner.exports.tree_inventory_digest_ptr(), 32));
    const inventory = owner.call("tree_parallel_inventory");
    const binding = hex(owner.call("tree_parallel_binding"));
    const manifest = owner.call("tree_parallel_manifest");
    const requests = manifest.length / 2;
    const revealPackages = manifest.filter((value, index) => index % 2 === 1 && value === 1).length;
    metadata = {...metadata, nodes: full ? 56132 : 26, requests, signatures: requests - revealPackages, revealPackages, adaptorSignatures: revealPackages * 52, inventoryBinding: binding, inventoryDigest};
    let stamp = performance.now(); update("workerInitialization");
    pool = new VerificationPool(new URL("./crypto-worker.js", import.meta.url), {count: workers});
    await pool.initialize(module, inventory, key); timingsMs.workerInitialization = performance.now() - stamp;
    stamp = performance.now(); let done = 0, responseBytes = 0;
    update("parallelCosigning", 0, requests);
    await Promise.all(jobsFor(manifest).map(async job => {
      const bytes = await pool.submit(job.role, "sign", job.bytes); responseBytes += bytes.byteLength - job.count * 8;
      const receipt = await pool.submit(1 - job.role, "verify", bytes);
      owner.call("tree_parallel_accept", receipt); done += job.count; update("parallelCosigning", done, requests);
    }));
    timingsMs.cosigning = performance.now() - stamp;
    const snapshot = owner.call("tree_parallel_snapshot");
    const checkpoint = owner.call("tree_parallel_checkpoint");
    const store = new PreparationCheckpointStore("poker-settlement-benchmark");
    stamp = performance.now(); update("persistCheckpoint");
    await store.save("latest", binding, joinBytes(key, checkpoint));
    timingsMs.checkpointPersistence = performance.now() - stamp;
    const initialSetupMs = performance.now() - started;
    const setupWasmBytes = owner.exports.memory.buffer.byteLength + pool.memoryBytes;
    const signingCpuMs = {...pool.timings, signMs: [...pool.timings.signMs], verifyMs: [...pool.timings.verifyMs]};
    update("setupComplete", requests, requests);

    stamp = performance.now(); update("localResume");
    const restored = wasmClient(await WebAssembly.instantiate(module, {benchmark: {now_ms: () => performance.now(), progress: () => {}}}));
    const cached = await store.load("latest", binding);
    const restoredBinding = hex(restored.call("tree_parallel_resume", cached));
    if (restoredBinding !== binding) throw new Error("Resume binding mismatch");
    if (hex(new Uint8Array(await crypto.subtle.digest("SHA-256", restored.call("tree_parallel_snapshot")))) !== hex(new Uint8Array(await crypto.subtle.digest("SHA-256", snapshot)))) throw new Error("Resume snapshot mismatch");
    timingsMs.localResume = performance.now() - stamp;
    peakWasmBytes = Math.max(peakWasmBytes, owner.exports.memory.buffer.byteLength + restored.exports.memory.buffer.byteLength + pool.memoryBytes);

    const mustReject = async (label, operation) => {
      try { await operation(); } catch { return; }
      throw new Error(`Accepted ${label}`);
    };
    const wrongKey = cached.slice(); wrongKey[0] ^= 1;
    await mustReject("wrong checkpoint key", () => restored.call("tree_parallel_resume", wrongKey));
    const badCheckpoint = cached.slice(); badCheckpoint[badCheckpoint.length - 1] ^= 1;
    await mustReject("altered checkpoint", () => restored.call("tree_parallel_resume", badCheckpoint));
    await mustReject("wrong checkpoint binding", () => store.load("latest", "wrong-binding"));
    class DamagedStore extends PreparationCheckpointStore {
      async read(name, id) {
        const record = await super.read(name, id);
        if (name === "checkpoints") {
          const ciphertext = new Uint8Array(record.ciphertext).slice(); ciphertext[ciphertext.length - 1] ^= 1;
          return {...record, ciphertext};
        }
        return record;
      }
    }
    class MissingKeyStore extends PreparationCheckpointStore {
      async read(name, id) { return name === "keys" ? undefined : super.read(name, id); }
    }
    await mustReject("tampered persisted ciphertext", () => new DamagedStore(store.name).load("latest", binding));
    await mustReject("missing local key", () => new MissingKeyStore(store.name).load("latest", binding));
    const checkpointFailureChecks = 5;

    // An untrusted public snapshot gets a freshly derived graph and full crypto verification.
    stamp = performance.now(); update("importInventory"); phase = undefined; importing = true;
    owner.call("tree_parallel_prepare", null, full ? 1 : 0); owner.call("tree_parallel_key", key);
    if (hex(owner.call("tree_parallel_binding")) !== binding) throw new Error("Import inventory mismatch");
    timingsMs.importInventory = performance.now() - stamp;
    timingsMs.import_transactionInventory = performance.now() - phaseStarted;
    stamp = performance.now(); done = 0;
    await Promise.all(snapshotBatches(snapshot, manifest).map(async job => {
      const receipt = await pool.submit(job.role, "verify", job.bytes);
      owner.call("tree_parallel_accept", receipt); done += job.count; update("importVerification", done, requests);
    }));
    timingsMs.importVerification = performance.now() - stamp;
    if (hex(new Uint8Array(await crypto.subtle.digest("SHA-256", owner.call("tree_parallel_snapshot")))) !== hex(new Uint8Array(await crypto.subtle.digest("SHA-256", snapshot)))) throw new Error("Import snapshot mismatch");
    update("complete", requests, requests);
    postMessage({type: "result", ok: true, ...metadata, initialSetupMs, setupWasmBytes, checkpointFailureChecks, localResumeMs: timingsMs.localResume, importRecoveryMs: timingsMs.importInventory + timingsMs.importVerification, setupTargetMet: initialSetupMs <= 30000, snapshotBytes: snapshot.byteLength, checkpointBytes: checkpoint.byteLength, responseBytes, timingsMs, signingCpuMs, peakWasmBytes, elapsedMs: performance.now() - started});
  } catch (error) {
    postMessage({type: "result", ok: false, ...metadata, error: String(error.stack ?? error), timingsMs, peakWasmBytes});
  } finally { pool?.close(); }
};
