import {acceptDiagnostic,traceOperation} from './diagnostics.js';
import { loadWasmBytes } from "../wasm/loader.js";
const encoder = new TextEncoder(),
  decoder = new TextDecoder();
export const hex = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
export function unhex(value) {
  if (typeof value !== "string" || value.length % 2 || /[^0-9a-f]/i.test(value))
    throw new Error("Invalid hex");
  return Uint8Array.from(value.match(/../g) ?? [], (b) => parseInt(b, 16));
}
export const encode = (value) => encoder.encode(JSON.stringify(value));
export const decode = (bytes) => JSON.parse(decoder.decode(bytes));
export async function client(module) {
  const { exports: e } = await WebAssembly.instantiate(module, {});
  return {
    checkpointPartsVersion: e.session_checkpoint_parts_version?.() ?? 0,
    call(op, bytes = new Uint8Array()) {
      const p = e.session_input(bytes.length);
      if (!p && bytes.length) throw new Error("Input too large");
      new Uint8Array(e.memory.buffer, p, bytes.length).set(bytes);
      if (!e.session_call(op))
        throw new Error(
          decoder.decode(
            new Uint8Array(
              e.memory.buffer,
              e.session_error_ptr(),
              e.session_error_len(),
            ),
          ),
        );
      return new Uint8Array(
        e.memory.buffer,
        e.session_output_ptr(),
        e.session_output_len(),
      ).slice();
    },
    get memoryBytes() {
      return e.memory.buffer.byteLength;
    },
  };
}
export async function moduleBytes() {
  return new Uint8Array(await loadWasmBytes("session"));
}
// Share verified, compiled public code across the table and wallet workers.
// Worker instances and their private memories remain independent.
let enginePromise;
export function sessionEngine() {
  return enginePromise ??= (async()=>{
    const raw=await moduleBytes();
    const [module,digest]=await Promise.all([WebAssembly.compile(raw),crypto.subtle.digest('SHA-256',raw)]);
    return {module,digest:hex(new Uint8Array(digest))};
  })().catch(error=>{enginePromise=undefined;throw error;});
}
let idleChannelWorker;
export function preloadChannelWorker() {
  if(!idleChannelWorker || idleChannelWorker.closed)idleChannelWorker=new Rpc(new URL('./channel-worker.js',import.meta.url));
}
export function channelWorker() {
  const worker=idleChannelWorker&&!idleChannelWorker.closed?idleChannelWorker:new Rpc(new URL('./channel-worker.js',import.meta.url));
  idleChannelWorker=undefined;return worker;
}
export async function workerFailure(url,message) {
  // A deployment removes the old versioned URLs. Recreating a worker from that
  // same tab cannot repair a missing module; ask for a page reload explicitly.
  // Never substitute code from another app version into a running session.
  const source=new URL(url,import.meta.url);
  if(/^https?:$/.test(source.protocol)&&/^\/assets\/[a-f0-9]{64}\//.test(source.pathname)) {
    try {
      const response=await fetch(source,{method:'HEAD',cache:'no-store',signal:AbortSignal.timeout(2000)});
      if(response.status===404)return new Error('Worker app file unavailable. Reload this tab.');
    } catch { /* Preserve the original worker failure if the probe is offline. */ }
  }
  return new Error(`Worker failed: ${source.pathname.split('/').at(-1)}: ${message || 'Worker could not start or stopped unexpectedly'}`);
}
export class Rpc {
  constructor(url) {
    this.worker = new Worker(url, { type: "module" });
    this.jobs = new Map();
    this.diagnostics={worker:String(url).split("/").at(-1)};
    this.id = 0;
    this.worker.onmessage = ({ data: d }) => {
      if(d.event==='diagnostic') {acceptDiagnostic({...this.diagnostics,...d.entry});return;}
      if (d.event) {
        this.onprogress?.(d);
        return;
      }
      const j = this.jobs.get(d.id);
      if (!j) return;
      this.jobs.delete(d.id);
      if (Object.hasOwn(d, "error")) j.reject(new Error(d.error || "Worker request failed without an error message"));
      else j.resolve(d.value);
    };
    this.worker.onerror = (e) => {
      // We reject this worker's RPCs explicitly. Do not also bubble the handled
      // failure through its parent worker as a second, usually empty error.
      e.preventDefault?.();
      void workerFailure(url,e.message).then(error=>this.close(error));
    };
  }
  call(method, args = {}, transfer = []) {
    if(this.closed)return Promise.reject(this.closed);
    return new Promise((resolve, reject) => {
      const id = ++this.id;
      const quiet=!['init','configure','configurePredeal','prepare','bindPayouts','select','act','submit','cashout','construct'].includes(method);
      const end=traceOperation('worker',{...this.diagnostics,method},quiet);
      this.jobs.set(id, {resolve:value=>{end();resolve(value)},reject:error=>{end(error);reject(error)}});
      try {this.worker.postMessage({ id, method, args }, transfer);}
      catch(error){this.jobs.delete(id);end(error);reject(error);}
    });
  }
  close(error = new Error("Worker closed")) {
    this.closed=error;
    this.worker.terminate();
    for (const j of this.jobs.values()) j.reject(error);
    this.jobs.clear();
  }
}

// A terminated worker may need a moment to release its browser-owned lock.
export function acquirePlayerLock(name, timeoutMs = 2000) {
  return new Promise((resolve, reject) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    navigator.locks.request(name, {signal: controller.signal}, async () => {
      clearTimeout(timer);
      await new Promise(release => resolve(release));
    }).catch(error => {
      clearTimeout(timer);
      reject(error.name === "AbortError" ? new Error("This seat is open in another tab. Close that tab, then reconnect here.") : error);
    });
  });
}
