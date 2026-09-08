import {wasmClient, joinBytes} from "./wasm-client.js";
let client;
self.onmessage = async ({data}) => {
  const started = performance.now();
  try {
    let bytes;
    if (data.mode === "init") {
      client = wasmClient(await WebAssembly.instantiate(data.module, {benchmark: {now_ms: () => performance.now(), progress: () => {}}}));
      bytes = client.call("tree_parallel_pool_init", joinBytes(data.key, data.inventory), data.role);
    } else {
      if (!client || !["sign", "verify"].includes(data.mode)) throw new Error("Invalid worker command");
      bytes = client.call(`tree_parallel_${data.mode}`, data.bytes);
    }
    self.postMessage({id: data.id, bytes, elapsedMs: performance.now() - started, memoryBytes: client.exports.memory.buffer.byteLength}, [bytes.buffer]);
  } catch (error) {
    self.postMessage({id: data.id, error: String(error.stack ?? error)});
  }
};
