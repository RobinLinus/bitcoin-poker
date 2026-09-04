import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

import {
  instantiateWasm,
  loadWasmBytes,
} from "./wasm-loader.js";

const wasm = Uint8Array.of(0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00);
const sha256 = createHash("sha256").update(wasm).digest("hex");
const manifest = JSON.stringify({
  schemaVersion: 1,
  artifacts: [{
    name: "test",
    url: "/wasm/test.wasm",
    sha256,
    sizeBytes: wasm.byteLength,
    securityBoundary: "test-only",
  }],
});
const fetchImplementation = async (url) => {
  if (url === "/wasm/manifest.json") {
    return new Response(manifest, { headers: { "content-type": "application/json" } });
  }
  if (url === "/wasm/test.wasm") {
    return new Response(wasm, {
      headers: {
        "content-type": "application/wasm",
        "content-length": String(wasm.byteLength),
      },
    });
  }
  return new Response("missing", { status: 404 });
};

assert.deepEqual(await loadWasmBytes("test", { fetchImplementation }), wasm);
assert.ok(await instantiateWasm("test", {}, { fetchImplementation }) instanceof WebAssembly.Instance);

const corruptFetch = async (url) => {
  if (url === "/wasm/manifest.json") {
    return new Response(manifest, { headers: { "content-type": "application/json" } });
  }
  return new Response(Uint8Array.of(...wasm.slice(0, 7), 1), {
    headers: { "content-type": "application/wasm" },
  });
};
await assert.rejects(
  () => loadWasmBytes("test", { fetchImplementation: corruptFetch }),
  /manifest verification/,
);
await assert.rejects(
  () => instantiateWasm("test", {}, { fetchImplementation: corruptFetch }),
  /manifest verification/,
);

console.log("raw Wasm manifest loader tests ok");
