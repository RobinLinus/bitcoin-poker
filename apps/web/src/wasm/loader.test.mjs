import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createHash, webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

import {
  instantiateWasm,
  loadWasmBytes,
} from "./loader.js";

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

// Browser Fetch has already decompressed the body but preserves wire headers.
const compressedFetch = async url => url === "/wasm/manifest.json"
  ? fetchImplementation(url)
  : new Response(wasm, {headers:{"content-type":"application/wasm", "content-encoding":"gzip", "content-length":"27"}});
assert.deepEqual(await loadWasmBytes("test", {fetchImplementation:compressedFetch}), wasm);
assert.ok(await instantiateWasm("test", {}, {fetchImplementation:compressedFetch}) instanceof WebAssembly.Instance);
const corruptCompressedFetch = async url => url === "/wasm/manifest.json"
  ? fetchImplementation(url)
  : new Response(Uint8Array.of(...wasm.slice(0,7),1), {headers:{"content-encoding":"gzip", "content-length":"27"}});
await assert.rejects(() => loadWasmBytes("test", {fetchImplementation:corruptCompressedFetch}), /manifest verification/);
const incorrectLengthFetch = async url => url === "/wasm/manifest.json"
  ? fetchImplementation(url)
  : new Response(wasm, {headers:{"content-length":"27"}});
await assert.rejects(() => loadWasmBytes("test", {fetchImplementation:incorrectLengthFetch}), /Content-Length/);
console.log("raw and compressed Wasm manifest loader tests ok");

// Model an open page whose immutable prefix was retired by a UI deployment.
const base = "/assets/" + "a".repeat(64);
const source = (await readFile(new URL("./loader.js", import.meta.url), "utf8"))
  .replace(/^const ASSET_BASE = .*;$/m, `const ASSET_BASE = "${base}";`);
const retiredLoader = await import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
const requests = [];
const retiredFetch = async (url, options) => {
  requests.push([url, options.cache]);
  if (url === `${base}/wasm/manifest.json`) return fetchImplementation("/wasm/manifest.json");
  if (url.startsWith(base)) return new Response("retired", {status:404});
  return fetchImplementation(url);
};
assert.deepEqual(await retiredLoader.loadWasmBytes("test", {fetchImplementation:retiredFetch}), wasm);
assert.ok(await retiredLoader.instantiateWasm("test", {}, {fetchImplementation:retiredFetch}) instanceof WebAssembly.Instance);
assert.equal(requests.filter(([url, cache]) => url === "/wasm/test.wasm" && cache === "no-cache").length, 2);
const changedArtifact = async (url, options) => url === "/wasm/test.wasm" ? corruptFetch(url) : retiredFetch(url, options);
await assert.rejects(() => retiredLoader.loadWasmBytes("test", {fetchImplementation:changedArtifact}), /manifest verification/);
await assert.rejects(() => retiredLoader.instantiateWasm("test", {}, {fetchImplementation:changedArtifact}), /manifest verification/);
const unavailableArtifact = async (url, options) => url.endsWith("test.wasm") ? new Response("unavailable", {status:503}) : retiredFetch(url, options);
requests.length = 0;
await assert.rejects(() => retiredLoader.loadWasmBytes("test", {fetchImplementation:unavailableArtifact}), /503/);
assert.ok(!requests.some(([url]) => url === "/wasm/test.wasm"), "only a retired route warrants a fallback");
for (const [html, expected] of [[`<html data-asset-base="${base}">`,false], [`<html data-asset-base="/assets/${"b".repeat(64)}">`,true], ["unavailable",false]]) {
  assert.equal(await retiredLoader.appUpdateAvailable({fetchImplementation:async()=>new Response(html)}), expected);
}
assert.equal(await retiredLoader.appUpdateAvailable({fetchImplementation:async()=>{throw Error("offline")}}), false);
console.log("retired deployment loads only matching Wasm and detects a new app version");
