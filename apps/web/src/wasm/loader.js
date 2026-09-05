const MANIFEST_URL = "/wasm/manifest.json";
const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_WASM_BYTES = 16 * 1024 * 1024;
const NAME_PATTERN = /^[a-z][a-z0-9-]{0,31}$/;

let manifestPromise;
const bytesPromises = new Map();

function canonicalEntry(value) {
  if (
    !value || typeof value !== "object" || Array.isArray(value) ||
    !NAME_PATTERN.test(value.name || "") ||
    value.url !== `/wasm/${value.name}.wasm` ||
    !/^[0-9a-f]{64}$/.test(value.sha256 || "") ||
    !Number.isSafeInteger(value.sizeBytes) || value.sizeBytes < 8 ||
    value.sizeBytes > MAX_WASM_BYTES ||
    typeof value.securityBoundary !== "string" || value.securityBoundary.length === 0 ||
    value.securityBoundary.length > 256
  ) {
    throw new Error("Wasm manifest contains a malformed artifact entry");
  }
  return Object.freeze({
    name: value.name,
    url: value.url,
    sha256: value.sha256,
    sizeBytes: value.sizeBytes,
    securityBoundary: value.securityBoundary,
  });
}

async function boundedText(response, maximum, label) {
  const text = await response.text();
  if (text.length === 0 || text.length > maximum) {
    throw new Error(`${label} has an invalid size`);
  }
  return text;
}

async function loadManifest(fetchImplementation) {
  const response = await fetchImplementation(MANIFEST_URL, {
    cache: "no-cache",
    credentials: "same-origin",
    headers: { accept: "application/json" },
    redirect: "error",
  });
  if (!response?.ok || response.redirected) {
    throw new Error(`Wasm manifest request failed (${response?.status ?? "no response"})`);
  }
  let decoded;
  try {
    decoded = JSON.parse(await boundedText(response, MAX_MANIFEST_BYTES, "Wasm manifest"));
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error("Wasm manifest is not valid JSON");
    throw error;
  }
  if (!decoded || decoded.schemaVersion !== 1) {
    throw new Error("Wasm manifest has an unsupported schema version");
  }
  const entries = Array.isArray(decoded) ? decoded : decoded?.artifacts;
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > 32) {
    throw new Error("Wasm manifest has an invalid artifact list");
  }
  const result = new Map();
  for (const rawEntry of entries) {
    const entry = canonicalEntry(rawEntry);
    if (result.has(entry.name)) throw new Error("Wasm manifest repeats an artifact name");
    result.set(entry.name, entry);
  }
  return result;
}

function manifest(fetchImplementation) {
  if (fetchImplementation !== globalThis.fetch) return loadManifest(fetchImplementation);
  manifestPromise ||= loadManifest(fetchImplementation).catch((error) => {
    manifestPromise = undefined;
    throw error;
  });
  return manifestPromise;
}

async function sha256Hex(value) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", value));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function verifiedBytes(name, fetchImplementation) {
  if (!NAME_PATTERN.test(name)) throw new Error("Wasm artifact name is malformed");
  const entry = (await manifest(fetchImplementation)).get(name);
  if (!entry) throw new Error(`Wasm artifact is absent from the manifest: ${name}`);
  const response = await fetchImplementation(entry.url, {
    cache: "no-cache",
    credentials: "same-origin",
    headers: { accept: "application/wasm" },
    redirect: "error",
  });
  if (!response?.ok || response.redirected) {
    throw new Error(`Wasm artifact request failed (${response?.status ?? "no response"}): ${name}`);
  }
  return verifyArtifactResponse(response, entry);
}

async function verifyArtifactResponse(response, entry) {
  const declared = response.headers?.get?.("content-length");
  if (declared !== null && declared !== undefined && Number(declared) !== entry.sizeBytes) {
    throw new Error(`Wasm artifact Content-Length differs from its manifest: ${entry.name}`);
  }
  const buffer = await response.arrayBuffer();
  if (buffer.byteLength !== entry.sizeBytes || await sha256Hex(buffer) !== entry.sha256) {
    throw new Error(`Wasm artifact failed manifest verification: ${entry.name}`);
  }
  return new Uint8Array(buffer);
}

/** Fetch a manifest-authenticated Wasm artifact for transfer to a dedicated Worker. */
export function loadWasmBytes(name, { fetchImplementation = globalThis.fetch, reload = false } = {}) {
  if (typeof fetchImplementation !== "function") return Promise.reject(new Error("Fetch is unavailable"));
  if (fetchImplementation !== globalThis.fetch) return verifiedBytes(name, fetchImplementation);
  if (reload) bytesPromises.delete(name);
  if (!bytesPromises.has(name)) {
    bytesPromises.set(name, verifiedBytes(name, fetchImplementation).catch((error) => {
      bytesPromises.delete(name);
      throw error;
    }));
  }
  return bytesPromises.get(name).then((bytes) => Uint8Array.from(bytes));
}

/** Verify the response against the manifest before allowing the engine to execute it. */
export async function instantiateWasm(name, imports = {}, options = {}) {
  const fetchImplementation = options.fetchImplementation ?? globalThis.fetch;
  if (typeof fetchImplementation !== "function") throw new Error("Fetch is unavailable");
  if (!NAME_PATTERN.test(name)) throw new Error("Wasm artifact name is malformed");
  const entry = (await manifest(fetchImplementation)).get(name);
  if (!entry) throw new Error(`Wasm artifact is absent from the manifest: ${name}`);
  const response = await fetchImplementation(entry.url, {
    cache: "no-cache",
    credentials: "same-origin",
    headers: { accept: "application/wasm" },
    redirect: "error",
  });
  if (!response?.ok || response.redirected) {
    throw new Error(`Wasm artifact request failed (${response?.status ?? "no response"}): ${name}`);
  }
  const verifiedResponse = response.clone();
  await verifyArtifactResponse(response, entry);
  const result = await WebAssembly.instantiateStreaming(
    Promise.resolve(verifiedResponse),
    imports,
  );
  return result instanceof WebAssembly.Instance ? result : result.instance;
}

export const wasmManifestUrl = MANIFEST_URL;
