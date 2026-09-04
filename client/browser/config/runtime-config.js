const DEFAULT_CONFIG_URL = "/api/v1/config";
const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_CONFIG_DEPTH = 16;
const MAX_CONFIG_VALUES = 4_096;
const MAX_CONFIG_URL_LENGTH = 2_048;
const CONFIG_REQUEST_TIMEOUT_MS = 15_000;

let defaultConfigPromise;

function fail(message) {
  throw new Error(`Invalid BP52 runtime config: ${message}`);
}

function sameOriginConfigUrl(value) {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_CONFIG_URL_LENGTH) {
    throw new Error("BP52 runtime config URL is invalid");
  }

  const fallbackBase = new URL("http://bp52.invalid/");
  let browserBase;
  try {
    browserBase = globalThis.location?.href ? new URL(globalThis.location.href) : null;
  } catch (_) {
    browserBase = null;
  }
  const base = browserBase ?? fallbackBase;
  let parsed;
  try {
    parsed = new URL(value, base);
  } catch (_) {
    throw new Error("BP52 runtime config URL is invalid");
  }
  if (
    !["https:", "http:"].includes(parsed.protocol) || parsed.origin !== base.origin ||
    parsed.username || parsed.password || parsed.hash
  ) {
    throw new Error("BP52 runtime config URL must be same-origin");
  }
  return browserBase ? parsed.href : `${parsed.pathname}${parsed.search}`;
}

function validateJsonValue(value, path, depth, state) {
  state.values += 1;
  if (state.values > MAX_CONFIG_VALUES) fail("JSON contains too many values");
  if (depth > MAX_CONFIG_DEPTH) fail("JSON is nested too deeply");

  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") {
    if (value.length > MAX_CONFIG_BYTES) fail(`${path} contains an oversized string`);
    return;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail(`${path} is not a nonnegative JavaScript-safe integer`);
    }
    return;
  }
  if (!value || typeof value !== "object") fail(`${path} is not a JSON value`);
  if (state.seen.has(value)) fail("JSON contains a cycle");
  state.seen.add(value);

  const isArray = Array.isArray(value);
  if (!isArray) {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      fail(`${path} is not a JSON object`);
    }
  }
  for (const key of Object.keys(value)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      fail(`${path} contains an unsafe property name`);
    }
    validateJsonValue(value[key], `${path}.${key}`, depth + 1, state);
  }
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

/**
 * Apply only JSON/JavaScript transport checks to a Rust-resolved deployment.
 * Deployment schema, network, relay-kind, and economic policy remain owned by Rust.
 */
export function validateRuntimeConfig(input) {
  let config;
  try {
    config = structuredClone(input);
  } catch (_) {
    fail("root is not cloneable JSON");
  }
  if (!config || typeof config !== "object" || Array.isArray(config)) {
    fail("root must be a JSON object");
  }
  validateJsonValue(config, "root", 0, { seen: new WeakSet(), values: 0 });
  return deepFreeze(config);
}

async function boundedResponseText(response) {
  const contentType = response.headers?.get?.("content-type");
  if (typeof contentType !== "string" || !/^application\/json(?:\s*;|$)/i.test(contentType)) {
    throw new Error("BP52 runtime config response is not JSON");
  }
  const contentLength = response.headers?.get?.("content-length");
  if (contentLength !== null && contentLength !== undefined) {
    if (!/^[0-9]+$/.test(contentLength) || Number(contentLength) > MAX_CONFIG_BYTES) {
      throw new Error("BP52 runtime config response has an invalid size");
    }
  }

  const reader = response.body?.getReader?.();
  if (!reader) throw new Error("BP52 runtime config response body is unavailable");
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) {
        throw new Error("BP52 runtime config response body is invalid");
      }
      total += value.byteLength;
      if (total > MAX_CONFIG_BYTES) {
        await reader.cancel().catch(() => {});
        throw new Error("BP52 runtime config response has an invalid size");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (total === 0) throw new Error("BP52 runtime config response has an invalid size");

  const encoded = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    encoded.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(encoded);
  } catch (_) {
    throw new Error("BP52 runtime config response is not valid UTF-8");
  }
}

async function fetchRuntimeConfig(fetchImplementation, url) {
  if (typeof fetchImplementation !== "function") throw new Error("Fetch is unavailable");
  const requestUrl = sameOriginConfigUrl(url);
  const signal = typeof globalThis.AbortSignal?.timeout === "function"
    ? globalThis.AbortSignal.timeout(CONFIG_REQUEST_TIMEOUT_MS)
    : undefined;
  const response = await fetchImplementation(requestUrl, {
    cache: "no-store",
    credentials: "omit",
    headers: { accept: "application/json" },
    redirect: "error",
    signal,
  });
  if (!response?.ok || response.redirected) {
    throw new Error(`BP52 runtime config request failed (${response?.status ?? "no response"})`);
  }
  const encoded = await boundedResponseText(response);
  let decoded;
  try {
    decoded = JSON.parse(encoded);
  } catch (_) {
    throw new Error("BP52 runtime config response is not valid JSON");
  }
  return validateRuntimeConfig(decoded);
}

/** Load and cache the relay's sole Rust-resolved deployment configuration. */
export function loadRuntimeConfig({
  fetchImplementation = globalThis.fetch,
  url = DEFAULT_CONFIG_URL,
  reload = false,
} = {}) {
  if (url !== DEFAULT_CONFIG_URL || fetchImplementation !== globalThis.fetch) {
    return fetchRuntimeConfig(fetchImplementation, url);
  }
  if (reload || !defaultConfigPromise) {
    defaultConfigPromise = fetchRuntimeConfig(fetchImplementation, url).catch((error) => {
      defaultConfigPromise = undefined;
      throw error;
    });
  }
  return defaultConfigPromise;
}

export const runtimeConfigUrl = DEFAULT_CONFIG_URL;
