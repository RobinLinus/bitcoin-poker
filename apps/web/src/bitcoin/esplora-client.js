import {
  inspectTransaction,
  transactionInspectorLimits,
} from "./transaction-inspector.js";
import { formatBitcoinFeeRate } from "../ui/bitcoin-amount.js";
import { WorkerRpcClient } from "../workers/rpc-client.js";

const MAX_METADATA_RESPONSE_BYTES = 32 * 1024;
const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_TIMEOUT_MS = 60_000;
const TIP_COHERENCE_ATTEMPTS = 3;
const MAX_U32 = 0xffffffff;

export class ChainAdapterError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = "ChainAdapterError";
    this.code = code;
  }
}

function fail(code, message, options) {
  return new ChainAdapterError(code, message, options);
}

function asBytes(value, label) {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw fail("INVALID_ARGUMENT", `${label} must be a byte array`);
}

function hexToBytes(value, label) {
  if (typeof value !== "string" || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw fail("INVALID_ARGUMENT", `${label} must be exactly 32 hexadecimal bytes`);
  }
  return Uint8Array.from(
    { length: 32 },
    (_, index) => Number.parseInt(value.slice(index * 2, index * 2 + 2), 16),
  );
}

function bytesToHex(value) {
  let result = "";
  for (const byte of value) {
    result += byte.toString(16).padStart(2, "0");
  }
  return result;
}

function displayHash(value, label) {
  if (typeof value === "string") {
    return hexToBytes(value.trim(), label);
  }
  const result = asBytes(value, label);
  if (result.byteLength !== 32) {
    throw fail("INVALID_ARGUMENT", `${label} must contain exactly 32 bytes`);
  }
  return Uint8Array.from(result);
}

function sameBytes(left, right) {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}

function sameBlock(left, right) {
  return left.height === right.height && sameBytes(left.displayHash, right.displayHash);
}

function canonicalU32(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_U32) {
    throw fail("INVALID_ARGUMENT", `${label} is outside the unsigned 32-bit range`);
  }
  return value;
}

function confirmationDepth(tip, block) {
  if (tip.height < block.height) {
    return 0;
  }
  return tip.height - block.height + 1;
}

function normalizeOutpoint(value, label = "outpoint") {
  if (!value || typeof value !== "object") {
    throw fail("INVALID_ARGUMENT", `${label} must be a structured object`);
  }
  return {
    displayTxid: displayHash(value.displayTxid, `${label}.displayTxid`),
    vout: canonicalU32(value.vout, `${label}.vout`),
  };
}

function sameOutpoint(left, right) {
  return left.vout === right.vout && sameBytes(left.displayTxid, right.displayTxid);
}

function normalizeValueSat(value, label) {
  let result;
  try {
    result = typeof value === "bigint" ? value : BigInt(value);
  } catch {
    throw fail("INVALID_ARGUMENT", `${label} must be an unsigned integer`);
  }
  if (result < 0n || result > 0xffffffffffffffffn) {
    throw fail("INVALID_ARGUMENT", `${label} is outside the unsigned 64-bit range`);
  }
  return result;
}

function normalizeConfirmations(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_U32) {
    throw fail("INVALID_ARGUMENT", "minimum confirmations must be a positive u32");
  }
  return value;
}

function normalizeFeeRate(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0 || value > 1_000_000) {
    throw fail("INVALID_ARGUMENT", "maximum fee rate must be a finite positive number");
  }
  return value;
}

function statusKey(status) {
  switch (status.state) {
    case "unknown":
    case "mempool":
      return status.state;
    case "confirmed":
      return `confirmed:${status.block.height}:${bytesToHex(status.block.displayHash)}`;
    default:
      return `other:${status.state}`;
  }
}

function parseWireStatus(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw fail("INVALID_RESPONSE", "transaction status is not an object");
  }
  if (typeof value.confirmed !== "boolean") {
    throw fail("INVALID_RESPONSE", "transaction status has no boolean confirmed field");
  }
  const hasHeight = value.block_height !== undefined && value.block_height !== null;
  const hasHash = value.block_hash !== undefined && value.block_hash !== null;
  const hasTime = value.block_time !== undefined && value.block_time !== null;
  if (!value.confirmed) {
    if (hasHeight || hasHash || hasTime) {
      throw fail("INVALID_RESPONSE", "unconfirmed transaction carries block metadata");
    }
    return { state: "mempool" };
  }
  if (!hasHeight || !hasHash) {
    throw fail("INVALID_RESPONSE", "confirmed transaction lacks a block height or hash");
  }
  const height = canonicalWireU32(value.block_height, "confirmed block height");
  const block = {
    height,
    displayHash: parseDisplayHashText(value.block_hash, "confirmed block hash"),
  };
  if (hasTime && (!Number.isSafeInteger(value.block_time) || value.block_time < 0)) {
    throw fail("INVALID_RESPONSE", "confirmed transaction has an invalid block time");
  }
  return { state: "confirmed", block };
}

function canonicalWireU32(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_U32) {
    throw fail("INVALID_RESPONSE", `${label} is outside the unsigned 32-bit range`);
  }
  return value;
}

function parseDisplayHashText(value, label) {
  if (typeof value !== "string" || value !== value.trim() || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw fail("INVALID_RESPONSE", `${label} is not a canonical 32-byte hexadecimal string`);
  }
  return hexToBytes(value, label);
}

function cloneBlock(block) {
  return { height: block.height, displayHash: Uint8Array.from(block.displayHash) };
}

function cloneStatus(status) {
  if (status.state === "confirmed") {
    return { state: "confirmed", block: cloneBlock(status.block) };
  }
  if (status.state === "reorged") {
    return { state: "reorged", reportedBlock: cloneBlock(status.reportedBlock) };
  }
  return { state: status.state };
}

function strictJson(bytes) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (cause) {
    throw fail("INVALID_RESPONSE", "metadata response is not UTF-8", { cause });
  }
  try {
    return JSON.parse(text);
  } catch (cause) {
    throw fail("INVALID_RESPONSE", "metadata response is not valid JSON", { cause });
  }
}

function strictText(bytes) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes).trim();
  } catch (cause) {
    throw fail("INVALID_RESPONSE", "text response is not UTF-8", { cause });
  }
}

async function boundedBody(response, maximum) {
  const declared = response.headers?.get?.("content-length");
  if (declared !== null && declared !== undefined) {
    if (!/^(0|[1-9][0-9]*)$/.test(declared)) {
      throw fail("INVALID_RESPONSE", "response has an invalid content-length header");
    }
    if (Number(declared) > maximum) {
      throw fail("RESPONSE_TOO_LARGE", `response exceeds its ${maximum}-byte bound`);
    }
  }
  const reader = response.body?.getReader?.();
  if (!reader) {
    throw fail("INVALID_RESPONSE", "response body is not available as a bounded byte stream");
  }
  const chunks = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    const chunk = asBytes(value, "HTTP response chunk");
    length += chunk.byteLength;
    if (!Number.isSafeInteger(length) || length > maximum) {
      await reader.cancel().catch(() => {});
      throw fail("RESPONSE_TOO_LARGE", `response exceeds its ${maximum}-byte bound`);
    }
    chunks.push(Uint8Array.from(chunk));
  }
  const output = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function normalizeEsploraConfig(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw fail("INVALID_CONFIGURATION", "deployment config must be an object");
  }
  const chain = value.chain ?? value;
  if (!chain || typeof chain !== "object" || Array.isArray(chain) || chain.backend !== "esplora") {
    throw fail("INVALID_CONFIGURATION", "chain.backend must select esplora");
  }
  let endpoint;
  try {
    endpoint = new URL(chain.esploraUrl);
  } catch (_) {
    throw fail("INVALID_CONFIGURATION", "chain.esploraUrl must be an absolute URL");
  }
  if (
    !["https:", "http:"].includes(endpoint.protocol) || endpoint.username || endpoint.password ||
    endpoint.search || endpoint.hash || (endpoint.protocol === "http:" &&
      !["127.0.0.1", "localhost", "[::1]"].includes(endpoint.hostname))
  ) {
    throw fail("INVALID_CONFIGURATION", "chain.esploraUrl is not a safe HTTP endpoint");
  }
  if (typeof chain.profileIdHex !== "string" || !/^[0-9a-f]{64}$/.test(chain.profileIdHex)) {
    throw fail("INVALID_CONFIGURATION", "chain.profileIdHex must be canonical lowercase hex");
  }
  if (
    typeof chain.genesisDisplayHashHex !== "string" ||
    !/^[0-9a-f]{64}$/.test(chain.genesisDisplayHashHex)
  ) {
    throw fail("INVALID_CONFIGURATION", "chain.genesisDisplayHashHex must be canonical lowercase hex");
  }
  const checkpoint = chain.checkpoint;
  if (checkpoint !== null && (
    !checkpoint || !Number.isSafeInteger(checkpoint.height) || checkpoint.height < 0 ||
    checkpoint.height > MAX_U32 || typeof checkpoint.displayHashHex !== "string" ||
    !/^[0-9a-f]{64}$/.test(checkpoint.displayHashHex)
  )) {
    throw fail("INVALID_CONFIGURATION", "chain checkpoint is malformed");
  }
  if (typeof chain.allowBroadcast !== "boolean") {
    throw fail("INVALID_CONFIGURATION", "chain.allowBroadcast must be boolean");
  }
  if (typeof chain.addressHrp !== "string" || !/^[a-z0-9]{1,16}$/.test(chain.addressHrp)) {
    throw fail("INVALID_CONFIGURATION", "chain.addressHrp is malformed");
  }
  return Object.freeze({
    name: value.deploymentId ?? chain.network,
    endpoint: endpoint.href.replace(/\/$/, ""),
    profileId: hexToBytes(chain.profileIdHex, "chain profile id"),
    genesisDisplayHash: hexToBytes(chain.genesisDisplayHashHex, "chain genesis hash"),
    checkpoint: checkpoint === null ? null : Object.freeze({
      height: checkpoint.height,
      displayHash: hexToBytes(checkpoint.displayHashHex, "chain checkpoint hash"),
    }),
    mainnet: chain.network === "bitcoin",
    allowBroadcast: chain.allowBroadcast,
    addressHrp: chain.addressHrp,
  });
}

/** Create an Esplora implementation from the relay-provided deployment config. */
export function createEsploraChainAdapter(config, options = {}) {
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    throw fail("INVALID_CONFIGURATION", "chain-adapter options must be an object");
  }
  for (const key of Object.keys(options)) {
    if (key !== "fetch" && key !== "timeoutMs" && key !== "transactionInspector") {
      throw fail("INVALID_CONFIGURATION", `unsupported chain-adapter option: ${key}`);
    }
  }
  const fetchImplementation = options.fetch ?? globalThis.fetch?.bind(globalThis);
  if (typeof fetchImplementation !== "function") {
    throw fail("INVALID_CONFIGURATION", "Fetch is unavailable");
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw fail("INVALID_CONFIGURATION", "timeoutMs must be between 1 and 60,000 milliseconds");
  }
  const inspector = options.transactionInspector ?? {
    limits: transactionInspectorLimits,
    inspect: inspectTransaction,
  };
  if (
    !inspector || typeof inspector !== "object" || Array.isArray(inspector) ||
    typeof inspector.limits !== "function" || typeof inspector.inspect !== "function"
  ) {
    throw fail("INVALID_CONFIGURATION", "transactionInspector must provide limits and inspect");
  }
  return new EsploraAdapter(
    normalizeEsploraConfig(config),
    fetchImplementation,
    timeoutMs,
    inspector,
  );
}

export const WORKER_METHODS = Object.freeze([
  "verifyProfile",
  "tip",
  "tipFact",
  "blockHash",
  "feeEstimates",
  "relayFeeFloorCompatibility",
  "relayFeeFloorCompatible",
  "rawTransaction",
  "transactionStatus",
  "addressUtxos",
  "outpointStatus",
  "outspend",
  "originFact",
  "spendFact",
  "publish",
]);

/** Keep Esplora parsing, Bitcoin transaction inspection, and Wasm off the UI thread. */
export async function createBrowserEsploraChainAdapter(config, options = {}) {
  if (typeof window === "undefined" || globalThis !== window) {
    throw fail("INVALID_CONFIGURATION", "browser chain adapter requires a window");
  }
  if (!options || typeof options !== "object" || Array.isArray(options) ||
      Object.keys(options).some((key) => key !== "timeoutMs")) {
    throw fail("INVALID_CONFIGURATION", "browser chain-adapter options are not cloneable");
  }
  const worker = new Worker(new URL("./esplora-worker.js", import.meta.url), {
    type: "module",
    name: "bp52-chain-adapter",
  });
  const rpc = new WorkerRpcClient(worker, {
    timeoutMs: 15 * 60 * 1_000,
    closedError: "chain-adapter Worker is closed",
    cancelledError: "chain-adapter Worker was cancelled",
    timeoutError: (type) => `chain-adapter Worker request timed out: ${type}`,
    rejectedError: "chain-adapter Worker rejected the request",
    workerError: "chain-adapter Worker failed",
  });
  await rpc.request("init", { config, options });
  return Object.freeze(Object.fromEntries(WORKER_METHODS.map((method) => [
    method,
    async (...args) => (await rpc.request("call", { method, args })).result,
  ])));
}

class EsploraAdapter {
  #config;
  #fetch;
  #timeoutMs;
  #transactionInspector;
  #profileState = "unknown";
  #profileFailure;
  #verificationPromise;

  constructor(config, fetchImplementation, timeoutMs, transactionInspector) {
    this.#config = config;
    this.#fetch = fetchImplementation;
    this.#timeoutMs = timeoutMs;
    this.#transactionInspector = transactionInspector;
  }

  get profile() {
    return {
      name: this.#config.name,
      endpoint: this.#config.endpoint,
      profileId: Uint8Array.from(this.#config.profileId),
      genesisDisplayHash: Uint8Array.from(this.#config.genesisDisplayHash),
      checkpoint: this.#config.checkpoint && {
        height: this.#config.checkpoint.height,
        displayHash: Uint8Array.from(this.#config.checkpoint.displayHash),
      },
      mainnet: this.#config.mainnet,
    };
  }

  async #request(path, { method = "GET", body, maximum = MAX_METADATA_RESPONSE_BYTES } = {}) {
    const controller = new AbortController();
    let timeoutHandle;
    let timedOut = false;
    const deadline = new Promise((_, reject) => {
      timeoutHandle = setTimeout(() => {
        timedOut = true;
        controller.abort();
        reject(fail("TIMEOUT", "Esplora request timed out"));
      }, this.#timeoutMs);
    });
    const operation = (async () => {
      let response;
      try {
        response = await this.#fetch(`${this.#config.endpoint}${path}`, {
          method,
          body,
          signal: controller.signal,
          redirect: "error",
          credentials: "omit",
          cache: "no-store",
          headers: method === "POST" ? { "content-type": "text/plain" } : undefined,
        });
      } catch (cause) {
        if (timedOut || cause?.name === "AbortError") {
          throw fail("TIMEOUT", "Esplora request timed out", { cause });
        }
        throw fail("TRANSPORT", "Esplora request failed", { cause });
      }
      if (!response || typeof response.status !== "number") {
        throw fail("TRANSPORT", "Esplora returned no HTTP response");
      }
      if (response.redirected) {
        throw fail("TRANSPORT", "Esplora redirected a configured endpoint request");
      }
      if (response.status === 404) {
        throw fail("NOT_FOUND", "Esplora object was not found");
      }
      if (response.status !== 200) {
        throw fail("TRANSPORT", `Esplora returned HTTP ${response.status}`);
      }
      try {
        return await boundedBody(response, maximum);
      } catch (cause) {
        if (cause instanceof ChainAdapterError) {
          throw cause;
        }
        if (timedOut || cause?.name === "AbortError") {
          throw fail("TIMEOUT", "Esplora response body timed out", { cause });
        }
        throw fail("TRANSPORT", "Esplora response body failed", { cause });
      }
    })();
    try {
      return await Promise.race([operation, deadline]);
    } finally {
      clearTimeout(timeoutHandle);
      controller.abort();
    }
  }

  async #text(path, maximum = MAX_METADATA_RESPONSE_BYTES) {
    return strictText(await this.#request(path, { maximum }));
  }

  async #json(path, maximum = MAX_METADATA_RESPONSE_BYTES) {
    return strictJson(await this.#request(path, { maximum }));
  }

  async #blockHashAt(height) {
    canonicalU32(height, "block height");
    try {
      return parseDisplayHashText(
        await this.#text(`/block-height/${height}`),
        "block hash",
      );
    } catch (error) {
      if (error instanceof ChainAdapterError && error.code === "NOT_FOUND") {
        return null;
      }
      throw error;
    }
  }

  async #blockRefAtHash(expectedDisplayHash) {
    const displayHashHex = bytesToHex(expectedDisplayHash);
    let value;
    try {
      value = await this.#json(`/block/${displayHashHex}`);
    } catch (error) {
      if (error instanceof ChainAdapterError && error.code === "NOT_FOUND") {
        return null;
      }
      throw error;
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw fail("INVALID_RESPONSE", "tip block metadata is not an object");
    }
    const responseDisplayHash = parseDisplayHashText(value.id, "tip block id");
    const height = canonicalWireU32(value.height, "tip block height");
    if (!sameBytes(responseDisplayHash, expectedDisplayHash)) {
      return null;
    }
    return { height, displayHash: responseDisplayHash };
  }

  async #tipObservation() {
    for (let attempt = 0; attempt < TIP_COHERENCE_ATTEMPTS; attempt += 1) {
      const displayHashBytes = parseDisplayHashText(
        await this.#text("/blocks/tip/hash"),
        "tip hash",
      );
      const block = await this.#blockRefAtHash(displayHashBytes);
      if (!block) {
        continue;
      }
      const canonicalHash = await this.#blockHashAt(block.height);
      if (canonicalHash && sameBytes(block.displayHash, canonicalHash)) {
        return block;
      }
    }
    throw fail(
      "UNSTABLE_CHAIN",
      `tip hash and canonical block endpoints remained inconsistent after ${TIP_COHERENCE_ATTEMPTS} attempts`,
    );
  }

  #rejectProfile(message) {
    const error = fail("CHAIN_IDENTITY_MISMATCH", message);
    this.#profileState = "rejected";
    this.#profileFailure = error;
    return error;
  }

  async #performProfileVerification() {
    const [genesis, checkpoint] = await Promise.all([
      this.#blockHashAt(0),
      this.#config.checkpoint
        ? this.#blockHashAt(this.#config.checkpoint.height)
        : Promise.resolve(null),
    ]);
    if (!genesis || !sameBytes(genesis, this.#config.genesisDisplayHash)) {
      throw this.#rejectProfile("endpoint does not report the configured genesis");
    }
    if (
      this.#config.checkpoint &&
      (!checkpoint || !sameBytes(checkpoint, this.#config.checkpoint.displayHash))
    ) {
      throw this.#rejectProfile("endpoint does not report the configured checkpoint");
    }
    const checkedTip = await this.#tipObservation();
    if (this.#config.checkpoint && checkedTip.height < this.#config.checkpoint.height) {
      throw this.#rejectProfile("endpoint tip is below the configured checkpoint");
    }
    this.#profileState = "verified";
    return {
      profileId: Uint8Array.from(this.#config.profileId),
      genesis: { height: 0, displayHash: Uint8Array.from(genesis) },
      checkpoint: this.#config.checkpoint && {
        height: this.#config.checkpoint.height,
        displayHash: Uint8Array.from(checkpoint),
      },
      checkedTip: cloneBlock(checkedTip),
    };
  }

  async verifyProfile({ force = false } = {}) {
    if (this.#profileState === "rejected") {
      throw this.#profileFailure;
    }
    if (!force && this.#profileState === "verified") {
      return this.#performProfileVerification();
    }
    if (this.#verificationPromise) {
      return this.#verificationPromise;
    }
    this.#verificationPromise = this.#performProfileVerification();
    try {
      return await this.#verificationPromise;
    } finally {
      this.#verificationPromise = undefined;
    }
  }

  async #ensureProfile() {
    if (this.#profileState === "rejected") {
      throw this.#profileFailure;
    }
    if (this.#profileState !== "verified") {
      await this.verifyProfile();
    }
  }

  #assertExpectedProfile(expectedProfileId) {
    const expected = expectedProfileId === undefined
      ? this.#config.profileId
      : displayHash(expectedProfileId, "expected profile id");
    if (!sameBytes(expected, this.#config.profileId)) {
      throw fail("CHAIN_IDENTITY_MISMATCH", "operation is not bound to the configured chain profile");
    }
  }

  async tip() {
    await this.#ensureProfile();
    const block = await this.#tipObservation();
    return { profileId: Uint8Array.from(this.#config.profileId), block: cloneBlock(block) };
  }

  async tipFact() {
    const observation = await this.tip();
    return { type: "tip-observed", ...observation };
  }

  async blockHash(height) {
    await this.#ensureProfile();
    const value = await this.#blockHashAt(height);
    return value && Uint8Array.from(value);
  }

  /** Return Esplora's bounded target-to-base-unit/vB estimate map. */
  async feeEstimates() {
    await this.#ensureProfile();
    const value = await this.#json("/fee-estimates");
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw fail("INVALID_RESPONSE", "fee estimates are not an object");
    }
    const estimates = {};
    for (const [targetText, rate] of Object.entries(value)) {
      if (!/^[1-9][0-9]*$/.test(targetText)) {
        throw fail("INVALID_RESPONSE", "fee estimate has a noncanonical confirmation target");
      }
      const target = Number(targetText);
      if (!Number.isSafeInteger(target) || target > MAX_U32) {
        throw fail("INVALID_RESPONSE", "fee estimate confirmation target is out of range");
      }
      if (typeof rate !== "number" || !Number.isFinite(rate) || rate < 0 || rate > 1_000_000) {
        throw fail("INVALID_RESPONSE", "fee estimate rate is invalid");
      }
      estimates[targetText] = rate;
    }
    return estimates;
  }

  /**
   * Report fee-estimate context without treating it as relay-policy evidence.
   * Standard Esplora exposes neither `mempoolminfee` nor an authenticated
   * equivalent, so estimates can prove neither compatibility nor rejection.
   */
  async relayFeeFloorCompatibility(maxSatPerVbyte = 1) {
    const maximum = normalizeFeeRate(maxSatPerVbyte);
    const estimates = await this.feeEstimates();
    const targets = Object.keys(estimates).map(Number).sort((left, right) => left - right);
    if (targets.length === 0) {
      return {
        state: "unknown",
        maxSatPerVbyte: maximum,
        fastestTarget: null,
        advertisedFastSatPerVbyte: null,
        estimateAboveGraphRate: false,
        authenticatedRelayFloorSatPerVbyte: null,
        estimates,
        advisory: "Esplora returned no confirmation-target fee estimates.",
        reason: "Standard Esplora exposes no authenticated relay-floor endpoint",
      };
    }
    const fastestTarget = targets[0];
    const advertisedFastSatPerVbyte = estimates[String(fastestTarget)];
    const estimateAboveGraphRate = advertisedFastSatPerVbyte > maximum;
    return {
      state: "unknown",
      maxSatPerVbyte: maximum,
      fastestTarget,
      advertisedFastSatPerVbyte,
      estimateAboveGraphRate,
      authenticatedRelayFloorSatPerVbyte: null,
      estimates,
      advisory: estimateAboveGraphRate
        ? `The ${fastestTarget}-block fee estimate (${formatBitcoinFeeRate(advertisedFastSatPerVbyte)}) exceeds ` +
          `the graph rate (${formatBitcoinFeeRate(maximum)}), but a confirmation estimate does not prove relay rejection.`
        : `The ${fastestTarget}-block fee estimate is at or below the graph rate, but does not prove relay acceptance.`,
      reason: "Standard Esplora exposes no authenticated relay-floor endpoint",
    };
  }

  async relayFeeFloorCompatible(maxSatPerVbyte = 1) {
    return this.relayFeeFloorCompatibility(maxSatPerVbyte);
  }

  async #rawTransaction(displayTxidBytes) {
    const txidHex = bytesToHex(displayTxidBytes);
    let raw;
    try {
      const { maxRawTransactionBytes } = await this.#transactionInspector.limits();
      if (!Number.isSafeInteger(maxRawTransactionBytes) || maxRawTransactionBytes <= 0) {
        throw fail("INVALID_RESPONSE", "transaction inspector returned an invalid raw-byte bound");
      }
      raw = await this.#request(`/tx/${txidHex}/raw`, { maximum: maxRawTransactionBytes });
    } catch (error) {
      if (error instanceof ChainAdapterError && error.code === "NOT_FOUND") {
        return null;
      }
      throw error;
    }
    let inspected;
    try {
      inspected = await this.#transactionInspector.inspect(raw);
    } catch (cause) {
      throw fail("INVALID_RESPONSE", "Esplora returned an invalid raw Bitcoin transaction", { cause });
    }
    if (!sameBytes(inspected.displayTxid, displayTxidBytes)) {
      throw fail("INVALID_RESPONSE", "raw transaction does not match its requested txid");
    }
    return inspected;
  }

  async rawTransaction(txid) {
    await this.#ensureProfile();
    return this.#rawTransaction(displayHash(txid, "transaction display txid"));
  }

  async #wireTransactionStatus(displayTxidBytes) {
    try {
      return parseWireStatus(
        await this.#json(`/tx/${bytesToHex(displayTxidBytes)}/status`),
      );
    } catch (error) {
      if (error instanceof ChainAdapterError && error.code === "NOT_FOUND") {
        return { state: "unknown" };
      }
      throw error;
    }
  }

  async #statusWithTransactionPresence(displayTxidBytes, wireStatus, transaction = undefined) {
    // Some Esplora deployments use the same unconfirmed response for unknown
    // txids. Only the Rust/Wasm-validated raw transaction proves mempool
    // presence; a raw 404 remains unknown.
    if (wireStatus.state !== "mempool") {
      return cloneStatus(wireStatus);
    }
    const inspected = transaction === undefined
      ? await this.#rawTransaction(displayTxidBytes)
      : transaction;
    return inspected ? { state: "mempool" } : { state: "unknown" };
  }

  async #bestChainStatus(status) {
    if (status.state !== "confirmed") {
      return cloneStatus(status);
    }
    const currentHash = await this.#blockHashAt(status.block.height);
    if (!currentHash || !sameBytes(currentHash, status.block.displayHash)) {
      return { state: "reorged", reportedBlock: cloneBlock(status.block) };
    }
    return cloneStatus(status);
  }

  async transactionStatus(txid) {
    await this.#ensureProfile();
    const displayTxidBytes = displayHash(txid, "transaction display txid");
    const rawStatus = await this.#statusWithTransactionPresence(
      displayTxidBytes,
      await this.#wireTransactionStatus(displayTxidBytes),
    );
    return this.#bestChainStatus(rawStatus);
  }

  async addressUtxos(address, { maximum = 128 } = {}) {
    await this.#ensureProfile();
    if (
      typeof address !== "string" || address.length < 8 || address.length > 128 ||
      !/^[a-zA-Z0-9]+$/.test(address) ||
      (this.#config.addressHrp && !address.toLowerCase().startsWith(`${this.#config.addressHrp}1`))
    ) {
      throw fail("INVALID_ARGUMENT", "address is not canonical for the configured chain");
    }
    if (!Number.isSafeInteger(maximum) || maximum < 1 || maximum > 1_024) {
      throw fail("INVALID_ARGUMENT", "address UTXO maximum is out of range");
    }
    const value = await this.#json(
      `/address/${encodeURIComponent(address)}/utxo`,
      256 * 1024,
    );
    if (!Array.isArray(value) || value.length > maximum) {
      throw fail("INVALID_RESPONSE", "address UTXO response exceeds its fixed bound");
    }
    return value.map((utxo) => {
      if (!utxo || typeof utxo !== "object" || Array.isArray(utxo)) {
        throw fail("INVALID_RESPONSE", "address UTXO entry is malformed");
      }
      const txid = bytesToHex(parseDisplayHashText(utxo.txid, "UTXO txid"));
      const vout = canonicalWireU32(utxo.vout, "UTXO output index");
      if (!Number.isSafeInteger(utxo.value) || utxo.value <= 0) {
        throw fail("INVALID_RESPONSE", "UTXO value is not a positive safe integer");
      }
      const status = parseWireStatus(utxo.status);
      if (status.state === "unknown" || status.state === "reorged") {
        throw fail("INVALID_RESPONSE", "address UTXO has invalid chain status");
      }
      return {
        txid,
        vout,
        value: utxo.value,
        status: status.state === "confirmed"
          ? {
            confirmed: true,
            block_height: status.block.height,
            block_hash: bytesToHex(status.block.displayHash),
          }
          : { confirmed: false },
      };
    });
  }

  async #wireOutpointStatus(outpoint) {
    let value;
    try {
      value = await this.#json(
        `/tx/${bytesToHex(outpoint.displayTxid)}/outspend/${outpoint.vout}`,
      );
    } catch (error) {
      if (error instanceof ChainAdapterError && error.code === "NOT_FOUND") {
        return { state: "unknown" };
      }
      throw error;
    }
    if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.spent !== "boolean") {
      throw fail("INVALID_RESPONSE", "outspend response is not a canonical object");
    }
    const hasTxid = value.txid !== undefined && value.txid !== null;
    const hasVin = value.vin !== undefined && value.vin !== null;
    const hasStatus = value.status !== undefined && value.status !== null;
    if (!value.spent) {
      if (hasTxid || hasVin || hasStatus) {
        throw fail("INVALID_RESPONSE", "unspent output carries spending metadata");
      }
      return { state: "unspent" };
    }
    if (!hasTxid || !hasVin || !hasStatus) {
      throw fail("INVALID_RESPONSE", "spent output lacks txid, input index, or status");
    }
    return {
      state: "spent",
      spendingDisplayTxid: parseDisplayHashText(value.txid, "spending txid"),
      inputIndex: canonicalWireU32(value.vin, "spending input index"),
      spendingStatus: parseWireStatus(value.status),
    };
  }

  async outpointStatus(value) {
    await this.#ensureProfile();
    const outpoint = normalizeOutpoint(value);
    const status = await this.#wireOutpointStatus(outpoint);
    if (status.state === "unknown") {
      return status;
    }
    if (status.state === "unspent") {
      const creatingStatus = await this.#bestChainStatus(
        await this.#statusWithTransactionPresence(
          outpoint.displayTxid,
          await this.#wireTransactionStatus(outpoint.displayTxid),
        ),
      );
      if (creatingStatus.state === "unknown" || creatingStatus.state === "reorged") {
        return { state: "unknown" };
      }
      return { state: "unspent", creatingStatus };
    }
    const spendingStatus = await this.#statusWithTransactionPresence(
      status.spendingDisplayTxid,
      status.spendingStatus,
    );
    if (spendingStatus.state === "unknown") {
      return { state: "unknown" };
    }
    return {
      state: "spent",
      spendingDisplayTxid: Uint8Array.from(status.spendingDisplayTxid),
      inputIndex: status.inputIndex,
      spendingStatus: await this.#bestChainStatus(spendingStatus),
    };
  }

  async outspend(outpoint) {
    return this.outpointStatus(outpoint);
  }

  async originFact({
    outpoint: outpointValue,
    valueSat: expectedValue,
    scriptPubkey: expectedScriptValue,
    minConfirmations = 1,
  }) {
    await this.#ensureProfile();
    const outpoint = normalizeOutpoint(outpointValue, "origin outpoint");
    const valueSat = normalizeValueSat(expectedValue, "origin valueSat");
    const scriptPubkey = Uint8Array.from(asBytes(expectedScriptValue, "origin scriptPubkey"));
    if (scriptPubkey.byteLength === 0 || scriptPubkey.byteLength > 10_000) {
      throw fail("INVALID_ARGUMENT", "origin scriptPubkey has an invalid length");
    }
    const requiredDepth = normalizeConfirmations(minConfirmations);
    const tipBefore = await this.#tipObservation();
    const [transaction, wireStatus] = await Promise.all([
      this.#rawTransaction(outpoint.displayTxid),
      this.#wireTransactionStatus(outpoint.displayTxid),
    ]);
    const resolvedStatus = await this.#statusWithTransactionPresence(
      outpoint.displayTxid,
      wireStatus,
      transaction,
    );
    if (!transaction) {
      if (resolvedStatus.state !== "unknown") {
        throw fail("INVALID_RESPONSE", "known origin status has no corresponding raw transaction");
      }
      return null;
    }
    const output = transaction.outputs[outpoint.vout];
    if (!output || output.valueSat !== valueSat || !sameBytes(output.scriptPubkey, scriptPubkey)) {
      throw fail("EXPECTED_OUTPUT_MISMATCH", "origin transaction does not contain the expected output");
    }
    const status = await this.#bestChainStatus(resolvedStatus);
    if (status.state !== "confirmed") {
      return null;
    }
    const tipAfter = await this.#tipObservation();
    if (!sameBlock(tipBefore, tipAfter) || confirmationDepth(tipAfter, status.block) < requiredDepth) {
      return null;
    }
    return {
      type: "origin-confirmed",
      profileId: Uint8Array.from(this.#config.profileId),
      outpoint: {
        displayTxid: Uint8Array.from(outpoint.displayTxid),
        vout: outpoint.vout,
      },
      valueSat,
      scriptPubkey,
      creatingDisplayTxid: Uint8Array.from(transaction.displayTxid),
      creatingTransaction: Uint8Array.from(transaction.raw),
      confirmedIn: cloneBlock(status.block),
      observedTip: cloneBlock(tipAfter),
    };
  }

  async spendFact({
    spentOutpoint: spentOutpointValue,
    expectedSpendingDisplayTxid,
    expectedInputIndex,
    minConfirmations = 1,
  }) {
    await this.#ensureProfile();
    const spentOutpoint = normalizeOutpoint(spentOutpointValue, "spent outpoint");
    const expectedTxid = expectedSpendingDisplayTxid === undefined
      ? undefined
      : displayHash(expectedSpendingDisplayTxid, "expected spending txid");
    const expectedVin = expectedInputIndex === undefined
      ? undefined
      : canonicalU32(expectedInputIndex, "expected input index");
    const requiredDepth = normalizeConfirmations(minConfirmations);
    const tipBefore = await this.#tipObservation();
    const outspend = await this.#wireOutpointStatus(spentOutpoint);
    if (outspend.state !== "spent") {
      return null;
    }
    if (
      (expectedTxid && !sameBytes(expectedTxid, outspend.spendingDisplayTxid)) ||
      (expectedVin !== undefined && expectedVin !== outspend.inputIndex)
    ) {
      throw fail("EXPECTED_INPUT_MISMATCH", "outspend does not identify the expected spending input");
    }
    const [transaction, directStatus] = await Promise.all([
      this.#rawTransaction(outspend.spendingDisplayTxid),
      this.#wireTransactionStatus(outspend.spendingDisplayTxid),
    ]);
    const resolvedDirectStatus = await this.#statusWithTransactionPresence(
      outspend.spendingDisplayTxid,
      directStatus,
      transaction,
    );
    if (!transaction) {
      throw fail("INVALID_RESPONSE", "outspend has no corresponding raw spending transaction");
    }
    if (statusKey(outspend.spendingStatus) !== statusKey(resolvedDirectStatus)) {
      throw fail("INVALID_RESPONSE", "outspend and transaction endpoints disagree about status");
    }
    const input = transaction.inputs[outspend.inputIndex];
    if (!input || !sameOutpoint(input.previousOutpoint, spentOutpoint)) {
      throw fail("EXPECTED_INPUT_MISMATCH", "spending transaction input does not spend the observed outpoint");
    }
    const status = await this.#bestChainStatus(resolvedDirectStatus);
    if (status.state !== "confirmed") {
      return null;
    }
    const tipAfter = await this.#tipObservation();
    if (!sameBlock(tipBefore, tipAfter) || confirmationDepth(tipAfter, status.block) < requiredDepth) {
      return null;
    }
    return {
      type: "spend-confirmed",
      profileId: Uint8Array.from(this.#config.profileId),
      spentOutpoint: {
        displayTxid: Uint8Array.from(spentOutpoint.displayTxid),
        vout: spentOutpoint.vout,
      },
      spendingDisplayTxid: Uint8Array.from(transaction.displayTxid),
      spendingTransaction: Uint8Array.from(transaction.raw),
      inputIndex: outspend.inputIndex,
      confirmedIn: cloneBlock(status.block),
      observedTip: cloneBlock(tipAfter),
    };
  }

  async publish(rawTransaction, { expectedProfileId } = {}) {
    if (this.#config.mainnet) {
      throw fail("MAINNET_BROADCAST_DISABLED", "transaction broadcast is disabled on mainnet");
    }
    if (!this.#config.allowBroadcast) {
      throw fail("BROADCAST_DISABLED", "transaction broadcast is disabled by deployment config");
    }
    this.#assertExpectedProfile(expectedProfileId);
    let transaction;
    try {
      transaction = await this.#transactionInspector.inspect(rawTransaction);
    } catch (cause) {
      throw fail("INVALID_ARGUMENT", "transaction submission is not a valid Bitcoin transaction", { cause });
    }
    // Broadcast always rechecks genesis, checkpoint, and a coherent tip. A
    // successful earlier check is deliberately insufficient for publication.
    await this.verifyProfile({ force: true });
    const response = parseDisplayHashText(
      await this.#textPost("/tx", bytesToHex(transaction.raw)),
      "broadcast txid",
    );
    if (!sameBytes(response, transaction.displayTxid)) {
      throw fail("INVALID_RESPONSE", "broadcast response txid differs from the submitted transaction");
    }
    return Uint8Array.from(response);
  }

  async #textPost(path, body) {
    return strictText(await this.#request(path, {
      method: "POST",
      body,
      maximum: MAX_METADATA_RESPONSE_BYTES,
    }));
  }
}
