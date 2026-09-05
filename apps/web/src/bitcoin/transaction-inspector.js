import { instantiateWasm } from "../wasm/loader.js";

const ABI_VERSION = 2;
const REQUIRED_EXPORTS = [
  "bp52_transaction_abi_version",
  "bp52_transaction_max_input_len",
  "bp52_transaction_max_output_len",
  "bp52_transaction_max_error_len",
  "bp52_transaction_begin_input",
  "bp52_transaction_input_ptr",
  "bp52_transaction_inspect",
  "bp52_transaction_output_ptr",
  "bp52_transaction_output_len",
  "bp52_transaction_last_error_ptr",
  "bp52_transaction_last_error_len",
  "bp52_transaction_clear",
];

function asBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new TypeError(`${label} must be a byte array`);
}

function wasmLimit(api, exportName, label) {
  const value = api[exportName]();
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`Bitcoin transaction-inspector Wasm returned an invalid ${label}`);
  }
  return value;
}

function exactObject(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`transaction metadata contains an invalid ${label}`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new Error(`transaction metadata contains an invalid ${label}`);
  }
  return value;
}

function createBoundaryLoader(instantiate) {
  let modulePromise;
  return async () => {
    modulePromise ||= (async () => {
      const instance = await instantiate();
      const api = instance.exports;
      if (
        REQUIRED_EXPORTS.some((name) => typeof api[name] !== "function") ||
        !(api.memory instanceof WebAssembly.Memory) ||
        api.bp52_transaction_abi_version() !== ABI_VERSION
      ) {
        throw new Error("Bitcoin transaction-inspector Wasm has an unexpected interface");
      }
      const limits = Object.freeze({
        maxRawTransactionBytes: wasmLimit(
          api,
          "bp52_transaction_max_input_len",
          "input bound",
        ),
        maxMetadataJsonBytes: wasmLimit(
          api,
          "bp52_transaction_max_output_len",
          "output bound",
        ),
        maxDiagnosticBytes: wasmLimit(
          api,
          "bp52_transaction_max_error_len",
          "diagnostic bound",
        ),
      });
      return { api, limits };
    })();
    try {
      return await modulePromise;
    } catch (error) {
      modulePromise = undefined;
      throw error;
    }
  };
}

function readRegion(api, pointerFunction, lengthFunction, maximum, label) {
  const length = lengthFunction();
  const pointer = pointerFunction();
  if (
    !Number.isSafeInteger(pointer) || pointer < 0 ||
    !Number.isSafeInteger(length) || length < 0 || length > maximum
  ) {
    throw new Error(`${label} has an invalid length`);
  }
  if (length > 0 && pointer === 0) throw new Error(`${label} has a null pointer`);
  const end = pointer + length;
  if (!Number.isSafeInteger(end) || end > api.memory.buffer.byteLength) {
    throw new Error(`${label} lies outside Wasm memory`);
  }
  return Uint8Array.from(new Uint8Array(api.memory.buffer, pointer, length));
}

function lastError(boundary) {
  const { api, limits } = boundary;
  try {
    const bytes = readRegion(
      api,
      api.bp52_transaction_last_error_ptr,
      api.bp52_transaction_last_error_len,
      limits.maxDiagnosticBytes,
      "transaction-inspector diagnostic",
    );
    return bytes.byteLength === 0
      ? "unknown transaction-inspector error"
      : new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (_) {
    return "unreadable transaction-inspector error";
  }
}

function exactInteger(value, minimum, maximum, label) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`transaction metadata contains an invalid ${label}`);
  }
  return value;
}

function hexBytes(value, label, expectedLength) {
  if (
    typeof value !== "string" || value.length % 2 !== 0 ||
    value.length / 2 !== expectedLength || !/^[0-9a-f]*$/u.test(value)
  ) {
    throw new Error(`transaction metadata contains an invalid ${label}`);
  }
  const result = new Uint8Array(expectedLength);
  for (let index = 0; index < expectedLength; index += 1) {
    result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return result;
}

function variableHexBytes(value, label) {
  if (typeof value !== "string" || value.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(value)) {
    throw new Error(`transaction metadata contains an invalid ${label}`);
  }
  return hexBytes(value, label, value.length / 2);
}

function metadataView(json, raw) {
  let metadata;
  try {
    metadata = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(json));
  } catch (cause) {
    throw new Error("transaction inspector returned invalid metadata JSON", { cause });
  }
  exactObject(
    metadata,
    ["displayTxidHex", "hasWitness", "version", "lockTime", "inputs", "outputs"],
    "root object",
  );
  const displayTxid = hexBytes(metadata.displayTxidHex, "display txid", 32);
  if (
    typeof metadata.hasWitness !== "boolean" || !Array.isArray(metadata.inputs) ||
    !Array.isArray(metadata.outputs)
  ) {
    throw new Error("transaction inspector returned an invalid metadata view");
  }
  return {
    displayTxid,
    displayTxidHex: metadata.displayTxidHex,
    raw,
    hasWitness: metadata.hasWitness,
    version: exactInteger(metadata.version, -0x8000_0000, 0x7fff_ffff, "version"),
    lockTime: exactInteger(metadata.lockTime, 0, 0xffff_ffff, "lock time"),
    inputs: metadata.inputs.map((candidate) => {
      const input = exactObject(
        candidate,
        ["previousOutpoint", "scriptSigHex", "sequence"],
        "input object",
      );
      const previousOutpoint = exactObject(
        input.previousOutpoint,
        ["displayTxidHex", "vout"],
        "previous outpoint object",
      );
      return {
        previousOutpoint: {
          displayTxid: hexBytes(
            previousOutpoint.displayTxidHex,
            "previous output txid",
            32,
          ),
          vout: exactInteger(previousOutpoint.vout, 0, 0xffff_ffff, "output index"),
        },
        scriptSig: variableHexBytes(input.scriptSigHex, "scriptSig"),
        sequence: exactInteger(input.sequence, 0, 0xffff_ffff, "sequence"),
      };
    }),
    outputs: metadata.outputs.map((candidate) => {
      const output = exactObject(
        candidate,
        ["valueSat", "scriptPubkeyHex"],
        "output object",
      );
      return {
        valueSat: BigInt(exactInteger(
          output.valueSat,
          0,
          Number.MAX_SAFE_INTEGER,
          "output value",
        )),
        scriptPubkey: variableHexBytes(output.scriptPubkeyHex, "scriptPubKey"),
      };
    }),
  };
}

async function inspectWith(boundary, raw) {
  const { api, limits } = boundary;
  const code = api.bp52_transaction_begin_input(raw.byteLength);
  if (code !== 0) {
    throw new Error(`Bitcoin transaction-inspector Wasm error ${code}: ${lastError(boundary)}`);
  }
  const pointer = api.bp52_transaction_input_ptr();
  if (!Number.isSafeInteger(pointer) || pointer < 0 || (raw.byteLength > 0 && pointer === 0)) {
    throw new Error("Bitcoin transaction-inspector Wasm returned a null input pointer");
  }
  const end = pointer + raw.byteLength;
  if (!Number.isSafeInteger(end) || end > api.memory.buffer.byteLength) {
    throw new Error("Bitcoin transaction-inspector input lies outside Wasm memory");
  }
  new Uint8Array(api.memory.buffer, pointer, raw.byteLength).set(raw);
  const inspectCode = api.bp52_transaction_inspect();
  if (inspectCode !== 0) {
    throw new Error(
      `Bitcoin transaction-inspector Wasm error ${inspectCode}: ${lastError(boundary)}`,
    );
  }
  return metadataView(
    readRegion(
      api,
      api.bp52_transaction_output_ptr,
      api.bp52_transaction_output_len,
      limits.maxMetadataJsonBytes,
      "transaction metadata JSON",
    ),
    raw,
  );
}

/** Build an inspector around an injected raw Wasm instance loader. */
export function createTransactionInspector({
  instantiate = () => instantiateWasm("transaction"),
} = {}) {
  if (typeof instantiate !== "function") {
    throw new TypeError("transaction inspector instantiate must be a function");
  }
  const loadBoundary = createBoundaryLoader(instantiate);
  let operationTail = Promise.resolve();
  return Object.freeze({
    async limits() {
      const { limits } = await loadBoundary();
      return limits;
    },
    async inspect(rawTransaction) {
      const source = asBytes(rawTransaction, "raw transaction");
      const boundary = await loadBoundary();
      if (source.byteLength === 0 || source.byteLength > boundary.limits.maxRawTransactionBytes) {
        throw new Error("raw transaction is empty or exceeds the Rust-owned bound");
      }
      const raw = Uint8Array.from(source);
      const operation = operationTail.then(async () => {
        try {
          return await inspectWith(boundary, raw);
        } finally {
          boundary.api.bp52_transaction_clear();
        }
      });
      operationTail = operation.catch(() => undefined);
      return operation;
    },
  });
}

const transactionInspector = createTransactionInspector();

/** Return bounds exported by the pinned Rust transaction inspector. */
export const transactionInspectorLimits = () => transactionInspector.limits();

/** Inspect opaque Bitcoin consensus bytes with the canonical rust-bitcoin boundary. */
export const inspectTransaction = (rawTransaction) => transactionInspector.inspect(rawTransaction);
