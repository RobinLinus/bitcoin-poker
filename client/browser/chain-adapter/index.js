import {
  ChainAdapterError,
  createEsploraChainAdapter,
} from "./esplora.js";

export {
  ChainAdapterError,
  createEsploraChainAdapter,
} from "./esplora.js";
export {
  inspectTransaction,
  transactionInspectorLimits,
} from "./transaction-runtime.js";

// The module API is authoritative. This small global makes the same factory
// available to the relay's classic-script bootstrap without duplicating any
// backend behavior in the UI.
if (typeof globalThis === "object") {
  globalThis.BP52_CHAIN_ADAPTER = Object.freeze({
    ChainAdapterError,
    createEsploraChainAdapter,
  });
}
