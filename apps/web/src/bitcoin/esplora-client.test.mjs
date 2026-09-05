import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

import {
  ChainAdapterError,
  createEsploraChainAdapter,
} from "./esplora-client.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const endpoint = "https://chain.example.test/esplora";
const genesis = "01".repeat(32);
const checkpoint = "02".repeat(32);
const tipHash = "03".repeat(32);
const profileId = "04".repeat(32);
const unknownTxid = "07".repeat(32);
const mempoolTxid = "0fa542dd3e2a240894cb047d1d32779bea6b6d0f9c659741d5bdfca4b9ef1663";
const mempoolRaw = Uint8Array.from(Buffer.from(
  `0200000001${"44".repeat(32)}0900000000ffffffff012c4c000000000000035120ab00000000`,
  "hex",
));
const deployment = {
  deploymentId: "injected-test",
  chain: {
    backend: "esplora",
    esploraUrl: `${endpoint}/`,
    network: "signet",
    profileIdHex: profileId,
    genesisDisplayHashHex: genesis,
    checkpoint: { height: 10, displayHashHex: checkpoint },
    allowBroadcast: false,
    addressHrp: "tb",
  },
};

const transactionInspector = Object.freeze({
  async limits() {
    return { maxRawTransactionBytes: 4_000_000 };
  },
  async inspect(raw) {
    assert.deepEqual(new Uint8Array(raw), mempoolRaw);
    return {
      displayTxid: Uint8Array.from(Buffer.from(mempoolTxid, "hex")),
      displayTxidHex: mempoolTxid,
      raw: Uint8Array.from(mempoolRaw),
      hasWitness: false,
      version: 2,
      lockTime: 0,
      inputs: [{
        previousOutpoint: {
          displayTxid: new Uint8Array(32).fill(0x44),
          vout: 9,
        },
        scriptSig: new Uint8Array(),
        sequence: 0xffff_ffff,
      }],
      outputs: [{ valueSat: 19_500n, scriptPubkey: Uint8Array.of(0x51, 0x20, 0xab) }],
    };
  },
});

const requests = [];
const fetchImplementation = async (url) => {
  requests.push(url);
  const path = url.slice(endpoint.length);
  const response = new Map([
    ["/block-height/0", genesis],
    ["/block-height/10", checkpoint],
    ["/blocks/tip/hash", tipHash],
    [`/block/${tipHash}`, JSON.stringify({ id: tipHash, height: 12 })],
    ["/block-height/12", tipHash],
    ["/fee-estimates", JSON.stringify({ 1: 1.09, 2: 1 })],
    [`/tx/${unknownTxid}/status`, JSON.stringify({ confirmed: false })],
    [`/tx/${unknownTxid}/outspend/0`, JSON.stringify({ spent: false })],
    [`/tx/${mempoolTxid}/status`, JSON.stringify({ confirmed: false })],
    [`/tx/${mempoolTxid}/raw`, mempoolRaw],
    ["/address/tb1ptest/utxo", JSON.stringify([{
      txid: "05".repeat(32),
      vout: 1,
      value: 10_000,
      status: { confirmed: true, block_height: 11, block_hash: "06".repeat(32) },
    }])],
  ]).get(path);
  return new Response(response ?? "missing", {
    status: response === undefined ? 404 : 200,
    headers: { "content-type": "text/plain" },
  });
};

const adapter = createEsploraChainAdapter(deployment, {
  fetch: fetchImplementation,
  transactionInspector,
});
const identity = await adapter.verifyProfile();
assert.equal(Buffer.from(identity.profileId).toString("hex"), profileId);
assert.ok(requests.every((url) => url.startsWith(endpoint)));

// A CDN may cache /blocks/tip/height behind /blocks/tip/hash for more than the
// duration of all retries. Derive the height from hash-addressed block metadata
// and validate it against the canonical height lookup instead.
const advancedTipHash = "08".repeat(32);
const priorTipHash = "09".repeat(32);
let staleHeightRequests = 0;
let racedHashRequests = 0;
const raceFetch = async (url) => {
  const path = url.slice(endpoint.length);
  let response;
  switch (path) {
    case "/block-height/0":
      response = genesis;
      break;
    case "/block-height/10":
      response = checkpoint;
      break;
    case "/blocks/tip/height":
      staleHeightRequests += 1;
      response = "12";
      break;
    case "/blocks/tip/hash":
      racedHashRequests += 1;
      response = advancedTipHash;
      break;
    case `/block/${advancedTipHash}`:
      response = JSON.stringify({ id: advancedTipHash, height: 13 });
      break;
    case "/block-height/13":
      response = advancedTipHash;
      break;
    default:
      response = undefined;
  }
  return new Response(response ?? "missing", { status: response === undefined ? 404 : 200 });
};
const raceAdapter = createEsploraChainAdapter(deployment, { fetch: raceFetch });
const racedIdentity = await raceAdapter.verifyProfile();
assert.equal(racedIdentity.checkedTip.height, 13);
assert.equal(Buffer.from(racedIdentity.checkedTip.displayHash).toString("hex"), advancedTipHash);
assert.equal(staleHeightRequests, 0);
assert.equal(racedHashRequests, 1);

// Hash-addressed metadata and the canonical height mapping can themselves be
// briefly skewed. Two incoherent samples followed by a coherent one succeed.
let stabilizingTipSamples = 0;
let stabilizingHeightLookups = 0;
const stabilizingTipFetch = async (url) => {
  const path = url.slice(endpoint.length);
  let response = new Map([
    ["/block-height/0", genesis],
    ["/block-height/10", checkpoint],
    [`/block/${advancedTipHash}`, JSON.stringify({ id: advancedTipHash, height: 13 })],
  ]).get(path);
  if (path === "/blocks/tip/hash") {
    stabilizingTipSamples += 1;
    response = advancedTipHash;
  } else if (path === "/block-height/13") {
    stabilizingHeightLookups += 1;
    response = stabilizingHeightLookups < 3 ? priorTipHash : advancedTipHash;
  }
  return new Response(response ?? "missing", { status: response === undefined ? 404 : 200 });
};
const stabilizingTipAdapter = createEsploraChainAdapter(deployment, {
  fetch: stabilizingTipFetch,
});
const stabilizedIdentity = await stabilizingTipAdapter.verifyProfile();
assert.equal(stabilizedIdentity.checkedTip.height, 13);
assert.equal(stabilizingTipSamples, 3);
assert.equal(stabilizingHeightLookups, 3);

let inconsistentTipSamples = 0;
const inconsistentTipFetch = async (url) => {
  const path = url.slice(endpoint.length);
  const response = new Map([
    ["/block-height/0", genesis],
    ["/block-height/10", checkpoint],
    ["/blocks/tip/hash", advancedTipHash],
    [`/block/${advancedTipHash}`, JSON.stringify({ id: advancedTipHash, height: 13 })],
    ["/block-height/13", priorTipHash],
  ]).get(path);
  if (path === "/blocks/tip/hash") inconsistentTipSamples += 1;
  return new Response(response ?? "missing", { status: response === undefined ? 404 : 200 });
};
const inconsistentTipAdapter = createEsploraChainAdapter(deployment, {
  fetch: inconsistentTipFetch,
});
await assert.rejects(
  () => inconsistentTipAdapter.verifyProfile(),
  (error) => error instanceof ChainAdapterError &&
    error.code === "UNSTABLE_CHAIN" &&
    /after 3 attempts/.test(error.message),
);
assert.equal(inconsistentTipSamples, 3);

const utxos = await adapter.addressUtxos("tb1ptest");
assert.equal(utxos.length, 1);
assert.equal(utxos[0].value, 10_000);
assert.equal(utxos[0].status.block_height, 11);

const feeCompatibility = await adapter.relayFeeFloorCompatibility(1);
assert.equal(feeCompatibility.state, "unknown");
assert.equal(feeCompatibility.estimateAboveGraphRate, true);
assert.equal(feeCompatibility.advertisedFastSatPerVbyte, 1.09);
assert.equal(feeCompatibility.authenticatedRelayFloorSatPerVbyte, null);
assert.match(feeCompatibility.advisory, /does not prove relay rejection/);
assert.match(feeCompatibility.advisory, /₿1\.09\/vB/u);
assert.match(feeCompatibility.advisory, /₿1\/vB/u);
assert.doesNotMatch(feeCompatibility.advisory, /\bsats?(?:oshi)?\b/iu);

// Mutinynet's Esplora returns 200 {confirmed:false} for an unknown txid.
// Only a present raw transaction, parsed and txid-checked by Rust/Wasm, may
// upgrade that ambiguous response to a mempool observation.
assert.deepEqual(await adapter.transactionStatus(unknownTxid), { state: "unknown" });
assert.ok(requests.includes(`${endpoint}/tx/${unknownTxid}/status`));
assert.ok(requests.includes(`${endpoint}/tx/${unknownTxid}/raw`));
assert.deepEqual(
  await adapter.outpointStatus({ displayTxid: unknownTxid, vout: 0 }),
  { state: "unknown" },
);
assert.equal(await adapter.originFact({
  outpoint: { displayTxid: unknownTxid, vout: 0 },
  valueSat: 1n,
  scriptPubkey: Uint8Array.of(0x51),
}), null);

assert.deepEqual(await adapter.transactionStatus(mempoolTxid), { state: "mempool" });

// Browser host functions may require their Window receiver. Exercise the
// default-fetch path, not only injected arrow-function mocks.
const originalFetch = globalThis.fetch;
let defaultFetchCalled = false;
try {
  globalThis.fetch = function boundReceiverFetch(url) {
    assert.equal(this, globalThis);
    defaultFetchCalled = true;
    return fetchImplementation(url);
  };
  const defaultAdapter = createEsploraChainAdapter(deployment);
  await defaultAdapter.verifyProfile();
  assert.equal(defaultFetchCalled, true);
} finally {
  globalThis.fetch = originalFetch;
}

await assert.rejects(
  () => adapter.publish(Uint8Array.of(1)),
  (error) => error instanceof ChainAdapterError && error.code === "BROADCAST_DISABLED",
);
const mainnetAdapter = createEsploraChainAdapter({
  ...deployment,
  chain: { ...deployment.chain, network: "bitcoin", allowBroadcast: true },
}, { fetch: fetchImplementation });
await assert.rejects(
  () => mainnetAdapter.publish(Uint8Array.of(1)),
  (error) => error instanceof ChainAdapterError && error.code === "MAINNET_BROADCAST_DISABLED",
);
assert.throws(
  () => createEsploraChainAdapter({
    ...deployment,
    chain: { ...deployment.chain, esploraUrl: "http://chain.example.test" },
  }),
  /safe HTTP endpoint/,
);

console.log("generic injected Esplora adapter tests ok");
