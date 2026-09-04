import assert from "node:assert/strict";

import { createTransactionInspector } from "./transaction-runtime.js";

const encoder = new TextEncoder();
const INPUT_POINTER = 1_024;
const OUTPUT_POINTER = 8_192;
const ERROR_POINTER = 48_000;

const validMetadata = {
  displayTxidHex: "11".repeat(32),
  hasWitness: true,
  version: 2,
  lockTime: 42,
  inputs: [{
    previousOutpoint: { displayTxidHex: "22".repeat(32), vout: 7 },
    scriptSigHex: "51",
    sequence: 0xffff_fffe,
  }],
  outputs: [{ valueSat: 19_500, scriptPubkeyHex: "5120ab" }],
};

function fakeInstance(metadata, {
  abiVersion = 2,
  maxInput = 4_000_000,
  maxOutput = 32_000_000,
  maxError = 2_048,
  inspectCode = 0,
  diagnostic = "inspection failed",
} = {}) {
  const memory = new WebAssembly.Memory({ initial: 1 });
  const output = encoder.encode(JSON.stringify(metadata));
  const error = encoder.encode(diagnostic);
  let inputLength = 0;
  let clearCount = 0;
  new Uint8Array(memory.buffer, OUTPUT_POINTER, output.byteLength).set(output);
  new Uint8Array(memory.buffer, ERROR_POINTER, error.byteLength).set(error);
  const exports = {
    memory,
    bp52_transaction_abi_version: () => abiVersion,
    bp52_transaction_max_input_len: () => maxInput,
    bp52_transaction_max_output_len: () => maxOutput,
    bp52_transaction_max_error_len: () => maxError,
    bp52_transaction_begin_input: (length) => {
      inputLength = length;
      return 0;
    },
    bp52_transaction_input_ptr: () => INPUT_POINTER,
    bp52_transaction_inspect: () => inspectCode,
    bp52_transaction_output_ptr: () => OUTPUT_POINTER,
    bp52_transaction_output_len: () => output.byteLength,
    bp52_transaction_last_error_ptr: () => ERROR_POINTER,
    bp52_transaction_last_error_len: () => error.byteLength,
    bp52_transaction_clear: () => {
      clearCount += 1;
    },
  };
  return {
    instance: { exports },
    input: () => Uint8Array.from(new Uint8Array(memory.buffer, INPUT_POINTER, inputLength)),
    clearCount: () => clearCount,
  };
}

{
  const fake = fakeInstance(validMetadata);
  const inspector = createTransactionInspector({ instantiate: async () => fake.instance });
  assert.deepEqual(await inspector.limits(), {
    maxRawTransactionBytes: 4_000_000,
    maxMetadataJsonBytes: 32_000_000,
    maxDiagnosticBytes: 2_048,
  });
  const source = Uint8Array.of(1, 2, 3, 4);
  const inspected = await inspector.inspect(source);
  source.fill(9);
  assert.deepEqual(fake.input(), Uint8Array.of(1, 2, 3, 4));
  assert.equal(inspected.displayTxidHex, "11".repeat(32));
  assert.deepEqual(inspected.displayTxid, Uint8Array.from({ length: 32 }, () => 0x11));
  assert.equal(inspected.hasWitness, true);
  assert.equal(inspected.version, 2);
  assert.equal(inspected.lockTime, 42);
  assert.deepEqual(inspected.inputs[0].previousOutpoint.displayTxid, Uint8Array.from({
    length: 32,
  }, () => 0x22));
  assert.equal(inspected.inputs[0].previousOutpoint.vout, 7);
  assert.deepEqual(inspected.inputs[0].scriptSig, Uint8Array.of(0x51));
  assert.equal(inspected.inputs[0].sequence, 0xffff_fffe);
  assert.equal(inspected.outputs[0].valueSat, 19_500n);
  assert.deepEqual(inspected.outputs[0].scriptPubkey, Uint8Array.of(0x51, 0x20, 0xab));
  assert.deepEqual(inspected.raw, Uint8Array.of(1, 2, 3, 4));
  assert.equal(fake.clearCount(), 1);
}

for (const metadata of [
  { ...validMetadata, extra: true },
  { ...validMetadata, displayTxidHex: "AA".repeat(32) },
  { ...validMetadata, version: 2.5 },
  { ...validMetadata, outputs: [{ ...validMetadata.outputs[0], valueSat: 9_007_199_254_740_992 }] },
  { ...validMetadata, inputs: [{ ...validMetadata.inputs[0], extra: true }] },
]) {
  const fake = fakeInstance(metadata);
  const inspector = createTransactionInspector({ instantiate: async () => fake.instance });
  await assert.rejects(() => inspector.inspect(Uint8Array.of(1)), /invalid|metadata view/u);
  assert.equal(fake.clearCount(), 1);
}

{
  const fake = fakeInstance(validMetadata, { maxInput: 3 });
  const inspector = createTransactionInspector({ instantiate: async () => fake.instance });
  await assert.rejects(
    () => inspector.inspect(Uint8Array.of(1, 2, 3, 4)),
    /Rust-owned bound/u,
  );
  assert.equal(fake.clearCount(), 0);
}

{
  const fake = fakeInstance(validMetadata, { maxOutput: 8 });
  const inspector = createTransactionInspector({ instantiate: async () => fake.instance });
  await assert.rejects(() => inspector.inspect(Uint8Array.of(1)), /invalid length/u);
  assert.equal(fake.clearCount(), 1);
}

{
  const fake = fakeInstance(validMetadata, { inspectCode: 7, diagnostic: "bad transaction" });
  const inspector = createTransactionInspector({ instantiate: async () => fake.instance });
  await assert.rejects(() => inspector.inspect(Uint8Array.of(1)), /error 7: bad transaction/u);
  assert.equal(fake.clearCount(), 1);
}

{
  const fake = fakeInstance(validMetadata, { abiVersion: 1 });
  const inspector = createTransactionInspector({ instantiate: async () => fake.instance });
  await assert.rejects(() => inspector.limits(), /unexpected interface/u);
}

{
  const fake = fakeInstance(validMetadata, { maxError: 0 });
  const inspector = createTransactionInspector({ instantiate: async () => fake.instance });
  await assert.rejects(() => inspector.limits(), /invalid diagnostic bound/u);
}

console.log("transaction inspector Serde boundary tests ok");
