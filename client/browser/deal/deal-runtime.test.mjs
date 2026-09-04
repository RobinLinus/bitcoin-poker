import assert from "node:assert/strict";
import test from "node:test";

import { DealWasmParticipant } from "./deal-runtime.js";

const INPUT_POINTER = 1_024;
const LOCAL_SECRET_POINTER = 30_000;
const ENTROPY_POINTER = 30_032;
const OUTPUT_POINTER = 40_000;
const ERROR_POINTER = 60_000;
const encoder = new TextEncoder();

function fixture({ snapshotExtra = undefined } = {}) {
  const memory = new WebAssembly.Memory({ initial: 1 });
  let inputLength = 0;
  let output = new Uint8Array();
  let selected;
  let control;
  let clearOutputCount = 0;
  const writeOutput = (value) => {
    output = value instanceof Uint8Array ? value : encoder.encode(JSON.stringify(value));
    new Uint8Array(memory.buffer, OUTPUT_POINTER, output.byteLength).set(output);
  };
  const select = (name) => {
    selected = name;
    writeOutput(Uint8Array.of(0xde, 0xad, 0xbe, 0xef));
    return 0;
  };
  const exports = {
    memory,
    bp52_deal_abi_version: () => 5,
    bp52_deal_max_input_len: () => 24_000,
    bp52_deal_max_output_len: () => 24_000,
    bp52_deal_max_error_len: () => 1_024,
    bp52_deal_secret_len: () => 32,
    bp52_deal_begin_input(length) {
      inputLength = length;
      return 0;
    },
    bp52_deal_input_ptr: () => INPUT_POINTER,
    bp52_deal_local_secret_ptr: () => LOCAL_SECRET_POINTER,
    bp52_deal_entropy_ptr: () => ENTROPY_POINTER,
    bp52_deal_init() {
      const bytes = new Uint8Array(memory.buffer, INPUT_POINTER, inputLength);
      control = JSON.parse(new TextDecoder().decode(bytes));
      return 0;
    },
    bp52_deal_generate_next() {
      writeOutput(Uint8Array.of(1, 2, 3));
      return 0;
    },
    bp52_deal_prepare_bundle: () => 0,
    bp52_deal_prepare_bundle_slots: () => select("slot-proofs"),
    bp52_deal_install_parallel_bundle: () => 0,
    bp52_deal_accept_envelope: () => 0,
    bp52_deal_replay_envelope: () => 0,
    bp52_deal_start_retry: () => 0,
    bp52_deal_make_acceptance_signature() {
      writeOutput(Uint8Array.of(4, 5));
      return 0;
    },
    bp52_deal_make_retry_signature: () => select("retry-signature"),
    bp52_deal_accept_acceptance_signature: () => 0,
    bp52_deal_export_accepted_body: () => select("body"),
    bp52_deal_export_accepted_deal: () => select("deal"),
    bp52_deal_export_local_acceptance_signature: () => select("signature"),
    bp52_deal_export_verification_attestation: () => select("attestation"),
    bp52_deal_snapshot() {
      writeOutput({
        status: "local-envelope",
        localRole: 0,
        attempt: 0,
        nextSequence: 0,
        hasRetainedPreimages: false,
        ...snapshotExtra,
      });
      return 0;
    },
    bp52_deal_seal_retained_preimages() {
      writeOutput(Uint8Array.of(6, 7));
      return 0;
    },
    bp52_deal_reveal_local_preimage() {
      writeOutput(Uint8Array.of(8, 9));
      return 0;
    },
    bp52_deal_output_ptr: () => OUTPUT_POINTER,
    bp52_deal_output_len: () => output.byteLength,
    bp52_deal_clear_output() {
      clearOutputCount += 1;
      output = new Uint8Array();
    },
    bp52_deal_last_error_ptr: () => ERROR_POINTER,
    bp52_deal_last_error_len: () => 0,
    bp52_deal_clear: () => {},
  };
  return {
    participant: new DealWasmParticipant({ exports }),
    control: () => control,
    localSecret: () => Uint8Array.from(
      new Uint8Array(memory.buffer, LOCAL_SECRET_POINTER, 32),
    ),
    entropy: () => Uint8Array.from(new Uint8Array(memory.buffer, ENTROPY_POINTER, 32)),
    selected: () => selected,
    clearOutputCount: () => clearOutputCount,
  };
}

test("DEAL initialization sends strict Serde control and separately stages secrets", () => {
  const runtime = fixture();
  const fill = (value) => new Uint8Array(32).fill(value);
  runtime.participant.initialize({
    sharedConfigHash: fill(1),
    sessionNonce: fill(2),
    gameId: fill(3),
    localSecretKey: fill(4),
    identityKeys: [fill(5), fill(6)],
    entropy: fill(7),
  });
  assert.deepEqual(runtime.control(), {
    sharedConfigHash: Array.from(fill(1)),
    sessionNonce: Array.from(fill(2)),
    gameId: Array.from(fill(3)),
    identityKeys: [Array.from(fill(5)), Array.from(fill(6))],
  });
  assert.equal(JSON.stringify(runtime.control()).includes("BP52DL"), false);
  assert.equal(Object.hasOwn(runtime.control(), "localSecretKey"), false);
  assert.equal(Object.hasOwn(runtime.control(), "entropy"), false);
  assert.deepEqual(runtime.localSecret(), fill(4));
  assert.deepEqual(runtime.entropy(), fill(7));
});

test("DEAL status is a strict Rust-owned Serde view", () => {
  const { participant, clearOutputCount } = fixture();
  assert.deepEqual(participant.snapshot(), {
    status: "local-envelope",
    localRole: 0,
    attempt: 0,
    nextSequence: 0,
    hasRetainedPreimages: false,
    wasmMiB: 0.0625,
  });
  assert.equal(clearOutputCount(), 1);

  const malformed = fixture({ snapshotExtra: { obsoleteStatusCode: 1 } });
  assert.throws(() => malformed.participant.snapshot(), /unexpected shape/u);
});

test("DEAL verification artifacts cross JavaScript opaquely through named exports", () => {
  const { participant, selected } = fixture();
  const artifact = participant.exportVerificationAttestation();
  assert.equal(selected(), "attestation");
  assert.deepEqual(artifact, Uint8Array.of(0xde, 0xad, 0xbe, 0xef));
  const retry = participant.makeRetrySignature(1, new Uint8Array(32));
  assert.equal(selected(), "retry-signature");
  assert.deepEqual(retry.signature, Uint8Array.of(0xde, 0xad, 0xbe, 0xef));
});

test("DEAL slot batches are canonical before entering Wasm", () => {
  const { participant, selected } = fixture();
  assert.deepEqual(
    participant.prepareBundleSlots([0, 2, 8]).proofs,
    Uint8Array.of(0xde, 0xad, 0xbe, 0xef),
  );
  assert.equal(selected(), "slot-proofs");
  assert.throws(() => participant.prepareBundleSlots([]), /unique and ascending/u);
  assert.throws(() => participant.prepareBundleSlots([2, 2]), /unique and ascending/u);
  assert.throws(() => participant.prepareBundleSlots([9]), /unique and ascending/u);
});

test("DEAL secret length comes only from the Rust export", () => {
  const { participant } = fixture();
  const fill = (value) => new Uint8Array(32).fill(value);
  assert.throws(
    () => participant.initialize({
      sharedConfigHash: fill(1),
      sessionNonce: fill(2),
      gameId: fill(3),
      localSecretKey: new Uint8Array(31),
      identityKeys: [fill(5), fill(6)],
      entropy: fill(7),
    }),
    /Rust-owned secret length/u,
  );
});
