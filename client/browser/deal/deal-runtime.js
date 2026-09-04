const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

const ABI_VERSION = 5;
const REQUIRED_EXPORTS = [
  "bp52_deal_abi_version",
  "bp52_deal_max_input_len",
  "bp52_deal_max_output_len",
  "bp52_deal_max_error_len",
  "bp52_deal_secret_len",
  "bp52_deal_begin_input",
  "bp52_deal_input_ptr",
  "bp52_deal_local_secret_ptr",
  "bp52_deal_entropy_ptr",
  "bp52_deal_init",
  "bp52_deal_generate_next",
  "bp52_deal_prepare_bundle",
  "bp52_deal_prepare_bundle_slots",
  "bp52_deal_install_parallel_bundle",
  "bp52_deal_accept_envelope",
  "bp52_deal_replay_envelope",
  "bp52_deal_start_retry",
  "bp52_deal_make_acceptance_signature",
  "bp52_deal_make_retry_signature",
  "bp52_deal_accept_acceptance_signature",
  "bp52_deal_export_accepted_body",
  "bp52_deal_export_accepted_deal",
  "bp52_deal_export_local_acceptance_signature",
  "bp52_deal_export_verification_attestation",
  "bp52_deal_snapshot",
  "bp52_deal_seal_retained_preimages",
  "bp52_deal_reveal_local_preimage",
  "bp52_deal_output_ptr",
  "bp52_deal_output_len",
  "bp52_deal_clear_output",
  "bp52_deal_last_error_ptr",
  "bp52_deal_last_error_len",
  "bp52_deal_clear",
];

function asBytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new TypeError(`${label} must be a byte array`);
}

function jsonByteArray(value) {
  if (
    value instanceof Uint8Array || value instanceof ArrayBuffer ||
    ArrayBuffer.isView(value)
  ) {
    return Array.from(asBytes(value, "DEAL control byte array"));
  }
  return value;
}

function copyBuffer(bytes) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

function wasmLimit(exports, name, label) {
  const value = exports[name]();
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`DEAL Wasm reported an invalid ${label}`);
  }
  return value;
}

function u32(value, label) {
  if (
    !Number.isSafeInteger(value) || value < 0 ||
    new Uint32Array([value])[0] !== value
  ) {
    throw new TypeError(`${label} must be an unsigned 32-bit integer`);
  }
  return value;
}

function exactObject(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new Error(`${label} has an unexpected shape`);
  }
  return value;
}

function checkedRegion(exports, pointer, length, maximum, label, allowEmpty = false) {
  if (
    !Number.isSafeInteger(pointer) || pointer < 0 ||
    !Number.isSafeInteger(length) || length < 0 || length > maximum ||
    (!allowEmpty && length === 0) || (length > 0 && pointer === 0)
  ) {
    throw new Error(`${label} has an invalid Wasm region`);
  }
  const end = pointer + length;
  if (!Number.isSafeInteger(end) || end > exports.memory.buffer.byteLength) {
    throw new Error(`${label} lies outside Wasm memory`);
  }
  return new Uint8Array(exports.memory.buffer, pointer, length);
}

/** One secret-bearing DEAL Wasm participant. Keep it inside a dedicated Worker. */
export class DealWasmParticipant {
  static async create(wasmSource) {
    const result = await WebAssembly.instantiate(wasmSource, {});
    const instance = result instanceof WebAssembly.Instance ? result : result.instance;
    return new DealWasmParticipant(instance);
  }

  constructor(instance) {
    this.instance = instance;
    this.exports = instance?.exports;
    if (
      !this.exports || REQUIRED_EXPORTS.some((name) => typeof this.exports[name] !== "function") ||
      !(this.exports.memory instanceof WebAssembly.Memory) ||
      this.exports.bp52_deal_abi_version() !== ABI_VERSION
    ) {
      throw new Error("DEAL Wasm has an unexpected interface");
    }
    this.limits = Object.freeze({
      input: wasmLimit(this.exports, "bp52_deal_max_input_len", "input bound"),
      output: wasmLimit(this.exports, "bp52_deal_max_output_len", "output bound"),
      error: wasmLimit(this.exports, "bp52_deal_max_error_len", "diagnostic bound"),
      secret: wasmLimit(this.exports, "bp52_deal_secret_len", "secret length"),
    });
  }

  initialize(request) {
    const identityKeys = Array.isArray(request?.identityKeys)
      ? request.identityKeys.map(jsonByteArray)
      : request?.identityKeys;
    const control = {
      sharedConfigHash: jsonByteArray(request?.sharedConfigHash),
      sessionNonce: jsonByteArray(request?.sessionNonce),
      gameId: jsonByteArray(request?.gameId),
      identityKeys,
    };
    const json = textEncoder.encode(JSON.stringify(control));
    try {
      return this.#timed(() => {
        this.#stageInput(json);
        this.#stageSecret(
          request?.localSecretKey,
          this.exports.bp52_deal_local_secret_ptr(),
          "local identity secret",
        );
        this.#stageSecret(
          request?.entropy,
          this.exports.bp52_deal_entropy_ptr(),
          "worker entropy",
        );
        this.#check(this.exports.bp52_deal_init());
      });
    } finally {
      json.fill(0);
    }
  }

  generateNextEnvelope() {
    const result = this.#timed(() => {
      this.#check(this.exports.bp52_deal_generate_next());
      return this.#takeOutput("generated DEAL envelope");
    });
    return { envelope: result.value, metrics: result.metrics };
  }

  prepareBundle() {
    return this.#timed(() => this.#check(this.exports.bp52_deal_prepare_bundle())).metrics;
  }

  prepareBundleSlots(slots) {
    if (
      !Array.isArray(slots) || slots.length === 0 ||
      slots.some((slot, index) =>
        !Number.isSafeInteger(slot) || slot < 0 || slot >= 9 ||
        (index > 0 && slots[index - 1] >= slot)
      )
    ) {
      throw new TypeError("bundle proof slots must be unique and ascending");
    }
    const mask = slots.reduce((value, slot) => value | (1 << slot), 0);
    const result = this.#timed(() => {
      this.#check(this.exports.bp52_deal_prepare_bundle_slots(mask));
      return this.#takeOutput("bundle slot proofs");
    });
    return { proofs: result.value, metrics: result.metrics };
  }

  installParallelBundle(proofs) {
    return this.#timed(() => {
      this.#stageInput(proofs);
      this.#check(this.exports.bp52_deal_install_parallel_bundle());
    }).metrics;
  }

  acceptEnvelope(envelope) {
    return this.#timed(() => {
      this.#stageInput(envelope);
      this.#check(this.exports.bp52_deal_accept_envelope());
    }).metrics;
  }

  replayEnvelope(envelope) {
    return this.#timed(() => {
      this.#stageInput(envelope);
      this.#check(this.exports.bp52_deal_replay_envelope());
    }).metrics;
  }

  startRetry(approvedAttempt) {
    return this.#timed(() => {
      this.#check(this.exports.bp52_deal_start_retry(u32(approvedAttempt, "approvedAttempt")));
    }).metrics;
  }

  makeAcceptanceSignature(coordinatorBody) {
    const result = this.#timed(() => {
      this.#stageInput(coordinatorBody);
      this.#check(this.exports.bp52_deal_make_acceptance_signature());
      return this.#takeOutput("accepted-body signature");
    });
    return { signature: result.value, metrics: result.metrics };
  }

  makeRetrySignature(nextAttempt, digest) {
    const retryDigest = asBytes(digest, "DEAL retry digest");
    if (retryDigest.byteLength !== 32) {
      throw new TypeError("DEAL retry digest must contain exactly 32 bytes");
    }
    const result = this.#timed(() => {
      this.#stageInput(retryDigest);
      this.#check(this.exports.bp52_deal_make_retry_signature(
        u32(nextAttempt, "next DEAL attempt"),
      ));
      return this.#takeOutput("DEAL retry signature");
    });
    return { signature: result.value, metrics: result.metrics };
  }

  acceptAcceptanceSignature(role, signature) {
    return this.#timed(() => {
      this.#stageInput(signature);
      this.#check(this.exports.bp52_deal_accept_acceptance_signature(
        u32(role, "accepted-body signature role"),
      ));
    }).metrics;
  }

  exportAcceptedBody() {
    return this.#export("bp52_deal_export_accepted_body", "accepted DEAL body");
  }

  exportAcceptedDeal() {
    return this.#export("bp52_deal_export_accepted_deal", "accepted DEAL certificate");
  }

  exportLocalAcceptanceSignature() {
    return this.#export(
      "bp52_deal_export_local_acceptance_signature",
      "local acceptance signature",
    );
  }

  exportVerificationAttestation() {
    return this.#export(
      "bp52_deal_export_verification_attestation",
      "DEAL verification attestation",
    );
  }

  sealRetainedPreimages(storageKey) {
    const key = Uint8Array.from(asBytes(storageKey, "preimage storage key"));
    try {
      return this.#timed(() => {
        this.#stageInput(key);
        this.#check(this.exports.bp52_deal_seal_retained_preimages());
        return this.#takeOutput("sealed DEAL preimages");
      });
    } finally {
      key.fill(0);
    }
  }

  revealLocalPreimage(slot) {
    this.#check(this.exports.bp52_deal_reveal_local_preimage(u32(slot, "preimage slot")));
    return this.#takeOutput("local DEAL preimage");
  }

  snapshot() {
    this.#check(this.exports.bp52_deal_snapshot());
    const bytes = this.#takeOutput("DEAL snapshot JSON");
    let snapshot;
    try {
      snapshot = JSON.parse(textDecoder.decode(bytes));
    } catch (cause) {
      throw new Error("DEAL Wasm returned invalid snapshot JSON", { cause });
    }
    exactObject(
      snapshot,
      ["status", "localRole", "attempt", "nextSequence", "hasRetainedPreimages"],
      "DEAL snapshot",
    );
    if (
      typeof snapshot.status !== "string" || snapshot.status.length === 0 ||
      (snapshot.localRole !== 0 && snapshot.localRole !== 1) ||
      u32(snapshot.attempt, "DEAL snapshot attempt") !== snapshot.attempt ||
      u32(snapshot.nextSequence, "DEAL snapshot next sequence") !== snapshot.nextSequence ||
      typeof snapshot.hasRetainedPreimages !== "boolean"
    ) {
      throw new Error("DEAL Wasm returned an invalid snapshot view");
    }
    return { ...snapshot, wasmMiB: this.exports.memory.buffer.byteLength / 1_048_576 };
  }

  clear() {
    this.exports.bp52_deal_clear();
  }

  #export(exportName, label) {
    this.#check(this.exports[exportName]());
    return this.#takeOutput(label);
  }

  #stageInput(value) {
    const bytes = asBytes(value, "DEAL input");
    if (bytes.byteLength > this.limits.input) {
      throw new Error("DEAL input exceeds the Rust-owned bound");
    }
    this.#check(this.exports.bp52_deal_begin_input(bytes.byteLength));
    const pointer = this.exports.bp52_deal_input_ptr();
    const target = checkedRegion(
      this.exports,
      pointer,
      bytes.byteLength,
      this.limits.input,
      "DEAL input",
      true,
    );
    target.set(bytes);
  }

  #stageSecret(value, pointer, label) {
    const bytes = asBytes(value, label);
    if (bytes.byteLength !== this.limits.secret) {
      throw new Error(`${label} differs from the Rust-owned secret length`);
    }
    checkedRegion(
      this.exports,
      pointer,
      this.limits.secret,
      this.limits.secret,
      label,
    ).set(bytes);
  }

  #takeOutput(label) {
    try {
      const source = checkedRegion(
        this.exports,
        this.exports.bp52_deal_output_ptr(),
        this.exports.bp52_deal_output_len(),
        this.limits.output,
        label,
      );
      return Uint8Array.from(source);
    } finally {
      this.exports.bp52_deal_clear_output();
    }
  }

  #lastError() {
    try {
      const bytes = checkedRegion(
        this.exports,
        this.exports.bp52_deal_last_error_ptr(),
        this.exports.bp52_deal_last_error_len(),
        this.limits.error,
        "DEAL diagnostic",
        true,
      );
      return bytes.byteLength === 0 ? "unknown DEAL Wasm error" : textDecoder.decode(bytes);
    } catch (_) {
      return "unreadable DEAL Wasm error";
    }
  }

  #check(code) {
    if (code !== 0) throw new Error(`DEAL Wasm error ${code}: ${this.#lastError()}`);
  }

  #timed(operation) {
    const started = performance.now();
    const value = operation();
    return {
      value,
      metrics: {
        elapsedMs: performance.now() - started,
        wasmMiB: this.exports.memory.buffer.byteLength / 1_048_576,
      },
    };
  }
}

export function transferBytes(bytes) {
  return copyBuffer(bytes);
}
