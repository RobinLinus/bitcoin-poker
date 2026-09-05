const REQUIRED = [
  "dealer_abi_version", "dealer_begin_input", "dealer_input_ptr",
  "dealer_secret_ptr", "dealer_entropy_ptr", "dealer_init",
  "dealer_prepare_outgoing", "dealer_confirm_outgoing",
  "dealer_accept_peer", "dealer_snapshot",
  "dealer_start_retry",
  "dealer_export_certificate", "dealer_verify_certificate",
  "dealer_export_share", "dealer_sign_card",
  "dealer_sign_offchain_commitment", "dealer_verify_offchain_commitment",
  "dealer_evaluate_seven",
  "dealer_gate_leaf",
  "dealer_output_ptr", "dealer_output_len",
  "dealer_error_ptr", "dealer_error_len", "dealer_clear",
];

function bytes(value, length, label) {
  const result = value instanceof Uint8Array ? value : new Uint8Array(value);
  if (length !== undefined && result.byteLength !== length) throw new Error(`${label} must be ${length} bytes`);
  return result;
}

function concat(parts) {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.byteLength; }
  return result;
}

/** Secret-owning DLOG52 participant. Instantiate only inside a dedicated Worker. */
export class DealerParticipant {
  static async create(source) {
    const result = await WebAssembly.instantiate(source, {});
    return new DealerParticipant(result instanceof WebAssembly.Instance ? result : result.instance);
  }

  constructor(instance) {
    this.exports = instance?.exports;
    if (!this.exports || !(this.exports.memory instanceof WebAssembly.Memory) ||
        REQUIRED.some((name) => typeof this.exports[name] !== "function") ||
        this.exports.dealer_abi_version() !== 1) throw new Error("unexpected DLOG52 Wasm interface");
  }

  initialize({ config, role, identitySecret, entropy }) {
    const fields = ["networkGenesis", "sessionAnchor", "identityA", "identityB", "sessionNonce", "rulesHash"];
    const control = concat([...fields.map((field) => bytes(config?.[field], 32, field)), Uint8Array.of(role)]);
    this.#input(control);
    this.#write(this.exports.dealer_secret_ptr(), bytes(identitySecret, 32, "identitySecret"));
    this.#write(this.exports.dealer_entropy_ptr(), bytes(entropy, 32, "entropy"));
    this.#check(this.exports.dealer_init());
  }

  prepareOutgoing() {
    const status = this.exports.dealer_prepare_outgoing();
    if (status === 2) return null;
    this.#check(status);
    return this.#output();
  }

  confirmPersistedOutgoing(envelope) {
    this.#input(envelope); this.#check(this.exports.dealer_confirm_outgoing());
  }

  acceptPeer(envelope) {
    this.#input(envelope); this.#check(this.exports.dealer_accept_peer());
  }

  snapshot() {
    this.#check(this.exports.dealer_snapshot());
    const value = this.#output();
    if (value.byteLength !== 41) throw new Error("malformed DLOG52 snapshot");
    const view = new DataView(value.buffer, value.byteOffset, value.byteLength);
    return { attempt: view.getUint32(0, true), stage: view.getUint16(4, true),
      stageRoot: value.slice(6, 38), hasPendingOutgoing: value[38] === 1, accepted: value[39] === 1, retryRequired: value[40] === 1 };
  }
  startRetry(nextAttempt) { this.#check(this.exports.dealer_start_retry(nextAttempt)); }

  exportCertificate() { this.#check(this.exports.dealer_export_certificate()); return this.#output(); }
  verifyCertificate(certificate) { this.#input(certificate); this.#check(this.exports.dealer_verify_certificate()); }
  exportShare(slot, { recipient = 255, stage = slot < 4 ? 4 : slot < 7 ? 1 : slot === 7 ? 2 : 3,
    auxiliaryRandomness = crypto.getRandomValues(new Uint8Array(32)) } = {}) {
    this.#input(concat([Uint8Array.of(recipient, stage), bytes(auxiliaryRandomness, 32, "auxiliaryRandomness")]));
    this.#check(this.exports.dealer_export_share(slot));
    const reveal = this.#output();
    if (reveal.byteLength !== 199) throw new Error("malformed DLOG52 signed share reveal");
    return reveal;
  }
  signCard(slot, peerOpening, sighash, auxiliaryRandomness) {
    this.#input(concat([bytes(peerOpening, 199, "peerOpening"), bytes(sighash, 32, "sighash"), bytes(auxiliaryRandomness, 32, "auxiliaryRandomness")]));
    this.#check(this.exports.dealer_sign_card(slot));
    const result = this.#output();
    if (result.byteLength !== 98) throw new Error("malformed DLOG52 card signature");
    return { rawSum: result[0], cardId: result[1], publicKey: result.slice(2, 34), signature: result.slice(34) };
  }
  signOffchainCommitment(commitmentHash, auxiliaryRandomness) {
    this.#input(concat([
      bytes(commitmentHash, 32, "commitmentHash"),
      bytes(auxiliaryRandomness, 32, "auxiliaryRandomness"),
    ]));
    this.#check(this.exports.dealer_sign_offchain_commitment());
    return bytes(this.#output(), 64, "off-chain commitment signature");
  }
  verifyOffchainCommitment(signer, commitmentHash, signature) {
    if (signer !== 0 && signer !== 1) throw new Error("signer must be player 0 or 1");
    this.#input(concat([
      Uint8Array.of(signer),
      bytes(commitmentHash, 32, "commitmentHash"),
      bytes(signature, 64, "signature"),
    ]));
    this.#check(this.exports.dealer_verify_offchain_commitment());
  }
  evaluateSeven(cards) {
    this.#input(bytes(cards, 7, "seven cards"));
    this.#check(this.exports.dealer_evaluate_seven());
    const result = this.#output();
    if (result.byteLength !== 5) throw new Error("malformed poker evaluation");
    return { score: new DataView(result.buffer, result.byteOffset, 4).getUint32(0, true), subset: result[4] };
  }
  gateLeaf(slot, rawSum) {
    this.#check(this.exports.dealer_gate_leaf(slot, rawSum));
    const value=this.#output();if(value.byteLength<169)throw new Error("malformed DLOG52 gate leaf");
    let offset=0;const take=(length)=>{const result=value.slice(offset,offset+length);offset+=length;return result;};
    const dealId=take(32),metadata=take(3),authorizer=take(32),internalKey=take(32),merkleRoot=take(32),outputScript=take(34);
    const view=new DataView(value.buffer,value.byteOffset,value.byteLength);const scriptLength=view.getUint16(offset,true);offset+=2;const script=take(scriptLength);const controlLength=view.getUint16(offset,true);offset+=2;const controlBlock=take(controlLength);
    if(offset!==value.byteLength||metadata[0]!==slot||metadata[1]!==rawSum)throw new Error("inconsistent DLOG52 gate leaf");
    return {dealId,slot:metadata[0],rawSum:metadata[1],cardId:metadata[2],authorizer,internalKey,merkleRoot,outputScript,script,controlBlock};
  }
  clear() { this.exports.dealer_clear(); }

  #input(value) {
    const source = bytes(value, undefined, "DLOG52 input");
    this.#check(this.exports.dealer_begin_input(source.byteLength));
    this.#write(this.exports.dealer_input_ptr(), source);
  }
  #write(pointer, source) {
    const end = pointer + source.byteLength;
    if (!Number.isSafeInteger(pointer) || pointer <= 0 || end > this.exports.memory.buffer.byteLength) throw new Error("invalid DLOG52 Wasm region");
    new Uint8Array(this.exports.memory.buffer, pointer, source.byteLength).set(source);
  }
  #output() {
    const pointer = this.exports.dealer_output_ptr();
    const length = this.exports.dealer_output_len();
    if (length === 0 || pointer + length > this.exports.memory.buffer.byteLength) throw new Error("invalid DLOG52 output region");
    return Uint8Array.from(new Uint8Array(this.exports.memory.buffer, pointer, length));
  }
  #check(status) {
    if (status === 1) return;
    const pointer = this.exports.dealer_error_ptr();
    const length = this.exports.dealer_error_len();
    const message = length > 0 && pointer + length <= this.exports.memory.buffer.byteLength
      ? new TextDecoder().decode(new Uint8Array(this.exports.memory.buffer, pointer, length)) : "DLOG52 Wasm operation failed";
    throw new Error(message);
  }
}
