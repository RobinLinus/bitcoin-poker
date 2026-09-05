const VERSION = 1;
const ZERO_HASH = "0".repeat(64);
const STREET_CODES = Object.freeze({ preflop: 0, flop: 1, turn: 2, river: 3 });
const ACTION_CODES = Object.freeze({ fold: 0, check: 1, call: 2, aggressive: 3 });
const MAX_AUTHORIZED_TRANSACTION_HEX = 800_000;

function assertHex(value, bytes, label) {
  if (typeof value !== "string" || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`, "u").test(value)) {
    throw new Error(`${label} must be ${bytes} canonical bytes`);
  }
  return value;
}

function assertUint(value, maximum, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new Error(`${label} is outside its canonical range`);
  }
  return value;
}

function hexBytes(value) {
  return Uint8Array.from(value.match(/../gu) ?? [], (byte) => Number.parseInt(byte, 16));
}

function toHex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function u32(value) {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, value, true);
  return result;
}

function concat(parts) {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function canonicalBody(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("off-chain commitment body is malformed");
  }
  const transactionHex = value.chain?.authorizedTransaction;
  if (value.chain != null && (typeof transactionHex !== "string" ||
      transactionHex.length === 0 || transactionHex.length % 2 !== 0 ||
      transactionHex.length > MAX_AUTHORIZED_TRANSACTION_HEX ||
      !/^[0-9a-f]+$/u.test(transactionHex))) {
    throw new Error("authorized transaction is outside its canonical bound");
  }
  const chain = value.chain == null ? null : {
    parentNodeId: assertHex(value.chain.parentNodeId, 32, "parent node id"),
    childNodeId: assertHex(value.chain.childNodeId, 32, "child node id"),
    childTxid: assertHex(value.chain.childTxid, 32, "child txid"),
    authorizedTransaction: transactionHex,
  };
  if (!(value.street in STREET_CODES) || !(value.action in ACTION_CODES)) {
    throw new Error("off-chain commitment has an unknown poker transition");
  }
  if (value.version !== VERSION) throw new Error("unsupported off-chain commitment version");
  const body = {
    version: VERSION,
    gameId: assertHex(value.gameId, 32, "game id"),
    hand: assertUint(value.hand, 0xffff_ffff, "hand"),
    sequence: assertUint(value.sequence, 0xffff_ffff, "sequence"),
    previous: assertHex(value.previous, 32, "previous commitment"),
    actor: assertUint(value.actor, 1, "actor"),
    street: value.street,
    action: value.action,
    chain,
  };
  if (Object.keys(value).length !== Object.keys(body).length) {
    throw new Error("off-chain commitment contains uncommitted fields");
  }
  return body;
}

function encodeBody(value) {
  const body = canonicalBody(value);
  const tx = body.chain ? hexBytes(body.chain.authorizedTransaction) : new Uint8Array();
  return concat([
    new TextEncoder().encode("BP52/offchain-move/v1\0"),
    hexBytes(body.gameId),
    u32(body.hand),
    u32(body.sequence),
    hexBytes(body.previous),
    Uint8Array.of(body.actor, STREET_CODES[body.street], ACTION_CODES[body.action]),
    Uint8Array.of(body.chain ? 1 : 0),
    body.chain ? hexBytes(body.chain.parentNodeId) : new Uint8Array(),
    body.chain ? hexBytes(body.chain.childNodeId) : new Uint8Array(),
    body.chain ? hexBytes(body.chain.childTxid) : new Uint8Array(),
    u32(tx.byteLength),
    tx,
  ]);
}

export async function offchainCommitmentHash(body) {
  return toHex(await sha256(encodeBody(body)));
}

export async function offchainGenesisHash(gameId, hand) {
  assertHex(gameId, 32, "game id");
  assertUint(hand, 0xffff_ffff, "hand");
  return toHex(await sha256(concat([
    new TextEncoder().encode("BP52/offchain-genesis/v1\0"),
    hexBytes(gameId),
    u32(hand),
  ])));
}

function signatureHex(value, label) {
  return assertHex(value, 64, label);
}

function canonicalTransaction(value, label = "transaction") {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is malformed`);
  }
  const authorizedTransaction = value.authorizedTransaction;
  if (typeof authorizedTransaction !== "string" || authorizedTransaction.length === 0 ||
      authorizedTransaction.length % 2 !== 0 ||
      authorizedTransaction.length > MAX_AUTHORIZED_TRANSACTION_HEX ||
      !/^[0-9a-f]+$/u.test(authorizedTransaction)) {
    throw new Error(`${label} bytes are outside the canonical bound`);
  }
  return {
    txid: assertHex(value.txid, 32, `${label} txid`),
    authorizedTransaction,
  };
}

function canonicalActivation(value) {
  if (value == null) return null;
  const transaction = canonicalTransaction(value, "activation");
  return {
    ...transaction,
    childNodeId: assertHex(value.childNodeId, 32, "activation child node id"),
  };
}

/**
 * Two-phase, hash-linked off-chain move ratchet.
 *
 * The actor proposes and signs one exact transition. The peer validates it,
 * persists a countersignature, and only then returns an acknowledgement. The
 * actor persists the same dual-signed record before exposing it as committed.
 */
export class SignedMoveLog {
  constructor({ gameId, hand, localRole, sign, verify, load, save, activation = null }) {
    this.gameId = assertHex(gameId, 32, "game id");
    this.hand = assertUint(hand, 0xffff_ffff, "hand");
    this.localRole = assertUint(localRole, 1, "local role");
    if (typeof sign !== "function" || typeof verify !== "function") {
      throw new Error("ratchet signing callbacks are required");
    }
    this.sign = sign;
    this.verify = verify;
    this.load = load ?? (() => null);
    this.save = save ?? (() => {});
    this.activation = canonicalActivation(activation);
    this.genesis = ZERO_HASH;
    this.records = [];
    this.pending = null;
    this.disputeState = null;
  }

  async initialize() {
    this.genesis = await offchainGenesisHash(this.gameId, this.hand);
    const saved = await this.load();
    if (saved != null) await this.#restore(saved);
    return this;
  }

  get sequence() { return this.records.length; }
  get head() { return this.records.at(-1)?.hash ?? this.genesis; }
  get committed() { return this.records.map((record) => structuredClone(record)); }
  get pendingProposal() {
    if (!this.pending) return null;
    return {
      type: "proposal",
      body: structuredClone(this.pending.body),
      hash: this.pending.hash,
      signature: this.pending.signatures[this.localRole],
    };
  }

  async propose({ actor, street, action, chain = null }) {
    if (this.disputeState) throw new Error("the channel is already recovering on-chain");
    if (this.pending) throw new Error("an off-chain move is already awaiting its countersignature");
    if (actor !== this.localRole) throw new Error("only the acting player may propose this move");
    const body = canonicalBody({
      version: VERSION,
      gameId: this.gameId,
      hand: this.hand,
      sequence: this.sequence,
      previous: this.head,
      actor,
      street,
      action,
      chain,
    });
    const hash = await offchainCommitmentHash(body);
    const signature = signatureHex(await this.sign(hash), "proposal signature");
    await this.verify(actor, hash, signature);
    this.pending = { body, hash, signatures: { [actor]: signature } };
    await this.#persist();
    return { type: "proposal", body, hash, signature };
  }

  async acceptProposal(message, validateTransition) {
    if (this.disputeState) throw new Error("the channel is already recovering on-chain");
    const proposal = await this.#validateProposal(message);
    if (proposal.body.actor === this.localRole) {
      throw new Error("a player cannot countersign its own proposal");
    }
    const prior = this.records[proposal.body.sequence];
    if (prior) {
      if (prior.hash !== proposal.hash) throw new Error("equivocation at an already committed sequence");
      return this.#ack(prior);
    }
    this.#requireNext(proposal.body);
    if (typeof validateTransition !== "function" || !(await validateTransition(proposal.body))) {
      throw new Error("off-chain move is not legal from the committed state");
    }
    const counterSignature = signatureHex(await this.sign(proposal.hash), "countersignature");
    await this.verify(this.localRole, proposal.hash, counterSignature);
    const record = {
      body: proposal.body,
      hash: proposal.hash,
      signatures: {
        [proposal.body.actor]: proposal.signature,
        [this.localRole]: counterSignature,
      },
    };
    this.records.push(record);
    await this.#persist();
    return this.#ack(record);
  }

  async acceptAcknowledgement(message) {
    if (!this.pending) {
      const prior = this.records[message?.sequence];
      if (prior && prior.hash === message?.hash) return structuredClone(prior);
      throw new Error("unexpected off-chain acknowledgement");
    }
    if (!message || message.type !== "ack" ||
        message.sequence !== this.pending.body.sequence || message.hash !== this.pending.hash) {
      throw new Error("off-chain acknowledgement does not match the pending move");
    }
    const peer = 1 - this.localRole;
    const counterSignature = signatureHex(message.signature, "countersignature");
    await this.verify(peer, this.pending.hash, counterSignature);
    const record = {
      body: this.pending.body,
      hash: this.pending.hash,
      signatures: { ...this.pending.signatures, [peer]: counterSignature },
    };
    this.records.push(record);
    this.pending = null;
    await this.#persist();
    return structuredClone(record);
  }

  disputePackage() {
    const transactions = this.records
      .map((record) => record.body.chain)
      .filter((chain) => chain != null)
      .map((chain) => ({ ...chain }));
    return Object.freeze({
      version: VERSION,
      gameId: this.gameId,
      hand: this.hand,
      sequence: this.sequence,
      head: this.head,
      activation: this.activation ? { ...this.activation } : null,
      commitments: this.committed,
      transactions,
    });
  }

  /** Submit the retained selected-edge path when cooperation stops.
   *
   * A production adapter supplies its authenticated Bitcoin broadcaster. The
   * method fails closed unless every committed move contains one contiguous,
   * fully authorized transaction; an off-chain-only demo record can never be
   * mistaken for an enforceable exit.
   */
  async broadcastDisputePath(broadcast) {
    if (typeof broadcast !== "function") throw new Error("a Bitcoin broadcaster is required");
    const path = this.records.map((record) => record.body.chain);
    if (path.length === 0 || path.some((chain) => chain == null)) {
      throw new Error("the off-chain history has no complete enforceable transaction path");
    }
    for (let index = 1; index < path.length; index += 1) {
      if (path[index].parentNodeId !== path[index - 1].childNodeId) {
        throw new Error("the retained transaction path is not contiguous");
      }
    }
    const submitted = [];
    for (let index = 0; index < path.length; index += 1) {
      const transaction = path[index];
      await broadcast(transaction.authorizedTransaction, {
        index,
        parentNodeId: transaction.parentNodeId,
        childNodeId: transaction.childNodeId,
        childTxid: transaction.childTxid,
      });
      submitted.push(transaction.childTxid);
    }
    return submitted;
  }

  /** Publish activation, the latest selected descendant path, and its timeout.
   *
   * Every stage is durably checkpointed and safe to retry. Descendants are
   * confirmed in bounded batches so the longest game cannot exceed Bitcoin
   * Core's unconfirmed-ancestor policy. Timeout construction is delegated to
   * the authenticated chain runtime only after the latest state confirms and
   * its exact CSV maturity has been observed.
   */
  async escalateDispute({
    broadcast,
    waitForConfirmation,
    waitForTimeoutMaturity,
    buildTimeout,
    maxUnconfirmedAncestors = 20,
  }) {
    if (typeof broadcast !== "function" || typeof waitForConfirmation !== "function") {
      throw new Error("Bitcoin broadcast and confirmation adapters are required");
    }
    if (!this.activation) throw new Error("the signed activation transaction is unavailable");
    if (!Number.isSafeInteger(maxUnconfirmedAncestors) ||
        maxUnconfirmedAncestors < 1 || maxUnconfirmedAncestors > 24) {
      throw new Error("the unconfirmed ancestor batch bound must be between 1 and 24");
    }
    const path = this.records.map((record) => record.body.chain);
    if (path.length === 0 || path.some((chain) => chain == null)) {
      throw new Error("the off-chain history has no complete enforceable transaction path");
    }
    if (path[0].parentNodeId !== this.activation.childNodeId) {
      throw new Error("the selected path does not descend from the signed activation");
    }
    for (let index = 1; index < path.length; index += 1) {
      if (path[index].parentNodeId !== path[index - 1].childNodeId) {
        throw new Error("the retained transaction path is not contiguous");
      }
    }

    const binding = `${this.gameId}:${this.hand}:${this.head}`;
    if (this.disputeState && this.disputeState.binding !== binding) {
      throw new Error("saved on-chain recovery belongs to another ratchet head");
    }
    this.disputeState ??= { binding, activationConfirmed: false, nextTransaction: 0, timeoutTxid: null };
    await this.#persist();

    if (!this.disputeState.activationConfirmed) {
      await broadcast(this.activation.authorizedTransaction, {
        stage: "activation",
        txid: this.activation.txid,
      });
      await waitForConfirmation(this.activation.txid, { stage: "activation" });
      this.disputeState.activationConfirmed = true;
      await this.#persist();
    }

    while (this.disputeState.nextTransaction < path.length) {
      const index = this.disputeState.nextTransaction;
      const transaction = path[index];
      await broadcast(transaction.authorizedTransaction, {
        stage: "descendant",
        index,
        parentNodeId: transaction.parentNodeId,
        childNodeId: transaction.childNodeId,
        txid: transaction.childTxid,
      });
      this.disputeState.nextTransaction = index + 1;
      await this.#persist();
      const batchBoundary = this.disputeState.nextTransaction % maxUnconfirmedAncestors === 0;
      const last = this.disputeState.nextTransaction === path.length;
      if (batchBoundary || last) {
        await waitForConfirmation(transaction.childTxid, { stage: "descendant", index });
      }
    }

    const latest = path.at(-1);
    if (typeof buildTimeout !== "function") {
      return { latestTxid: latest.childTxid, timeoutTxid: null };
    }
    if (typeof waitForTimeoutMaturity !== "function") {
      throw new Error("CSV maturity observation is required before timeout construction");
    }
    await waitForTimeoutMaturity({
      parentNodeId: latest.childNodeId,
      parentTxid: latest.childTxid,
    });
    const timeout = canonicalTransaction(await buildTimeout({
      parentNodeId: latest.childNodeId,
      parentTxid: latest.childTxid,
    }), "timeout");
    if (this.disputeState.timeoutTxid && this.disputeState.timeoutTxid !== timeout.txid) {
      throw new Error("the chain runtime produced a conflicting timeout transaction");
    }
    await broadcast(timeout.authorizedTransaction, { stage: "timeout", txid: timeout.txid });
    this.disputeState.timeoutTxid = timeout.txid;
    await this.#persist();
    return { latestTxid: latest.childTxid, timeoutTxid: timeout.txid };
  }

  /** Publish a mutually signed direct-origin close for this exact final head. */
  async broadcastCooperativeClose(close, { validate, broadcast }) {
    if (this.pending) throw new Error("cannot close while a move is awaiting countersignature");
    if (typeof validate !== "function" || typeof broadcast !== "function") {
      throw new Error("cooperative close validation and broadcast adapters are required");
    }
    if (!close || close.head !== this.head) {
      throw new Error("cooperative close does not settle the latest agreed state");
    }
    const transaction = canonicalTransaction(close, "cooperative close");
    if (!(await validate({
      gameId: this.gameId,
      hand: this.hand,
      head: this.head,
      ...transaction,
    }))) {
      throw new Error("cooperative close failed chain-runtime validation");
    }
    await broadcast(transaction.authorizedTransaction, {
      stage: "cooperative-close",
      txid: transaction.txid,
    });
    return transaction.txid;
  }

  async #validateProposal(message) {
    if (!message || message.type !== "proposal") throw new Error("malformed off-chain proposal");
    const body = canonicalBody(message.body);
    const hash = await offchainCommitmentHash(body);
    if (hash !== message.hash) throw new Error("off-chain proposal hash mismatch");
    const signature = signatureHex(message.signature, "proposal signature");
    await this.verify(body.actor, hash, signature);
    return { body, hash, signature };
  }

  #requireNext(body) {
    if (body.gameId !== this.gameId || body.hand !== this.hand ||
        body.sequence !== this.sequence || body.previous !== this.head) {
      throw new Error("stale, skipped, or cross-session off-chain move");
    }
  }

  #ack(record) {
    return {
      type: "ack",
      sequence: record.body.sequence,
      hash: record.hash,
      signature: record.signatures[this.localRole],
    };
  }

  async #persist() {
    await this.save({
      version: VERSION,
      gameId: this.gameId,
      hand: this.hand,
      records: this.records,
      pending: this.pending,
      disputeState: this.disputeState,
    });
  }

  async #restore(saved) {
    if (!saved || saved.version !== VERSION || saved.gameId !== this.gameId || saved.hand !== this.hand ||
        !Array.isArray(saved.records)) throw new Error("saved off-chain ratchet belongs to another session");
    const records = [];
    for (const candidate of saved.records) {
      const body = canonicalBody(candidate.body);
      const expectedPrevious = records.at(-1)?.hash ?? this.genesis;
      if (body.sequence !== records.length || body.previous !== expectedPrevious) {
        throw new Error("saved off-chain ratchet is not contiguous");
      }
      const hash = await offchainCommitmentHash(body);
      if (hash !== candidate.hash) throw new Error("saved off-chain commitment hash mismatch");
      const signatures = {};
      for (const role of [0, 1]) {
        const signature = signatureHex(candidate.signatures?.[role], "saved commitment signature");
        await this.verify(role, hash, signature);
        signatures[role] = signature;
      }
      records.push({ body, hash, signatures });
    }
    this.records = records;
    if (saved.disputeState != null) {
      if (!saved.disputeState || typeof saved.disputeState.binding !== "string" ||
          typeof saved.disputeState.activationConfirmed !== "boolean" ||
          !Number.isSafeInteger(saved.disputeState.nextTransaction) ||
          saved.disputeState.nextTransaction < 0 ||
          saved.disputeState.nextTransaction > records.length ||
          (saved.disputeState.timeoutTxid != null &&
            !/^[0-9a-f]{64}$/u.test(saved.disputeState.timeoutTxid))) {
        throw new Error("saved on-chain recovery state is malformed");
      }
      const binding = `${this.gameId}:${this.hand}:${records.at(-1)?.hash ?? this.genesis}`;
      if (saved.disputeState.binding !== binding) {
        throw new Error("saved on-chain recovery belongs to another ratchet head");
      }
      this.disputeState = structuredClone(saved.disputeState);
    }
    if (saved.pending != null) {
      const body = canonicalBody(saved.pending.body);
      const hash = await offchainCommitmentHash(body);
      this.#requireNext(body);
      if (hash !== saved.pending.hash || body.actor !== this.localRole) {
        throw new Error("saved pending off-chain move is inconsistent");
      }
      const signature = signatureHex(saved.pending.signatures?.[this.localRole], "saved proposal signature");
      await this.verify(this.localRole, hash, signature);
      this.pending = { body, hash, signatures: { [this.localRole]: signature } };
    }
  }
}

export const OFFCHAIN_RATCHET_VERSION = VERSION;
