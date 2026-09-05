import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

globalThis.crypto ??= webcrypto;

const { SignedMoveLog } = await import("./signed-move-log.js");
const gameId = "31".repeat(32);

function fakeIdentity() {
  const signatures = new Map();
  return {
    sign(role) {
      return async (hash) => {
        const signature = `${role.toString(16).padStart(2, "0")}${hash}${"a5".repeat(31)}`;
        signatures.set(`${role}:${hash}`, signature);
        return signature;
      };
    },
    async verify(role, hash, signature) {
      assert.equal(signature, signatures.get(`${role}:${hash}`), "identity signature");
    },
  };
}

async function pair() {
  const identity = fakeIdentity();
  const saved = [null, null];
  const create = async (role) => new SignedMoveLog({
    gameId,
    hand: 7,
    localRole: role,
    sign: identity.sign(role),
    verify: identity.verify,
    load: () => saved[role],
    save: (value) => { saved[role] = structuredClone(value); },
  }).initialize();
  return { a: await create(0), b: await create(1), saved, create };
}

async function fundedPair() {
  const identity = fakeIdentity();
  const saved = [null, null];
  const activation = {
    txid: "30".repeat(32),
    childNodeId: "40".repeat(32),
    authorizedTransaction: "02000000",
  };
  const create = async (role) => new SignedMoveLog({
    gameId,
    hand: 7,
    localRole: role,
    sign: identity.sign(role),
    verify: identity.verify,
    activation,
    load: () => saved[role],
    save: (value) => { saved[role] = structuredClone(value); },
  }).initialize();
  return { a: await create(0), b: await create(1), saved, create };
}

test("two-phase countersigning advances both players to one identical head", async () => {
  const { a, b } = await pair();
  const proposal = await a.propose({ actor: 0, street: "preflop", action: "call" });
  assert.equal(a.sequence, 0, "proposal alone is not committed");
  const ack = await b.acceptProposal(proposal, () => true);
  assert.equal(b.sequence, 1);
  await a.acceptAcknowledgement(ack);
  assert.equal(a.sequence, 1);
  assert.equal(a.head, b.head);
  assert.equal(a.disputePackage().commitments.length, 1);
});

test("replay is idempotent while sibling equivocation and stale moves fail", async () => {
  const { a, b } = await pair();
  const proposal = await a.propose({ actor: 0, street: "preflop", action: "call" });
  const ack = await b.acceptProposal(proposal, () => true);
  const replayAck = await b.acceptProposal(proposal, () => { throw new Error("not rerun"); });
  assert.deepEqual(replayAck, ack);
  await a.acceptAcknowledgement(ack);

  const sibling = structuredClone(proposal);
  sibling.body.action = "fold";
  await assert.rejects(() => b.acceptProposal(sibling, () => true), /hash mismatch/);
  await assert.rejects(
    () => b.acceptProposal({ ...proposal, hash: "11".repeat(32) }, () => true),
    /hash mismatch/,
  );
});

test("illegal transitions are never countersigned", async () => {
  const { a, b } = await pair();
  const proposal = await a.propose({ actor: 0, street: "preflop", action: "check" });
  await assert.rejects(() => b.acceptProposal(proposal, () => false), /not legal/);
  assert.equal(b.sequence, 0);
});

test("durable records recover and authenticated transaction paths form a dispute package", async () => {
  const { a, b, create } = await pair();
  const chain = {
    parentNodeId: "41".repeat(32),
    childNodeId: "42".repeat(32),
    childTxid: "43".repeat(32),
    authorizedTransaction: "02000000",
  };
  const proposal = await a.propose({ actor: 0, street: "preflop", action: "fold", chain });
  const ack = await b.acceptProposal(proposal, () => true);
  await a.acceptAcknowledgement(ack);
  const recovered = await create(0);
  assert.equal(recovered.head, a.head);
  assert.deepEqual(recovered.disputePackage().transactions, [chain]);
  const broadcasts = [];
  assert.deepEqual(
    await recovered.broadcastDisputePath(async (transaction, metadata) => {
      broadcasts.push({ transaction, metadata });
    }),
    [chain.childTxid],
  );
  assert.equal(broadcasts[0].transaction, chain.authorizedTransaction);
});

test("off-chain-only histories fail closed instead of pretending to be enforceable", async () => {
  const { a, b } = await pair();
  const proposal = await a.propose({ actor: 0, street: "preflop", action: "fold" });
  const ack = await b.acceptProposal(proposal, () => true);
  await a.acceptAcknowledgement(ack);
  await assert.rejects(
    () => a.broadcastDisputePath(async () => {}),
    /no complete enforceable transaction path/,
  );
});

test("unresponsive recovery publishes activation, bounded descendant batches, then CSV timeout", async () => {
  const { a, b } = await fundedPair();
  const first = {
    parentNodeId: "40".repeat(32),
    childNodeId: "41".repeat(32),
    childTxid: "51".repeat(32),
    authorizedTransaction: "02000001",
  };
  const second = {
    parentNodeId: first.childNodeId,
    childNodeId: "42".repeat(32),
    childTxid: "52".repeat(32),
    authorizedTransaction: "02000002",
  };
  let proposal = await a.propose({ actor: 0, street: "preflop", action: "call", chain: first });
  let ack = await b.acceptProposal(proposal, () => true);
  await a.acceptAcknowledgement(ack);
  proposal = await b.propose({ actor: 1, street: "flop", action: "check", chain: second });
  ack = await a.acceptProposal(proposal, () => true);
  await b.acceptAcknowledgement(ack);

  const events = [];
  const result = await a.escalateDispute({
    maxUnconfirmedAncestors: 1,
    broadcast: async (_transaction, metadata) => events.push(`broadcast:${metadata.stage}:${metadata.txid}`),
    waitForConfirmation: async (txid, metadata) => events.push(`confirm:${metadata.stage}:${txid}`),
    waitForTimeoutMaturity: async ({ parentTxid }) => events.push(`mature:${parentTxid}`),
    buildTimeout: async () => ({
      txid: "60".repeat(32),
      authorizedTransaction: "02000003",
    }),
  });
  assert.deepEqual(result, { latestTxid: second.childTxid, timeoutTxid: "60".repeat(32) });
  assert.deepEqual(events, [
    `broadcast:activation:${"30".repeat(32)}`,
    `confirm:activation:${"30".repeat(32)}`,
    `broadcast:descendant:${first.childTxid}`,
    `confirm:descendant:${first.childTxid}`,
    `broadcast:descendant:${second.childTxid}`,
    `confirm:descendant:${second.childTxid}`,
    `mature:${second.childTxid}`,
    `broadcast:timeout:${"60".repeat(32)}`,
  ]);
  await assert.rejects(
    () => a.propose({ actor: 0, street: "river", action: "fold" }),
    /already recovering on-chain/,
  );
});

test("cooperative close spends directly from origin only for the latest ratchet head", async () => {
  const { a, b } = await pair();
  const proposal = await a.propose({ actor: 0, street: "preflop", action: "fold" });
  const ack = await b.acceptProposal(proposal, () => true);
  await a.acceptAcknowledgement(ack);
  const broadcasts = [];
  const txid = "70".repeat(32);
  assert.equal(await a.broadcastCooperativeClose({
    head: a.head,
    txid,
    authorizedTransaction: "02000004",
  }, {
    validate: async (close) => close.head === a.head && close.txid === txid,
    broadcast: async (_transaction, metadata) => broadcasts.push(metadata),
  }), txid);
  assert.deepEqual(broadcasts, [{ stage: "cooperative-close", txid }]);
  await assert.rejects(() => a.broadcastCooperativeClose({
    head: "00".repeat(32),
    txid,
    authorizedTransaction: "02000004",
  }, { validate: async () => true, broadcast: async () => {} }), /latest agreed state/);
});
