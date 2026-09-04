import assert from "node:assert/strict";

import {
  OriginSpendDisposition,
  activationTxidFromProjection,
  bindExpectedActivationTxid,
  classifyOriginSpend,
} from "./game-chain-safety.js";

const spender = "11".repeat(32);
const refund = "22".repeat(32);
const activation = "33".repeat(32);

assert.equal(activationTxidFromProjection({ status: {} }), null);
assert.equal(activationTxidFromProjection({
  status: { activationTxid: Uint8Array.from({ length: 32 }, () => 0x33) },
}), activation);
assert.throws(
  () => activationTxidFromProjection({ status: { activationTxid: new ArrayBuffer(32) } }),
  /malformed activation transaction id/,
);
assert.equal(bindExpectedActivationTxid(null, activation), activation);
assert.equal(bindExpectedActivationTxid(activation, activation), activation);
assert.throws(
  () => bindExpectedActivationTxid(activation, spender),
  /activation transaction id changed/,
);

assert.equal(classifyOriginSpend({
  spendingTxid: refund,
  refundTxid: refund,
  expectedActivationTxid: null,
  activationRecoveryPending: true,
}), OriginSpendDisposition.REFUND);

assert.equal(classifyOriginSpend({
  spendingTxid: activation,
  refundTxid: refund,
  expectedActivationTxid: activation,
}), OriginSpendDisposition.ACTIVATION);

assert.equal(classifyOriginSpend({
  spendingTxid: spender,
  refundTxid: refund,
  expectedActivationTxid: null,
  activationRecoveryPending: true,
}), OriginSpendDisposition.RECOVERY_PENDING);

assert.equal(classifyOriginSpend({
  spendingTxid: spender,
  refundTxid: refund,
  expectedActivationTxid: null,
  activationRecoveryPending: false,
}), OriginSpendDisposition.UNEXPECTED);

assert.equal(classifyOriginSpend({
  spendingTxid: spender,
  refundTxid: refund,
  expectedActivationTxid: activation,
}), OriginSpendDisposition.UNEXPECTED);

assert.throws(() => classifyOriginSpend({
  spendingTxid: "11",
  refundTxid: refund,
  expectedActivationTxid: activation,
}), /canonical display-order txid/);

process.stdout.write("origin spend classification tests ok\n");
