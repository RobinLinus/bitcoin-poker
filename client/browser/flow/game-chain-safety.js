export const OriginSpendDisposition = Object.freeze({
  REFUND: "refund",
  ACTIVATION: "activation",
  RECOVERY_PENDING: "recovery-pending",
  UNEXPECTED: "unexpected",
});

function txid(value, label, optional = false) {
  if (optional && value === null) return null;
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be one canonical display-order txid`);
  }
  return value;
}

function bytesToHex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Extract the reducer-authenticated activation transaction id without falling
 * back to a chain observation. Undefined means the reducer has not authorized
 * activation yet; every present value must use the projected byte contract.
 */
export function activationTxidFromProjection(projection) {
  const candidate = projection?.status?.activationTxid;
  if (candidate === undefined || candidate === null) return null;
  if (!(candidate instanceof Uint8Array) || candidate.byteLength !== 32) {
    throw new Error("the reducer projected a malformed activation transaction id");
  }
  return bytesToHex(candidate);
}

/** Bind the first authenticated activation id and reject later equivocation. */
export function bindExpectedActivationTxid(current, candidate) {
  const bound = txid(current, "current activation txid", true);
  const next = txid(candidate, "activation txid");
  if (bound !== null && bound !== next) {
    throw new Error("the authenticated activation transaction id changed");
  }
  return next;
}

/**
 * Classify the independently observed origin spender without ever learning an
 * expected transaction id from the chain observation itself.
 */
export function classifyOriginSpend({
  spendingTxid,
  refundTxid,
  expectedActivationTxid,
  activationRecoveryPending = false,
}) {
  const spending = txid(spendingTxid, "origin spender");
  const refund = txid(refundTxid, "refund txid");
  const activation = txid(expectedActivationTxid, "activation txid", true);
  if (spending === refund) return OriginSpendDisposition.REFUND;
  if (activation !== null && spending === activation) {
    return OriginSpendDisposition.ACTIVATION;
  }
  if (activation === null && activationRecoveryPending === true) {
    return OriginSpendDisposition.RECOVERY_PENDING;
  }
  return OriginSpendDisposition.UNEXPECTED;
}
