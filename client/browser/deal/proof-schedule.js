const DEAL_PROOF_SLOTS = 9;
const FALLBACK_HARDWARE_CONCURRENCY = 4;
const MAX_PROOF_WORKERS = 2;

export function proofExecutionMode(attempt) {
  if (!Number.isSafeInteger(attempt) || attempt < 0) {
    throw new TypeError("DEAL attempt must be a non-negative safe integer");
  }
  return attempt === 0 ? "parallel" : "resident";
}

/**
 * Splits independent proof slots across a small bounded Worker pool. This
 * keeps scheduling latency low while still parallelizing independent proofs.
 */
export function scheduleProofSlots(
  hardwareConcurrency,
  slotCount = DEAL_PROOF_SLOTS,
) {
  if (!Number.isSafeInteger(slotCount) || slotCount < 1) {
    throw new TypeError("proof slot count must be a positive safe integer");
  }
  const logicalCpus = Number.isSafeInteger(hardwareConcurrency) && hardwareConcurrency > 0
    ? hardwareConcurrency
    : FALLBACK_HARDWARE_CONCURRENCY;
  const workerCount = Math.min(
    slotCount,
    MAX_PROOF_WORKERS,
    Math.max(1, Math.floor(logicalCpus / 2)),
  );
  const assignments = Array.from({ length: workerCount }, () => []);
  for (let slot = 0; slot < slotCount; slot += 1) {
    assignments[slot % workerCount].push(slot);
  }
  return assignments;
}
