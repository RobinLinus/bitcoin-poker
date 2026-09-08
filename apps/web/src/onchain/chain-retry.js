/** Retry only known races between independently updated Esplora endpoints. */
export function isTransientChainIndexError(error) {
  return /outspend and transaction endpoints disagree|tip hash and canonical block endpoints remained inconsistent/.test(
    error?.message ?? "",
  );
}
