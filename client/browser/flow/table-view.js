function baseUnits(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be an exact nonnegative Bitcoin amount`);
  }
  return value;
}

/** Map canonical Rust balances to this browser's local/opponent table seats. */
export function tableBalancesForViewer(projected, canonicalRole, startingStackSat) {
  const starting = baseUnits(startingStackSat, "starting stack");
  if (projected === undefined || projected === null) {
    return { localStackSat: starting, opponentStackSat: starting, potSat: 0 };
  }
  const alice = baseUnits(projected.aliceStackSat, "Alice stack");
  const bob = baseUnits(projected.bobStackSat, "Bob stack");
  const pot = baseUnits(projected.potSat, "pot");
  if (canonicalRole !== 0 && canonicalRole !== 1) {
    throw new Error("canonical role must be Alice or Bob once balances are projected");
  }
  return canonicalRole === 0
    ? { localStackSat: alice, opponentStackSat: bob, potSat: pot }
    : { localStackSat: bob, opponentStackSat: alice, potSat: pot };
}
