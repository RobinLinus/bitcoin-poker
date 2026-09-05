const BITCOIN_BASE_UNIT_SYMBOL = "₿";

function integralBaseUnits(value) {
  if (typeof value === "bigint") {
    if (value < 0n) throw new TypeError("Bitcoin amount must be nonnegative");
    return value.toString();
  }
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError("Bitcoin amount must be a nonnegative safe integer");
  }
  return String(value);
}

/** Format integral Bitcoin base units using the BIP-177 symbol convention. */
export function formatBitcoinAmount(value) {
  const digits = integralBaseUnits(value);
  return `${BITCOIN_BASE_UNIT_SYMBOL}${digits.replace(/\B(?=(\d{3})+(?!\d))/gu, ",")}`;
}

/** Format a base-unit-per-vbyte rate without reverting to legacy unit labels. */
export function formatBitcoinFeeRate(value) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new TypeError("Bitcoin fee rate must be a finite nonnegative number");
  }
  const formatted = value.toLocaleString("en-US", {
    maximumFractionDigits: 20,
    useGrouping: true,
  });
  return `${BITCOIN_BASE_UNIT_SYMBOL}${formatted}/vB`;
}
