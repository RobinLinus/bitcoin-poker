import { formatBitcoinAmount } from "../ui/bitcoin-amount.js";

function positiveSafeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer`);
  }
  return value;
}

function blind(name, abbreviation, amountSat) {
  const amount = formatBitcoinAmount(amountSat);
  return Object.freeze({
    name,
    abbreviation,
    amountSat,
    amount,
    badge: `${abbreviation} · ${amount}`,
  });
}

/**
 * Present the audited table unit from runtime configuration as poker blinds.
 * Seat assignment is intentionally withheld until Rust exposes the browser's
 * canonical role; the configured button/dealer is the heads-up small blind.
 */
export function tableBlindView(gameConfig, canonicalRole) {
  if (!gameConfig || typeof gameConfig !== "object") {
    throw new TypeError("game config is required");
  }
  const smallBlindSat = positiveSafeInteger(gameConfig.unitSat, "game unit");
  const bigBlindSat = positiveSafeInteger(
    smallBlindSat + smallBlindSat,
    "big blind",
  );
  const smallBlind = blind("Small blind", "SB", smallBlindSat);
  const bigBlind = blind("Big blind", "BB", bigBlindSat);

  if (canonicalRole === undefined || canonicalRole === null) {
    return Object.freeze({ smallBlind, bigBlind, localBlind: null, opponentBlind: null });
  }
  if (canonicalRole !== 0 && canonicalRole !== 1) {
    throw new TypeError("canonical role must be Alice (0) or Bob (1)");
  }
  const buttonRole = gameConfig.button === "alice"
    ? 0
    : gameConfig.button === "bob"
      ? 1
      : null;
  if (buttonRole === null) {
    throw new TypeError("game button must be alice or bob");
  }
  const localBlind = canonicalRole === buttonRole ? smallBlind : bigBlind;
  const opponentBlind = canonicalRole === buttonRole ? bigBlind : smallBlind;
  return Object.freeze({ smallBlind, bigBlind, localBlind, opponentBlind });
}
