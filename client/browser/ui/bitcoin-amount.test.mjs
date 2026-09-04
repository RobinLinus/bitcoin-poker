import assert from "node:assert/strict";

import { formatBitcoinAmount, formatBitcoinFeeRate } from "./bitcoin-amount.js";

assert.equal(formatBitcoinAmount(0), "₿0");
assert.equal(formatBitcoinAmount(10_000), "₿10,000");
assert.equal(formatBitcoinAmount(Number.MAX_SAFE_INTEGER), "₿9,007,199,254,740,991");
assert.equal(formatBitcoinAmount(21_000_000_000_000_000n), "₿21,000,000,000,000,000");
assert.throws(() => formatBitcoinAmount(-1), /nonnegative/u);
assert.throws(() => formatBitcoinAmount(1.5), /safe integer/u);
assert.throws(() => formatBitcoinAmount(Number.MAX_SAFE_INTEGER + 1), /safe integer/u);
assert.throws(() => formatBitcoinAmount("10000"), /safe integer/u);
assert.equal(formatBitcoinFeeRate(1), "₿1/vB");
assert.equal(formatBitcoinFeeRate(1.09), "₿1.09/vB");
assert.equal(formatBitcoinFeeRate(1_000.25), "₿1,000.25/vB");
assert.throws(() => formatBitcoinFeeRate(-0.1), /nonnegative/u);

process.stdout.write("BIP-177 Bitcoin amount formatter tests ok\n");
