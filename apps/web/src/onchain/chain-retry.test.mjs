import assert from "node:assert/strict";
import test from "node:test";
import { isTransientChainIndexError } from "./chain-retry.js";
test("indexing races may retry, invalid chain evidence must stop", () => {
  assert.equal(
    isTransientChainIndexError(
      new Error(
        "call: outspend and transaction endpoints disagree about status",
      ),
    ),
    true,
  );
  for (const message of [
    "chain identity mismatch",
    "raw transaction does not match its requested txid",
    "wrong parent",
    "invalid reveal signature",
    "transaction submission failed",
  ]) {
    assert.equal(isTransientChainIndexError(new Error(message)), false);
  }
});
