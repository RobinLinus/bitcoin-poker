import test from "node:test";
import assert from "node:assert/strict";
import { accountReport } from "./report.js";
test("recovery recomputes fees from the full confirmed chain", () => {
  const r = {
    funding: { inputValue: 720846 },
    transactions: [
      { outputs: [{ value: 91400 }, { value: 627446 }] },
      { outputs: [{ value: 90400 }] },
      { outputs: [{ value: 15900 }, { value: 16300 }] },
    ],
    ok: true,
  };
  accountReport(r);
  assert.equal(r.totalFees, 61200);
  assert.deepEqual(
    r.transactions.map((t) => t.fee),
    [2000, 1000, 58200],
  );
  assert.deepEqual(r.payouts, [{ value: 15900 }, { value: 16300 }]);
  assert.throws(() =>
    accountReport({
      funding: { inputValue: 1 },
      transactions: [{ outputs: [{ value: 2 }] }],
    }),
  );
});
