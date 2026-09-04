import assert from "node:assert/strict";

import { tableBalancesForViewer } from "./table-view.js";

assert.deepEqual(tableBalancesForViewer(undefined, undefined, 5_686), {
  localStackSat: 5_686,
  opponentStackSat: 5_686,
  potSat: 0,
});
assert.deepEqual(tableBalancesForViewer({
  aliceStackSat: 2_843,
  bobStackSat: 0,
  potSat: 8_529,
}, 0, 5_686), {
  localStackSat: 2_843,
  opponentStackSat: 0,
  potSat: 8_529,
});
assert.deepEqual(tableBalancesForViewer({
  aliceStackSat: 0,
  bobStackSat: 0,
  potSat: 11_372,
}, 1, 5_686), {
  localStackSat: 0,
  opponentStackSat: 0,
  potSat: 11_372,
});
assert.throws(
  () => tableBalancesForViewer({ aliceStackSat: 1, bobStackSat: 2, potSat: 3 }, undefined, 4),
  /canonical role/,
);
assert.throws(
  () => tableBalancesForViewer({ aliceStackSat: -1, bobStackSat: 2, potSat: 3 }, 0, 4),
  /Alice stack/,
);

process.stdout.write("table balance view tests ok\n");
