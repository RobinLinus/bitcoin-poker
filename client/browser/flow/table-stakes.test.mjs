import assert from "node:assert/strict";

import { tableBlindView } from "./table-stakes.js";

const config = Object.freeze({ unitSat: 2_843, button: "alice" });

assert.deepEqual(tableBlindView(config), {
  smallBlind: {
    name: "Small blind",
    abbreviation: "SB",
    amountSat: 2_843,
    amount: "₿2,843",
    badge: "SB · ₿2,843",
  },
  bigBlind: {
    name: "Big blind",
    abbreviation: "BB",
    amountSat: 5_686,
    amount: "₿5,686",
    badge: "BB · ₿5,686",
  },
  localBlind: null,
  opponentBlind: null,
});

const aliceView = tableBlindView(config, 0);
assert.equal(aliceView.localBlind, aliceView.smallBlind);
assert.equal(aliceView.opponentBlind, aliceView.bigBlind);

const bobView = tableBlindView(config, 1);
assert.equal(bobView.localBlind, bobView.bigBlind);
assert.equal(bobView.opponentBlind, bobView.smallBlind);

const bobButtonView = tableBlindView({ unitSat: 125, button: "bob" }, 1);
assert.equal(bobButtonView.localBlind.badge, "SB · ₿125");
assert.equal(bobButtonView.opponentBlind.badge, "BB · ₿250");

assert.throws(() => tableBlindView(null), /game config is required/);
assert.throws(() => tableBlindView({ unitSat: 0, button: "alice" }), /game unit/);
assert.throws(
  () => tableBlindView({ unitSat: Number.MAX_SAFE_INTEGER, button: "alice" }),
  /big blind/,
);
assert.throws(() => tableBlindView(config, 2), /canonical role/);
assert.throws(() => tableBlindView({ unitSat: 1, button: "dealer" }, 0), /game button/);

process.stdout.write("table blind view tests ok\n");
