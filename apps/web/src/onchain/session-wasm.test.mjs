import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { client, decode, encode } from "./wasm-client.js";

test("bundled session exposes split recovery without colliding with crypto opcodes", async () => {
  const raw = await readFile(new URL("../../public/wasm/session.wasm", import.meta.url));
  const module = await WebAssembly.compile(raw);
  const wasm = await client(module);
  assert.equal(wasm.checkpointPartsVersion, 1);
  const seed = new Array(32).fill(1);
  const keys = [decode(wasm.call(2, Uint8Array.from(seed))),
    decode(wasm.call(2, new Uint8Array(32).fill(2)))];
  keys.sort((a, b) => Buffer.compare(Buffer.from(a.identity), Buffer.from(b.identity)));
  const terms = { regtest: true, identities: keys.map((k) => k.identity),
    reveal_keys: [keys[1].reveal, keys[0].reveal], origin: `${"01".repeat(32)}:0`,
    origin_value: 45900, nonce: new Array(32).fill(3), full: false,
    fee_multiplier: 1, csv: 2 };
  wasm.call(1, encode({ seed, terms }));
  const journal = wasm.call(50);
  assert.deepEqual(journal, wasm.call(16));
  assert.equal(wasm.call(51).length, 0);
  assert.throws(() => wasm.call(31), /crypto worker not initialized/);
  const restored = await client(module);
  restored.call(17, journal);
  assert.deepEqual(restored.call(50), journal);
});
