import { readFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";

const wasmPath = new URL("../apps/web/public/wasm/dealer.wasm", import.meta.url);
const bytes = await readFile(wasmPath);
const imports = {
  __wbindgen_placeholder__: {
    __wbindgen_describe() {},
    __wbg___wbindgen_throw_bb96b2010945f0bc() { throw new Error("wasm-bindgen throw"); },
  },
  __wbindgen_externref_xform__: {
    __wbindgen_externref_table_set_null() {},
    __wbindgen_externref_table_grow() { return 0; },
  },
};
const { instance } = await WebAssembly.instantiate(bytes, imports);
const run = instance.exports.dealer_benchmark;
if (typeof run !== "function") throw new Error("missing dealer_benchmark export");

const cases = [
  [0, "range prove", 100], [1, "range verify", 200],
  [2, "link prove", 500], [3, "link verify", 500],
  [4, "scale prove (108)", 50], [5, "scale verify (108)", 100],
  [6, "decrypt prove (108)", 200], [7, "decrypt verify (108)", 200],
];

for (const [code, name, iterations] of cases) {
  run(code, 1);
  const samples = [];
  for (let sample = 0; sample < 5; sample++) {
    const start = performance.now();
    const checksum = run(code, iterations);
    const elapsed = (performance.now() - start) / iterations;
    if (checksum === 0) throw new Error(`${name} failed`);
    samples.push(elapsed);
  }
  samples.sort((a, b) => a - b);
  const p95 = samples[Math.min(samples.length - 1, Math.floor(samples.length * 0.95))];
  console.log(`${name.padEnd(24)} n=${String(samples.length).padStart(3)} median=${samples[Math.floor(samples.length / 2)].toFixed(3).padStart(9)} ms p95=${p95.toFixed(3).padStart(9)} ms`);
}
console.log(`wasm bytes               ${bytes.length}`);
