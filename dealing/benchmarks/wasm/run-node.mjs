import { readFile } from "node:fs/promises";

const wasmUrl = new URL(
  "./target/wasm32-unknown-unknown/release/bp52_wasm_proof_spike.wasm",
  import.meta.url,
);
const bytes = await readFile(wasmUrl);
const { instance } = await WebAssembly.instantiate(bytes);
const { memory, setup_parameters, prove_once, verify_once } = instance.exports;

function run(label, operation) {
  const started = performance.now();
  const code = operation();
  const seconds = (performance.now() - started) / 1_000;
  const result = {
    label,
    seconds,
    code,
    linearMiB: memory.buffer.byteLength / 1_048_576,
    rssMiB: process.memoryUsage().rss / 1_048_576,
  };
  console.log(JSON.stringify(result));
  if (code !== 0) {
    throw new Error(`${label} failed with diagnostic code ${code}`);
  }
}

run("setup", setup_parameters);
run("prove", prove_once);
run("verify", verify_once);

