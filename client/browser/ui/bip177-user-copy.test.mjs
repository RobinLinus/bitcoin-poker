import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const userDocumentPaths = [
  "../../../README.md",
  "../../../SECURITY.md",
  "../../../chain/README.md",
  "../../../chain/docs/bitcoin-core-regtest.md",
  "../../../chain/fuzz/README.md",
  "../../../chain/test-vectors/README.md",
  "../../../dealing/README.md",
  "../../../dealing/benchmarks/README.md",
  "../../../dealing/benchmarks/wasm/README.md",
  "../../../dealing/fuzz/README.md",
  "../../README.md",
  "../../TESTING.md",
  "../../browser/chain-adapter/README.md",
  "../../browser/chain/README.md",
  "../../browser/deal/README.md",
  "../../browser/game/README.md",
  "../../crates/bp52-game-session/README.md",
  "../../deployments/mutinynet/README.md",
  "../../docs/browser-prototype.md",
  "../../docs/browser-wasm-build.md",
];

const legacyUnit = /\bsats?(?:oshi(?:s)?)?\b/iu;
const documents = await Promise.all(userDocumentPaths.map(async (path) => ({
  path,
  text: await readFile(new URL(path, import.meta.url), "utf8"),
})));
for (const { path, text } of documents) {
  assert.doesNotMatch(text, legacyUnit, `${path} must use BIP-177 display`);
}
assert.match(documents.map(({ text }) => text).join("\n"), /₿10,000/u);

const cli = await readFile(
  new URL("../../../client-cli/src/main.rs", import.meta.url),
  "utf8",
);
assert.doesNotMatch(cli, legacyUnit, "CLI display source must not use legacy unit labels");
assert.match(cli, /format_bip177\(confirmation\.output_value_sat\)/u);

process.stdout.write("BIP-177 user documentation and CLI copy tests ok\n");
