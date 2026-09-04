import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

const source = async (relative) => readFile(new URL(relative, import.meta.url), "utf8");

test("only the disposable DEAL runtime owns heavyweight proof verification", async () => {
  const [game, gameWasm, chain, gameCargo, chainCargo, chainBrowser] = await Promise.all([
    source("../../crates/bp52-game-session/src/state.rs"),
    source("../../crates/bp52-browser-game-wasm/src/lib.rs"),
    source("../../crates/bp52-browser-chain-wasm/src/lib.rs"),
    source("../../crates/bp52-browser-game-wasm/Cargo.toml"),
    source("../../crates/bp52-browser-chain-wasm/Cargo.toml"),
    source("../chain/chain-runtime.js"),
  ]);

  for (const [name, contents] of [["GAME", `${game}\n${gameWasm}`], ["CHAIN", chain]]) {
    assert.doesNotMatch(
      contents,
      /\bverify_accepted_archive\b|\bHashLengthParameters\b|\bdecode_archive\b/,
      `${name} must never replay the heavyweight DEAL archive`,
    );
  }
  assert.match(chain, /verify_deal_verification/);
  assert.match(chain, /verify_attested_accepted_deal/);
  assert.doesNotMatch(gameWasm, /verifier_entropy|VerifierRng|custom_getrandom/);
  assert.doesNotMatch(gameCargo, /getrandom|clear_on_drop/);
  assert.doesNotMatch(chainCargo, /bp52-circuit/);
  assert.doesNotMatch(chainBrowser, /deal\.archive|accepted DEAL archive/);
});
