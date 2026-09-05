import assert from "node:assert/strict";
import fs from "node:fs";

const directory = new URL("../../public/", import.meta.url);
const originalFetch = globalThis.fetch;
globalThis.fetch = async (input) => {
  const path = typeof input === "string" ? input : input.url;
  if (path === "/wasm/manifest.json") {
    return new Response(fs.readFileSync(new URL("wasm/manifest.json", directory)), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }
  const match = /^\/wasm\/([a-z]+\.wasm)$/.exec(path);
  if (match) {
    return new Response(fs.readFileSync(new URL(`wasm/${match[1]}`, directory)), {
      status: 200,
      headers: { "content-type": "application/wasm" },
    });
  }
  return originalFetch(input);
};
const { fundingEngine: hooks } = await import("./engine.js");

function hex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function descriptor(secretHex) {
  const { instance } = await WebAssembly.instantiate(
    fs.readFileSync(new URL("wasm/wallet.wasm", directory)),
    {},
  );
  const api = instance.exports;
  const secret = Uint8Array.from(secretHex.match(/../g), (part) => Number.parseInt(part, 16));
  for (let index = 0; index < secret.length; index += 1) {
    assert.equal(api.bp52_wallet_set_secret_byte(index, secret[index]), 1);
  }
  assert.equal(api.bp52_wallet_derive_public_key(), 1);
  assert.equal(api.bp52_wallet_derive_staging_descriptor(1), 1);
  const witnessScriptHex = hex(Uint8Array.from(
    { length: 35 },
    (_, index) => api.bp52_wallet_witness_script_byte(index),
  ));
  const scriptPubKeyHex = hex(Uint8Array.from(
    { length: 34 },
    (_, index) => api.bp52_wallet_script_pubkey_byte(index),
  ));
  api.bp52_wallet_clear();
  secret.fill(0);
  return { witnessScriptHex, scriptPubKeyHex };
}

const aliceSecret = `${"00".repeat(31)}01`;
const bobSecret = `${"00".repeat(31)}02`;
const aliceDescriptor = await descriptor(aliceSecret);
const bobDescriptor = await descriptor(bobSecret);
const shared = {
  version: 2,
  protocolProfileCode: 1,
  networkId: "33".repeat(32),
  roomId: "44".repeat(32),
  sessionNonce: "55".repeat(32),
};
assert.ok(Object.isFrozen(hooks));
const workerDerivedAlice = await hooks.deriveStagingDescriptor({
  privateKeyHex: aliceSecret,
  walletNetworkCode: 1,
});
assert.equal(workerDerivedAlice.witnessScriptHex, aliceDescriptor.witnessScriptHex);
assert.equal(workerDerivedAlice.scriptPubKeyHex, aliceDescriptor.scriptPubKeyHex);
assert.match(workerDerivedAlice.address, /^tb1/u);

const aliceStaging = await hooks.buildStagingFrame({
  ...shared,
  transportRole: "alice",
  stagingFunding: {
    ...aliceDescriptor,
    txid: "11".repeat(32),
    vout: 1,
    valueSat: 27_000,
  },
});
const bobStaging = await hooks.buildStagingFrame({
  ...shared,
  transportRole: "bob",
  stagingFunding: {
    ...bobDescriptor,
    txid: "22".repeat(32),
    vout: 2,
    valueSat: 27_000,
  },
});
assert.deepEqual(Object.keys(aliceStaging), ["stagingFrame"]);

const aliceInput = {
  ...shared,
  transportRole: "alice",
  localStagingFunding: aliceStaging.stagingFrame,
  peerStagingFunding: bobStaging.stagingFrame,
};
const bobInput = {
  ...shared,
  transportRole: "bob",
  localStagingFunding: bobStaging.stagingFrame,
  peerStagingFunding: aliceStaging.stagingFrame,
};
const alicePackage = await hooks.buildPackage(aliceInput);
const bobPackage = await hooks.buildPackage(bobInput);
assert.deepEqual(alicePackage.localStaging, {
  txid: "11".repeat(32),
  vout: 1,
  valueSat: 27_000,
  ...aliceDescriptor,
});
assert.deepEqual(alicePackage.peerStaging, {
  txid: "22".repeat(32),
  vout: 2,
  valueSat: 27_000,
  ...bobDescriptor,
});
for (const field of [
  "packageId",
  "fundingTxid",
  "refundTxid",
  "originWitnessScriptHex",
  "originScriptPubkeyHex",
  "fundingSighashesHex",
  "refundSighashHex",
]) {
  assert.deepEqual(alicePackage[field], bobPackage[field]);
}
assert.notEqual(alicePackage.packageFrame, bobPackage.packageFrame);
assert.equal(alicePackage.peerPackageFrame, bobPackage.packageFrame);
assert.equal(bobPackage.peerPackageFrame, alicePackage.packageFrame);
assert.notEqual(alicePackage.localInputIndex, bobPackage.localInputIndex);

function boundInput(input, localPackage, peerPackage) {
  return {
    ...input,
    packageFrame: localPackage.packageFrame,
    peerPackageFrame: peerPackage.packageFrame,
    localInputIndex: localPackage.localInputIndex,
  };
}
const aliceBound = boundInput(aliceInput, alicePackage, bobPackage);
const bobBound = boundInput(bobInput, bobPackage, alicePackage);

async function refundSignature(input, built, secret) {
  return (await hooks.createRefundSignature({
    ...input,
    sighashHex: built.refundSighashHex,
    localSecretKeyHex: secret,
  })).signatureFrame;
}
const aliceRefundSignature = await refundSignature(aliceBound, alicePackage, aliceSecret);
const bobRefundSignature = await refundSignature(bobBound, bobPackage, bobSecret);
const refund = await hooks.verifyAndAssembleRefund({
  ...aliceBound,
  localSignature: aliceRefundSignature,
  peerSignature: bobRefundSignature,
});
assert.equal(refund.txid, alicePackage.refundTxid);
assert.ok(
  refund.signedTxHex.length / 2 >= 388 && refund.signedTxHex.length / 2 <= 392,
  "strict-DER witness length may vary by one byte per signature",
);

const gameplayRootScriptPubKeyHex = `5120${"77".repeat(32)}`;
const aliceActivation = await hooks.buildActivation({
  ...aliceBound,
  gameplayRootScriptPubKeyHex,
});
const bobActivation = await hooks.buildActivation({
  ...bobBound,
  gameplayRootScriptPubKeyHex,
});
assert.deepEqual(aliceActivation, bobActivation);

async function activationSignature(input, activation, secret) {
  return (await hooks.createActivationSignature({
    ...input,
    gameplayRootScriptPubKeyHex,
    activationFrame: activation.activationFrame,
    sighashHex: activation.activationSighashHex,
    localSecretKeyHex: secret,
  })).signatureFrame;
}
const aliceActivationSignature = await activationSignature(
  aliceBound,
  aliceActivation,
  aliceSecret,
);
const bobActivationSignature = await activationSignature(bobBound, bobActivation, bobSecret);
const activation = await hooks.verifyAndAssembleActivation({
  ...aliceBound,
  gameplayRootScriptPubKeyHex,
  activationFrame: aliceActivation.activationFrame,
  localSignature: aliceActivationSignature,
  peerSignature: bobActivationSignature,
  localRefundSignature: aliceRefundSignature,
  peerRefundSignature: bobRefundSignature,
  signedRefundTxHex: refund.signedTxHex,
});
assert.equal(activation.txid, aliceActivation.activationTxid);

async function fundingSignature(input, built, secret, localRefund, peerRefund) {
  return (await hooks.createFundingSignature({
    ...input,
    sighashHex: built.fundingSighashesHex[built.localInputIndex],
    signedRefundTxHex: refund.signedTxHex,
    localRefundSignature: localRefund,
    peerRefundSignature: peerRefund,
    gameplayRootScriptPubKeyHex,
    activationFrame: aliceActivation.activationFrame,
    localActivationSignature: input.transportRole === "alice"
      ? aliceActivationSignature
      : bobActivationSignature,
    peerActivationSignature: input.transportRole === "alice"
      ? bobActivationSignature
      : aliceActivationSignature,
    signedActivationTxHex: activation.signedTxHex,
    localSecretKeyHex: secret,
  })).signatureFrame;
}
const aliceFundingSignature = await fundingSignature(
  aliceBound,
  alicePackage,
  aliceSecret,
  aliceRefundSignature,
  bobRefundSignature,
);
const bobFundingSignature = await fundingSignature(
  bobBound,
  bobPackage,
  bobSecret,
  bobRefundSignature,
  aliceRefundSignature,
);
const funding = await hooks.verifyAndAssembleFunding({
  ...aliceBound,
  localSignature: aliceFundingSignature,
  peerSignature: bobFundingSignature,
  signedRefundTxHex: refund.signedTxHex,
  localRefundSignature: aliceRefundSignature,
  peerRefundSignature: bobRefundSignature,
  gameplayRootScriptPubKeyHex,
  activationFrame: aliceActivation.activationFrame,
  localActivationSignature: aliceActivationSignature,
  peerActivationSignature: bobActivationSignature,
  signedActivationTxHex: activation.signedTxHex,
});
assert.equal(funding.txid, alicePackage.fundingTxid);

await assert.rejects(
  hooks.verifyAndAssembleRefund({
    ...aliceBound,
    peerPackageFrame: alicePackage.packageFrame,
    localSignature: aliceRefundSignature,
    peerSignature: bobRefundSignature,
  }),
  /packageFrame|origin package/,
);

console.log(`origin browser V2 flow ok: ${funding.txid}`);
