import assert from "node:assert/strict";

import {
  loadRuntimeConfig,
  validateRuntimeConfig,
} from "./deployment.js";

const fixture = {
  schemaVersion: 2,
  deploymentId: "mutinynet",
  protocolProfile: "headsUpFixedLimitV1",
  protocolProfileCode: 1,
  deploymentDigestHex: "99".repeat(32),
  relay: {
    apiBasePath: "/api/v1",
    pollIntervalMs: 1_400,
    requestTimeoutMs: 10_000,
    maxPayloadBase64Bytes: 22_369_624,
    kinds: {
      ready: "session.ready.v1",
      nonceCommit: "client.nonce-commit.v1",
      nonceReveal: "client.nonce-reveal.v1",
      nonceReady: "client.nonce-ready.v1",
      stagingFunding: "client.staging-funding.v2",
      originPackage: "client.origin-package.v2",
      originRefundSignature: "client.origin-refund-sig.v2",
      originFundingSignature: "client.origin-funding-sig.v2",
      gameExchange: "game.exchange.v1",
      chainExchange: "chain.exchange.v1",
    },
  },
  chain: {
    backend: "esplora",
    esploraUrl: "https://mutinynet.com/api/",
    explorerUrl: "https://mutinynet.com/",
    network: "signet",
    bitcoinNetworkCode: 2,
    walletNetworkCode: 1,
    profileIdHex: "e3bc9730af93197380e11b43ca00d6b516d83321f46b8b9f53a22a4fae89e680",
    genesisDisplayHashHex: "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
    signetChallengeHex: "51",
    checkpoint: {
      height: 339_000,
      displayHashHex: "000001ce7d14b7c4eb8f989d3825b4212ea6a6a30f62df8bf6486b69a247242b",
    },
    allowBroadcast: true,
    addressHrp: "tb",
    confirmations: { origin: 1, gameplay: 1 },
    feeFloorSatPerVbyte: 1,
  },
  game: {
    stagingContributionSat: 27_000,
    originFundingFeeSat: 500,
    originValueSat: 53_500,
    activationFeeSat: 500,
    gameplayRootValueSat: 53_000,
    originRefundFeeSat: 500,
    refundOutputSat: 26_500,
    refundCsvBlocks: 144,
    unitSat: 100,
    maxBetsPerStreet: 4,
    startingStackSat: 20_000,
    feeReserveSat: 13_000,
    dustThresholdSat: 330,
    fees: {
      bettingSat: 224,
      revealSat: 264,
      aliceShowdownSat: 2_203,
      bobPayoutSat: 3_089,
      timeoutSat: 232,
    },
    button: "alice",
    revealOrder: { flopFirst: "alice", turnFirst: "bob", riverFirst: "alice" },
    splitRemainderRecipient: "bob",
    timeoutPolicy: "potOnly",
  },
};

const validated = validateRuntimeConfig(fixture);
assert.ok(Object.isFrozen(validated));
assert.ok(Object.isFrozen(validated.relay.kinds));
assert.equal(validated.protocolProfileCode, 1);
assert.equal(validated.chain.bitcoinNetworkCode, 2);
assert.equal(validated.chain.walletNetworkCode, 1);
assert.equal(validated.chain.esploraUrl, "https://mutinynet.com/api/");
assert.throws(() => { validated.deploymentId = "changed"; }, TypeError);

// This boundary intentionally does not duplicate Rust's deployment schema or
// protocol enum validation. It accepts Rust-resolved fields it does not know.
const extended = validateRuntimeConfig({ ...fixture, futureRustField: { enabled: true } });
assert.deepEqual(extended.futureRustField, { enabled: true });
assert.ok(Object.isFrozen(extended.futureRustField));

const unsafeInteger = structuredClone(fixture);
unsafeInteger.game.startingStackSat = Number.MAX_SAFE_INTEGER + 1;
assert.throws(() => validateRuntimeConfig(unsafeInteger), /JavaScript-safe integer/);
assert.throws(() => validateRuntimeConfig({ value: -1 }), /JavaScript-safe integer/);
assert.throws(() => validateRuntimeConfig({ value: () => {} }), /cloneable JSON/);
const cyclic = {};
cyclic.self = cyclic;
assert.throws(() => validateRuntimeConfig(cyclic), /cycle/);

let requests = 0;
let requestedUrl;
const loaded = await loadRuntimeConfig({
  url: "/test-config",
  fetchImplementation: async (url, options) => {
    requests += 1;
    requestedUrl = url;
    assert.equal(options.credentials, "omit");
    assert.equal(options.redirect, "error");
    return new Response(JSON.stringify(fixture), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  },
});
assert.equal(requests, 1);
assert.equal(requestedUrl, "/test-config");
assert.equal(loaded.deploymentId, "mutinynet");
assert.ok(Object.isFrozen(loaded.chain));

await assert.rejects(
  loadRuntimeConfig({
    url: "https://attacker.example/config",
    fetchImplementation: async () => { throw new Error("must not fetch"); },
  }),
  /same-origin/,
);

await assert.rejects(
  loadRuntimeConfig({
    url: "/wrong-content-type",
    fetchImplementation: async () => new Response("{}", {
      status: 200,
      headers: { "content-type": "text/plain" },
    }),
  }),
  /not JSON/,
);

await assert.rejects(
  loadRuntimeConfig({
    url: "/too-large",
    fetchImplementation: async () => new Response("x", {
      status: 200,
      headers: {
        "content-type": "application/json",
        "content-length": String(64 * 1024 + 1),
      },
    }),
  }),
  /invalid size/,
);

await assert.rejects(
  loadRuntimeConfig({
    url: "/too-large-without-length",
    fetchImplementation: async () => new Response(`"${"x".repeat(64 * 1024)}"`, {
      status: 200,
      headers: { "content-type": "application/json" },
    }),
  }),
  /invalid size/,
);

console.log("runtime config loader tests ok");
