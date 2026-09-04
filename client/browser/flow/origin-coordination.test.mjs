import assert from "node:assert/strict";

import {
  acceptOpaqueRelayArtifact,
  durableRefundArtifacts,
  opaqueRelayArtifact,
  originBoundCommand,
  originCommandContext,
  originPackageCommand,
  originPublicationRequired,
} from "./origin-coordination.js";

const limit = 4_096;
const opaque = (text) => Buffer.from(text).toString("base64");
const runtime = { protocolProfileCode: 1, chain: { profileIdHex: "11".repeat(32) } };
const seat = {
  gameId: "22".repeat(32),
  sessionNonce: "33".repeat(32),
  role: "alice",
};
const common = originCommandContext(runtime, seat);
assert.deepEqual(common, {
  version: 2,
  protocolProfileCode: 1,
  networkId: "11".repeat(32),
  roomId: "22".repeat(32),
  sessionNonce: "33".repeat(32),
  transportRole: "alice",
});
assert.equal("profile" in common, false);

const localStaging = opaque("local staging artifact");
const peerStaging = opaque("peer staging artifact");
const packageCommand = originPackageCommand(common, localStaging, peerStaging, limit);
assert.equal(packageCommand.localStagingFunding, localStaging);
assert.equal(packageCommand.peerStagingFunding, peerStaging);

const localPackage = opaque("local package artifact");
const peerPackage = opaque("peer package artifact");
const bound = originBoundCommand(packageCommand, {
  packageFrame: localPackage,
  peerPackageFrame: peerPackage,
  localInputIndex: 0,
}, peerPackage, limit);
assert.equal(bound.packageFrame, localPackage);
assert.equal(bound.peerPackageFrame, peerPackage);
assert.equal(bound.localInputIndex, 0);
assert.throws(
  () => originBoundCommand(packageCommand, {
    packageFrame: localPackage,
    peerPackageFrame: peerPackage,
    localInputIndex: 0,
  }, opaque("crossed package"), limit),
  /differs/u,
);

assert.equal(acceptOpaqueRelayArtifact(undefined, localPackage, limit), localPackage);
assert.equal(acceptOpaqueRelayArtifact(localPackage, localPackage, limit), localPackage);
assert.throws(
  () => acceptOpaqueRelayArtifact(localPackage, peerPackage, limit),
  /conflicts/u,
);
for (const malformed of ["", "A===", "AA=A", "AB==", "AAB=", "%%%%"] ) {
  assert.throws(() => opaqueRelayArtifact(malformed, limit), /canonical base64/u);
}

assert.throws(() => durableRefundArtifacts({}, limit), /complete durable refund/u);
const refund = durableRefundArtifacts({
  signedRefundTxHex: "00",
  localRefundSignaturePayload: opaque("local refund signature"),
  peerRefundSignaturePayload: opaque("peer refund signature"),
}, limit);
assert.equal(refund.signedRefundTxHex, "00");

assert.equal(
  await originPublicationRequired({ found: true }, async () => {
    throw new Error("must not verify inputs after observing the origin");
  }, async () => ({ found: false })),
  false,
);
assert.equal(
  await originPublicationRequired(
    { found: false },
    async () => true,
    async () => ({ found: false }),
  ),
  true,
);
assert.equal(
  await originPublicationRequired(
    { found: false },
    async () => { throw new Error("staging input was spent"); },
    async () => ({ found: true }),
  ),
  false,
);
await assert.rejects(
  originPublicationRequired(
    { found: false },
    async () => { throw new Error("staging input was spent unexpectedly"); },
    async () => ({ found: false }),
  ),
  /unexpectedly/u,
);

process.stdout.write("origin coordination tests ok\n");
