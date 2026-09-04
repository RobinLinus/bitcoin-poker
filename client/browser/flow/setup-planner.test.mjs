import assert from "node:assert/strict";

import {
  AutomaticSetupAction,
  agreedOriginPackageId,
  originGameFlowReady,
  originInputsAreReady,
  nextAutomaticSetupAction,
  playerSetupStatus,
  selectSetupFailureCause,
  setupFailurePresentation,
  stagingFundingExchangePlan,
} from "./setup-planner.js";

const agreedPackageId = "ab".repeat(32);
assert.equal(
  agreedOriginPackageId({ packageId: agreedPackageId }),
  agreedPackageId,
);
// Package agreement returns the canonical frame directly. A build-result
// wrapper is deliberately rejected so the Start handler cannot regress to
// reading `agreed.frame.packageId`.
assert.throws(
  () => agreedOriginPackageId({ frame: { packageId: agreedPackageId } }),
  /canonical package frame/u,
);
assert.throws(() => agreedOriginPackageId(null), /canonical package frame/u);

const ready = {
  ownsSeat: true,
  halted: false,
  busy: false,
  seatClaimed: true,
  localReady: true,
  inputsReady: false,
  packageVerified: false,
  packagesAgreed: false,
  localRefundPresent: false,
  refundHooksAvailable: true,
  setupAuthorized: false,
  refundVerified: false,
  localFundingPresent: false,
  fundingHooksAvailable: true,
  fundingVerified: false,
  originFound: false,
  chainFlowPresent: false,
  activationReady: false,
  activationAuthorized: false,
  originRefunded: false,
  pendingPurpose: undefined,
  pendingTransactionPresent: false,
  pendingTxidPresent: false,
  activationSubmitted: false,
};

assert.equal(
  nextAutomaticSetupAction({ ...ready, localReady: false }),
  AutomaticSetupAction.SEND_READY,
);
assert.equal(
  nextAutomaticSetupAction({
    ...ready,
    inputsReady: true,
    packageVerified: true,
    packagesAgreed: true,
  }),
  AutomaticSetupAction.PROTECT_REFUND,
);

// No authorization is persisted before the inputs, package agreement, and
// fully verified refund are all present.
assert.equal(
  nextAutomaticSetupAction({ ...ready, refundVerified: true }),
  null,
);
assert.equal(
  nextAutomaticSetupAction({
    ...ready,
    inputsReady: true,
    packageVerified: true,
    packagesAgreed: true,
    refundVerified: true,
    localRefundPresent: true,
  }),
  AutomaticSetupAction.PERSIST_AUTHORIZATION,
);
// Funding cannot be released until the durable package-bound authorization
// has been written and read back by the coordinator.
assert.equal(
  nextAutomaticSetupAction({
    ...ready,
    inputsReady: true,
    packageVerified: true,
    packagesAgreed: true,
    refundVerified: true,
    localRefundPresent: true,
    setupAuthorized: true,
  }),
  AutomaticSetupAction.RELEASE_FUNDING,
);
assert.equal(
  nextAutomaticSetupAction({
    ...ready,
    setupAuthorized: true,
    fundingVerified: true,
  }),
  AutomaticSetupAction.BROADCAST_ORIGIN,
);
assert.equal(
  nextAutomaticSetupAction({
    ...ready,
    setupAuthorized: true,
    originFound: true,
    chainFlowPresent: true,
    activationReady: true,
  }),
  AutomaticSetupAction.AUTHORIZE_ACTIVATION,
);
assert.equal(
  nextAutomaticSetupAction({
    ...ready,
    setupAuthorized: true,
    originFound: true,
    activationAuthorized: true,
    pendingPurpose: 0,
    pendingTransactionPresent: true,
    pendingTxidPresent: true,
  }),
  AutomaticSetupAction.BROADCAST_ACTIVATION,
);
assert.equal(
  nextAutomaticSetupAction({
    ...ready,
    setupAuthorized: true,
    originFound: true,
    activationAuthorized: true,
    pendingPurpose: 0,
    pendingTransactionPresent: true,
    pendingTxidPresent: true,
    activationSubmitted: true,
  }),
  null,
);

for (const state of [
  { ...ready, ownsSeat: false, seatClaimed: true, localReady: false },
  { ...ready, halted: true, seatClaimed: true, localReady: false },
  { ...ready, busy: true, seatClaimed: true, localReady: false },
]) {
  assert.equal(nextAutomaticSetupAction(state), null);
}

const freshInputs = {
  expectedOriginSeen: false,
  depositObservationVerified: true,
  localDepositConfirmed: true,
  framesBoundToSession: true,
  localFramePresent: true,
  localFrameSent: true,
  peerFramePresent: true,
  peerObservationVerified: true,
  peerStatus: "verified",
  durablePackagePresent: false,
};
assert.equal(originInputsAreReady(freshInputs), true);
assert.equal(originInputsAreReady({ ...freshInputs, peerObservationVerified: false }), false);
assert.equal(originInputsAreReady({
  ...freshInputs,
  depositObservationVerified: false,
  localDepositConfirmed: false,
  framesBoundToSession: false,
  localFrameSent: false,
  peerObservationVerified: false,
  peerStatus: "spent",
  durablePackagePresent: true,
}), true);
assert.equal(originInputsAreReady({
  ...freshInputs,
  localFramePresent: false,
  durablePackagePresent: true,
}), false);
assert.equal(originInputsAreReady({ expectedOriginSeen: true }), true);

const gameFlowOrigin = {
  confirmed: true,
  refunded: false,
  packagePresent: true,
  refundVerified: true,
  signedRefundPresent: true,
  walletPresent: true,
  observedTxid: "11".repeat(32),
  fundingTxid: "11".repeat(32),
};
assert.equal(originGameFlowReady(gameFlowOrigin), true);
assert.equal(originGameFlowReady({ ...gameFlowOrigin, confirmed: false }), false);
assert.equal(originGameFlowReady({ ...gameFlowOrigin, refunded: true }), false);
assert.equal(originGameFlowReady({ ...gameFlowOrigin, fundingTxid: "22".repeat(32) }), false);

// A peer payload can arrive before the worker has validated and projected it.
// That intermediate state must not continuously reschedule chain inspection.
assert.deepEqual(stagingFundingExchangePlan({
  storedFramesValidated: true,
  peerPayloadPresent: true,
  peerFramePresent: false,
  peerObservationVerified: false,
  peerCheckAt: 0,
  now: 1,
}), {
  needsStoredValidation: false,
  needsPublish: false,
  needsPeerCheck: false,
  shouldSchedule: false,
});
assert.deepEqual(stagingFundingExchangePlan({
  storedFramesValidated: true,
  peerPayloadPresent: true,
  peerFramePresent: true,
  peerObservationVerified: false,
  peerCheckAt: 10,
  now: 10,
}), {
  needsStoredValidation: false,
  needsPublish: false,
  needsPeerCheck: true,
  shouldSchedule: true,
});
assert.equal(stagingFundingExchangePlan({
  storedFramesValidated: false,
  peerPayloadPresent: true,
}).needsStoredValidation, true);
assert.equal(stagingFundingExchangePlan({
  storedFramesValidated: true,
  localDepositConfirmed: true,
  localFrameSent: false,
}).needsPublish, true);

// Diagnostics remain deterministic, but player-facing copy never includes
// protocol or JavaScript exception details.
assert.equal(selectSetupFailureCause({
  primaryError: "  The saved recovery signature belongs to another game.  ",
  chainGameError: "stale chain error",
}), "The saved recovery signature belongs to another game.");
assert.equal(selectSetupFailureCause({
  chainGameError: new Error("Activation confirmation no longer matches."),
  gameFlowError: "deal failed",
  originError: "origin failed",
  stagingExchangeError: "deposit failed",
}), "Activation confirmation no longer matches.");
assert.equal(selectSetupFailureCause({
  gameFlowError: "deal failed",
  originError: "origin failed",
}), "deal failed");
assert.equal(selectSetupFailureCause({ originError: "\n relay   request timed out \n" }),
  "relay request timed out");
assert.equal(selectSetupFailureCause({}), null);

assert.deepEqual(setupFailurePresentation({
  halted: true,
  originError: "The two seats received different game terms.",
}), {
  headline: "Couldn’t continue",
  detail: "Reload the page to try again.",
  diagnostic: "The two seats received different game terms.",
});
assert.deepEqual(setupFailurePresentation({
  halted: false,
  stagingExchangeError: "The deposit check timed out.",
}), {
  headline: "Reconnecting…",
  detail: "We’ll keep trying automatically.",
  diagnostic: "The deposit check timed out.",
});
assert.deepEqual(setupFailurePresentation({ halted: true }), {
  headline: "Couldn’t continue",
  detail: "Reload the page to try again.",
  diagnostic: "The browser could not verify the saved game state.",
});
assert.equal(setupFailurePresentation({ halted: false }), null);

const technicalFailure = setupFailurePresentation({
  originError: "Cannot read properties of undefined (reading 'packageId')",
});
assert.equal(technicalFailure.headline, "Reconnecting…");
assert.equal(technicalFailure.detail, "We’ll keep trying automatically.");
assert.doesNotMatch(`${technicalFailure.headline} ${technicalFailure.detail}`, /packageId|undefined/u);

const protectedReady = {
  ownsSeat: true,
  inputsReady: true,
  engineAvailable: true,
  packageVerified: true,
  peerPackage: true,
  packagesAgreed: true,
  localProtection: true,
  protectionVerified: true,
  setupAuthorized: false,
};
assert.deepEqual(playerSetupStatus(protectedReady), {
  headline: "Starting the game",
  detail: "No action is needed.",
});
assert.deepEqual(playerSetupStatus({ ...protectedReady, setupAuthorized: true }), {
  headline: "Preparing the game",
  detail: "The game will continue automatically.",
});
assert.deepEqual(playerSetupStatus({
  ...protectedReady,
  setupAuthorized: true,
  localFunding: true,
  peerFunding: true,
  fundingVerified: true,
  found: true,
}), {
  headline: "Waiting for confirmation",
  detail: "The game will start automatically.",
});
assert.deepEqual(playerSetupStatus({ failure: technicalFailure }), {
  headline: "Reconnecting…",
  detail: "We’ll keep trying automatically.",
});

// Model reload after every durable transition. The planner must always select
// the same next command from serialized facts and never repeat a completed one.
const reload = (value) => JSON.parse(JSON.stringify(value));
let sequence = reload({ ...ready, localReady: false });
assert.equal(nextAutomaticSetupAction(sequence), AutomaticSetupAction.SEND_READY);
sequence = reload({ ...sequence, localReady: true });
assert.equal(nextAutomaticSetupAction(sequence), null);
sequence = reload({
  ...sequence,
  inputsReady: true,
  packageVerified: true,
  packagesAgreed: true,
});
assert.equal(nextAutomaticSetupAction(sequence), AutomaticSetupAction.PROTECT_REFUND);
sequence = reload({ ...sequence, localRefundPresent: true });
assert.equal(nextAutomaticSetupAction(sequence), null);
sequence = reload({ ...sequence, refundVerified: true });
assert.equal(
  nextAutomaticSetupAction(sequence),
  AutomaticSetupAction.PERSIST_AUTHORIZATION,
);
sequence = reload({ ...sequence, setupAuthorized: true });
assert.equal(nextAutomaticSetupAction(sequence), AutomaticSetupAction.RELEASE_FUNDING);
sequence = reload({ ...sequence, localFundingPresent: true });
assert.equal(nextAutomaticSetupAction(sequence), null);
sequence = reload({ ...sequence, fundingVerified: true });
assert.equal(nextAutomaticSetupAction(sequence), AutomaticSetupAction.BROADCAST_ORIGIN);
sequence = reload({ ...sequence, originFound: true, chainFlowPresent: true, activationReady: true });
assert.equal(nextAutomaticSetupAction(sequence), AutomaticSetupAction.AUTHORIZE_ACTIVATION);
sequence = reload({
  ...sequence,
  activationAuthorized: true,
  pendingPurpose: 0,
  pendingTransactionPresent: true,
  pendingTxidPresent: true,
});
assert.equal(nextAutomaticSetupAction(sequence), AutomaticSetupAction.BROADCAST_ACTIVATION);

process.stdout.write("automatic setup planner tests ok\n");
