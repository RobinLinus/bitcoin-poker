/** Automatic, idempotent setup commands. The package-bound authorization is
 * persisted only after the refund transaction has been verified and saved;
 * no funding signature may be released before that durable barrier. */
export const AutomaticSetupAction = Object.freeze({
  SEND_READY: "send-ready",
  PROTECT_REFUND: "protect-refund",
  PERSIST_AUTHORIZATION: "persist-authorization",
  RELEASE_FUNDING: "release-funding",
  BROADCAST_ORIGIN: "broadcast-origin",
  AUTHORIZE_ACTIVATION: "authorize-activation",
  BROADCAST_ACTIVATION: "broadcast-activation",
});

/**
 * Return the package id from the canonical frame produced by package
 * agreement. Keeping this shape check in a pure module prevents coordinators
 * from accidentally treating that frame as a wrapped build result.
 */
export function agreedOriginPackageId(agreedPackage) {
  const packageId = agreedPackage?.packageId;
  if (typeof packageId !== "string" || !/^[0-9a-f]{64}$/u.test(packageId)) {
    throw new TypeError("Agreed origin package must be a canonical package frame.");
  }
  return packageId;
}

function setupErrorMessage(value) {
  const message = typeof value === "string"
    ? value
    : value && typeof value.message === "string" ? value.message : "";
  return message.trim().replace(/\s+/gu, " ");
}

/**
 * Select the most relevant setup failure without coupling status rendering to
 * coordinator globals. Callers should supply `primaryError` when rendering a
 * particular setup phase; the remaining fields provide a deterministic
 * whole-flow fallback for the table status.
 */
export function selectSetupFailureCause(state) {
  if (!state) return null;
  for (const candidate of [
    state.primaryError,
    state.chainGameError,
    state.gameFlowError,
    state.originError,
    state.stagingExchangeError,
  ]) {
    const message = setupErrorMessage(candidate);
    if (message) return message;
  }
  return null;
}

/** Build short player-facing copy while retaining diagnostics for the console. */
export function setupFailurePresentation(state) {
  const cause = selectSetupFailureCause(state);
  const halted = Boolean(state?.halted);
  if (!halted && !cause) return null;
  return {
    headline: halted ? "Couldn’t continue" : "Reconnecting…",
    detail: halted
      ? "Reload the page to try again."
      : "We’ll keep trying automatically.",
    diagnostic: cause ?? "The browser could not verify the saved game state.",
  };
}

/**
 * Reduce the many internal setup states to the only information a poker
 * player needs. Protocol names and intermediate artifacts intentionally never
 * appear in this projection.
 */
export function playerSetupStatus(state) {
  if (state?.failure) {
    return {
      headline: state.failure.headline,
      detail: state.failure.detail,
    };
  }
  if (!state?.ownsSeat) {
    return {
      headline: "Open in another tab",
      detail: "Continue from the tab already using this seat.",
    };
  }
  if (!state?.inputsReady) {
    return {
      headline: "Waiting for deposits",
      detail: "The game will continue automatically.",
    };
  }
  if (!state?.engineAvailable) {
    return {
      headline: "Couldn’t prepare the game",
      detail: "Reload the page to try again.",
    };
  }
  if (!state.packageVerified || !state.peerPackage || !state.packagesAgreed ||
      !state.localProtection || !state.protectionVerified) {
    return {
      headline: state.packageVerified && !state.peerPackage
        ? "Waiting for the other player"
        : "Preparing the game",
      detail: "No action is needed.",
    };
  }
  if (!state.setupAuthorized) {
    return {
      headline: "Starting the game",
      detail: "No action is needed.",
    };
  }
  if (!state.localFunding || !state.fundingVerified) {
    return {
      headline: state.localFunding && !state.peerFunding
        ? "Waiting for the other player"
        : "Preparing the game",
      detail: "The game will continue automatically.",
    };
  }
  if (state.confirmed) {
    return {
      headline: "Preparing the cards",
      detail: "No action is needed.",
    };
  }
  if (state.found) {
    return {
      headline: "Waiting for confirmation",
      detail: "The game will start automatically.",
    };
  }
  return {
    headline: "Starting the game",
    detail: "No action is needed.",
  };
}

/**
 * Decide whether the two exact staging inputs are usable without consulting
 * the DOM or timers. A durable package may resume after the inputs have been
 * spent by their expected origin, while a fresh package requires both current
 * chain observations.
 */
export function originInputsAreReady(state) {
  if (!state) return false;
  if (state.expectedOriginSeen) return true;
  const fresh = Boolean(
    state.depositObservationVerified && state.localDepositConfirmed &&
    state.framesBoundToSession && state.localFramePresent && state.localFrameSent &&
    state.peerFramePresent && state.peerObservationVerified && state.peerStatus === "verified"
  );
  const durable = Boolean(
    state.durablePackagePresent && state.localFramePresent && state.peerFramePresent
  );
  return fresh || durable;
}

/** Gate private-game replay on the exact confirmed, refund-protected origin. */
export function originGameFlowReady(state) {
  return Boolean(
    state?.confirmed && !state.refunded && state.packagePresent &&
    state.refundVerified && state.signedRefundPresent && state.walletPresent &&
    typeof state.observedTxid === "string" &&
    state.observedTxid === state.fundingTxid
  );
}

/**
 * Project the staging-funding coordinator's timer work from explicit facts.
 * A relayed payload is not enough to inspect the peer deposit: the origin
 * worker must first validate it and produce `peerFramePresent`. Treating the
 * opaque payload as an inspectable frame creates an immediate retry loop while
 * that validation is still in flight.
 */
export function stagingFundingExchangePlan(state) {
  const needsStoredValidation = Boolean(
    !state?.storedFramesValidated &&
    (state?.localPayloadPresent || state?.peerPayloadPresent)
  );
  const needsPublish = Boolean(
    state?.localDepositConfirmed && !state?.localFrameSent
  );
  const needsPeerCheck = Boolean(
    state?.peerFramePresent && !state?.peerObservationVerified &&
    state?.now >= state?.peerCheckAt
  );
  return {
    needsStoredValidation,
    needsPublish,
    needsPeerCheck,
    shouldSchedule: needsStoredValidation || needsPublish || needsPeerCheck,
  };
}

/** Derive all automatic-transition guards from durable/public facts. */
export function deriveAutomaticSetupReadiness(state) {
  const inputsReady = Boolean(state?.inputsReady);
  const packageReady = inputsReady && state?.packageVerified && state?.packagesAgreed;
  return {
    canProtectRefund: Boolean(
      packageReady && !state?.refundVerified && !state?.localRefundPresent &&
      state?.refundHooksAvailable
    ),
    canPersistAuthorization: Boolean(
      packageReady && state?.refundVerified && state?.localRefundPresent &&
      !state?.setupAuthorized
    ),
    canReleaseFunding: Boolean(
      packageReady && state?.refundVerified && state?.localRefundPresent &&
      state?.setupAuthorized &&
      !state?.localFundingPresent &&
      state?.fundingHooksAvailable
    ),
    canBroadcastOrigin: Boolean(state?.fundingVerified && !state?.originFound),
    canAuthorizeActivation: Boolean(
      state?.chainFlowPresent && state?.activationReady && !state?.activationAuthorized &&
      !state?.originRefunded
    ),
    canBroadcastActivation: Boolean(
      state?.pendingPurpose === 0 && state?.pendingTransactionPresent &&
      state?.pendingTxidPresent && !state?.originRefunded
    ),
  };
}

/**
 * Select at most one setup command from a projection of the current state.
 * The executor serializes commands and calls this function again after every
 * durable transition. This keeps retries deterministic and unit-testable.
 */
export function nextAutomaticSetupAction(state) {
  if (!state || !state.ownsSeat || state.halted || state.busy) return null;
  const readiness = deriveAutomaticSetupReadiness(state);
  if (state.seatClaimed && !state.localReady) {
    return AutomaticSetupAction.SEND_READY;
  }
  if (readiness.canProtectRefund) {
    return AutomaticSetupAction.PROTECT_REFUND;
  }
  if (readiness.canPersistAuthorization) {
    return AutomaticSetupAction.PERSIST_AUTHORIZATION;
  }
  if (!state.setupAuthorized) return null;
  if (readiness.canReleaseFunding) {
    return AutomaticSetupAction.RELEASE_FUNDING;
  }
  if (readiness.canBroadcastOrigin) {
    return AutomaticSetupAction.BROADCAST_ORIGIN;
  }
  if (readiness.canAuthorizeActivation) {
    return AutomaticSetupAction.AUTHORIZE_ACTIVATION;
  }
  if (readiness.canBroadcastActivation && !state.activationSubmitted) {
    return AutomaticSetupAction.BROADCAST_ACTIVATION;
  }
  return null;
}
