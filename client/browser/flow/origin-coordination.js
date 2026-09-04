/** Thin browser coordination around the Rust-owned origin protocol artifacts. */

export const ORIGIN_COMMAND_VERSION = 2;

function base64Index(character) {
  const code = character.charCodeAt(0);
  if (code >= 65 && code <= 90) return code - 65;
  if (code >= 97 && code <= 122) return code - 71;
  if (code >= 48 && code <= 57) return code + 4;
  if (character === "+") return 62;
  if (character === "/") return 63;
  return -1;
}

/** Validate only the relay transport encoding. Artifact bytes remain opaque to JavaScript. */
export function opaqueRelayArtifact(payload, maximumBase64Bytes) {
  if (
    typeof payload !== "string" || payload.length === 0 ||
    !Number.isSafeInteger(maximumBase64Bytes) || maximumBase64Bytes <= 0 ||
    payload.length > maximumBase64Bytes || payload.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(payload)
  ) {
    throw new TypeError("Origin relay artifact is not bounded canonical base64.");
  }
  if (payload.endsWith("==") && (base64Index(payload.at(-3)) & 0x0f) !== 0) {
    throw new TypeError("Origin relay artifact is not bounded canonical base64.");
  }
  if (payload.endsWith("=") && !payload.endsWith("==") &&
      (base64Index(payload.at(-2)) & 0x03) !== 0) {
    throw new TypeError("Origin relay artifact is not bounded canonical base64.");
  }
  return payload;
}

/** Accept an idempotent relay artifact and reject equivocation without inspecting its bytes. */
export function acceptOpaqueRelayArtifact(current, candidate, maximumBase64Bytes) {
  const artifact = opaqueRelayArtifact(candidate, maximumBase64Bytes);
  if (current !== undefined && current !== artifact) {
    throw new TypeError("Origin relay artifact conflicts with durable state.");
  }
  return artifact;
}

/** Build the common local-control DTO understood by the V2 origin Wasm boundary. */
export function originCommandContext(runtimeConfig, activeSession) {
  return {
    version: ORIGIN_COMMAND_VERSION,
    protocolProfileCode: runtimeConfig.protocolProfileCode,
    networkId: runtimeConfig.chain.profileIdHex,
    roomId: activeSession.gameId,
    sessionNonce: activeSession.sessionNonce,
    transportRole: activeSession.role,
  };
}

/** Bind two opaque staging announcements into a package-build command. */
export function originPackageCommand(
  common,
  localStagingFunding,
  peerStagingFunding,
  maximumBase64Bytes,
) {
  return {
    ...common,
    localStagingFunding: opaqueRelayArtifact(localStagingFunding, maximumBase64Bytes),
    peerStagingFunding: opaqueRelayArtifact(peerStagingFunding, maximumBase64Bytes),
  };
}

/**
 * Bind the locally rebuilt package to the exact opaque peer announcement.
 * Rust emits the expected peer frame, so JavaScript only performs byte equality.
 */
export function originBoundCommand(packageCommand, built, peerPackageFrame, maximumBase64Bytes) {
  const local = opaqueRelayArtifact(built?.packageFrame, maximumBase64Bytes);
  const expectedPeer = opaqueRelayArtifact(built?.peerPackageFrame, maximumBase64Bytes);
  const peer = opaqueRelayArtifact(peerPackageFrame, maximumBase64Bytes);
  if (peer !== expectedPeer) {
    throw new TypeError("Peer origin package differs from the Rust-rebuilt package.");
  }
  if (built.localInputIndex !== 0 && built.localInputIndex !== 1) {
    throw new TypeError("Rust returned an invalid local origin input index.");
  }
  return {
    ...packageCommand,
    packageFrame: local,
    peerPackageFrame: peer,
    localInputIndex: built.localInputIndex,
  };
}

/** Return the all-or-none durable refund barrier required before funding authorization. */
export function durableRefundArtifacts(state, maximumBase64Bytes) {
  if (
    !state?.signedRefundTxHex ||
    !state.localRefundSignaturePayload ||
    !state.peerRefundSignaturePayload
  ) {
    throw new TypeError("Funding requires the complete durable refund barrier.");
  }
  return {
    signedRefundTxHex: state.signedRefundTxHex,
    localRefundSignature: opaqueRelayArtifact(
      state.localRefundSignaturePayload,
      maximumBase64Bytes,
    ),
    peerRefundSignature: opaqueRelayArtifact(
      state.peerRefundSignaturePayload,
      maximumBase64Bytes,
    ),
  };
}

/**
 * Decide whether this participant still needs to publish the shared origin.
 *
 * Both participants may observe the origin as absent and then check the same
 * staging inputs concurrently. If the peer publishes between those two
 * operations, the fresh-input check sees spent inputs. Re-observe the exact
 * agreed transaction before treating that expected race as a protocol fault.
 */
export async function originPublicationRequired(
  initialObservation,
  verifyInputs,
  observeExpectedOrigin,
) {
  if (initialObservation?.found) return false;
  try {
    if (!await verifyInputs()) return false;
  } catch (error) {
    const racedObservation = await observeExpectedOrigin();
    if (racedObservation?.found) return false;
    throw error;
  }
  return true;
}
