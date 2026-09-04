import { parentPort } from "node:worker_threads";
import { DealWasmParticipant, transferBytes } from "./deal-runtime.js";

let participant;

parentPort.on("message", async (message) => {
  const { id, type } = message;
  try {
    let payload;
    if (type === "init") {
      try {
        participant = await DealWasmParticipant.create(message.wasm);
        const result = participant.initialize(message.request);
        payload = { snapshot: participant.snapshot(), metrics: result.metrics };
      } finally {
        message.request?.localSecretKey?.fill?.(0);
        message.request?.entropy?.fill?.(0);
      }
    } else if (type === "snapshot") {
      payload = { snapshot: participant.snapshot() };
    } else if (type === "generate-envelope") {
      const result = participant.generateNextEnvelope();
      payload = {
        envelope: transferBytes(result.envelope),
        snapshot: participant.snapshot(),
        metrics: result.metrics,
      };
    } else if (type === "prepare-bundle") {
      const metrics = participant.prepareBundle();
      payload = { snapshot: participant.snapshot(), metrics };
    } else if (type === "accept-envelope") {
      const metrics = participant.acceptEnvelope(message.envelope);
      payload = { snapshot: participant.snapshot(), metrics };
    } else if (type === "start-retry") {
      const metrics = participant.startRetry(message.approvedAttempt);
      payload = { snapshot: participant.snapshot(), metrics };
    } else if (type === "make-acceptance-signature") {
      const result = participant.makeAcceptanceSignature(message.body);
      payload = {
        signature: transferBytes(result.signature),
        snapshot: participant.snapshot(),
        metrics: result.metrics,
      };
    } else if (type === "accept-acceptance-signature") {
      const metrics = participant.acceptAcceptanceSignature(message.role, message.signature);
      payload = { snapshot: participant.snapshot(), metrics };
    } else if (type === "export") {
      payload = {
        body: transferBytes(participant.exportAcceptedBody()),
        deal: transferBytes(participant.exportAcceptedDeal()),
        attestation: transferBytes(participant.exportVerificationAttestation()),
        snapshot: participant.snapshot(),
      };
    } else if (type === "export-accepted-body") {
      payload = {
        body: transferBytes(participant.exportAcceptedBody()),
        snapshot: participant.snapshot(),
      };
    } else if (type === "seal-preimages") {
      try {
        const result = participant.sealRetainedPreimages(message.storageKey);
        payload = {
          sealedPreimages: transferBytes(result.value),
          snapshot: participant.snapshot(),
          metrics: result.metrics,
        };
      } finally {
        message.storageKey?.fill?.(0);
      }
    } else if (type === "export-verification-attestation") {
      payload = {
        attestation: transferBytes(participant.exportVerificationAttestation()),
        snapshot: participant.snapshot(),
      };
    } else if (type === "reveal-local-preimage") {
      payload = {
        preimage: transferBytes(participant.revealLocalPreimage(message.slot)),
      };
    } else if (type === "clear") {
      participant.clear();
      payload = {};
    } else {
      throw new Error(`unknown node DEAL Worker request: ${String(type)}`);
    }
    parentPort.postMessage({ id, ok: true, ...payload });
  } catch (error) {
    parentPort.postMessage({
      id,
      ok: false,
      error: error instanceof Error ? error.stack ?? error.message : String(error),
    });
  }
});
