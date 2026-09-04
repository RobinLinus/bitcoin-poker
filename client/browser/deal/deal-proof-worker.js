import { DealWasmParticipant, transferBytes } from "./deal-runtime.js";

self.addEventListener("message", async (event) => {
  let participant;
  try {
    participant = await DealWasmParticipant.create(event.data.wasm);
    participant.initialize(event.data.init);
    for (const action of event.data.actions) {
      if (action.type === "envelope") {
        participant.replayEnvelope(action.envelope);
      } else if (action.type === "retry") {
        participant.startRetry(action.approvedAttempt);
      } else {
        throw new Error("parallel DEAL proof replay contains an unknown action");
      }
    }
    const result = participant.prepareBundleSlots(event.data.slots);
    const slotProofSize = result.proofs.byteLength / event.data.slots.length;
    if (!Number.isSafeInteger(slotProofSize) || slotProofSize <= 0) {
      throw new Error("parallel DEAL proof batch has an invalid length");
    }
    const proofs = event.data.slots.map((_, index) => transferBytes(
      result.proofs.slice(index * slotProofSize, (index + 1) * slotProofSize),
    ));
    self.postMessage({ ok: true, proofs }, proofs);
  } catch (error) {
    self.postMessage({
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
  } finally {
    participant?.clear();
  }
});
