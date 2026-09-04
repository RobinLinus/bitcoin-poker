import { DealWasmParticipant, transferBytes } from "./deal-runtime.js";
import { proofExecutionMode, scheduleProofSlots } from "./proof-schedule.js";
import { serializeAsync } from "../worker/serial-dispatch.js";

let participant;
let wasmModule;
let replayInit;
let replayActions = [];

function ownedBytes(value) {
  return Uint8Array.from(value instanceof Uint8Array ? value : new Uint8Array(value));
}

function retainedInit(request) {
  return {
    sharedConfigHash: ownedBytes(request.sharedConfigHash),
    sessionNonce: ownedBytes(request.sessionNonce),
    gameId: ownedBytes(request.gameId),
    localSecretKey: ownedBytes(request.localSecretKey),
    identityKeys: request.identityKeys.map(ownedBytes),
    entropy: ownedBytes(request.entropy),
  };
}

function clearReplaySecrets() {
  replayInit?.localSecretKey.fill(0);
  replayInit?.entropy.fill(0);
  replayInit = undefined;
  replayActions = [];
}

async function prepareBundleWithAssignments(assignments) {
  if (!replayInit || !wasmModule) {
    throw new Error("parallel DEAL preparation state is unavailable");
  }
  const proofWorkerUrl = new URL("./deal-proof-worker.js", import.meta.url);
  const workers = assignments.map(() => new Worker(proofWorkerUrl, { type: "module" }));
  try {
    const proofs = new Array(9);
    const batches = await Promise.all(workers.map((worker, index) =>
      new Promise((resolve, reject) => {
          worker.addEventListener("message", (message) => {
            if (message.data?.ok) resolve(message.data.proofs.map(ownedBytes));
            else reject(new Error(message.data?.error || "parallel DEAL proof worker failed"));
          }, { once: true });
          worker.addEventListener("error", (event) => {
            reject(event.error instanceof Error ? event.error : new Error(event.message));
          }, { once: true });
          worker.postMessage({
            wasm: wasmModule,
            init: structuredClone(replayInit),
            actions: structuredClone(replayActions),
            slots: assignments[index],
          });
      }),
    ));
    for (let batch = 0; batch < batches.length; batch += 1) {
      for (let index = 0; index < assignments[batch].length; index += 1) {
        proofs[assignments[batch][index]] = batches[batch][index];
      }
    }
    const joined = new Uint8Array(proofs.reduce((sum, proof) => sum + proof.byteLength, 0));
    let offset = 0;
    for (const proof of proofs) {
      joined.set(proof, offset);
      offset += proof.byteLength;
    }
    return participant.installParallelBundle(joined);
  } finally {
    for (const worker of workers) worker.terminate();
  }
}

async function prepareBundleInParallel() {
  return prepareBundleWithAssignments(
    scheduleProofSlots(self.navigator?.hardwareConcurrency),
  );
}

function respond(id, payload, transfer = []) {
  self.postMessage({ id, ok: true, ...payload }, transfer);
}

function fail(id, error) {
  self.postMessage({
    id,
    ok: false,
    error: error instanceof Error ? error.message : String(error),
  });
}

async function handleMessage(event) {
  const { id, type } = event.data ?? {};
  const startedAt = performance.now();
  try {
    if (type === "init") {
      if (participant) {
        throw new Error("DEAL Worker is already initialized");
      }
      const request = event.data.request;
      try {
        wasmModule = event.data.wasm instanceof WebAssembly.Module
          ? event.data.wasm
          : await WebAssembly.compile(event.data.wasm);
        replayInit = retainedInit(request);
        participant = await DealWasmParticipant.create(wasmModule);
        const result = participant.initialize(request);
        respond(id, { snapshot: participant.snapshot(), metrics: result.metrics });
      } finally {
        request?.localSecretKey?.fill?.(0);
        request?.entropy?.fill?.(0);
      }
      return;
    }
    if (!participant) {
      throw new Error("DEAL Worker is not initialized");
    }
    switch (type) {
      case "snapshot":
        respond(id, { snapshot: participant.snapshot() });
        break;
      case "generate-envelope": {
        const result = participant.generateNextEnvelope();
        replayActions.push({ type: "envelope", envelope: ownedBytes(result.envelope) });
        const envelope = transferBytes(result.envelope);
        respond(
          id,
          { envelope, snapshot: participant.snapshot(), metrics: result.metrics },
          [envelope],
        );
        break;
      }
      case "prepare-bundle": {
        const startedAt = performance.now();
        const attempt = participant.snapshot().attempt;
        const installed = proofExecutionMode(attempt) === "parallel"
          ? await prepareBundleInParallel()
          : participant.prepareBundle();
        const metrics = {
          ...installed,
          elapsedMs: performance.now() - startedAt,
        };
        respond(id, { snapshot: participant.snapshot(), metrics });
        break;
      }
      case "accept-envelope": {
        const metrics = participant.acceptEnvelope(event.data.envelope);
        replayActions.push({ type: "envelope", envelope: ownedBytes(event.data.envelope) });
        respond(id, { snapshot: participant.snapshot(), metrics });
        break;
      }
      case "start-retry": {
        const metrics = participant.startRetry(event.data.approvedAttempt);
        replayActions.push({ type: "retry", approvedAttempt: event.data.approvedAttempt });
        respond(id, { snapshot: participant.snapshot(), metrics });
        break;
      }
      case "make-acceptance-signature": {
        const result = participant.makeAcceptanceSignature(event.data.body);
        const signature = transferBytes(result.signature);
        respond(
          id,
          { signature, snapshot: participant.snapshot(), metrics: result.metrics },
          [signature],
        );
        break;
      }
      case "make-retry-signature": {
        const result = participant.makeRetrySignature(
          event.data.nextAttempt,
          event.data.digest,
        );
        const signature = transferBytes(result.signature);
        respond(
          id,
          { signature, snapshot: participant.snapshot(), metrics: result.metrics },
          [signature],
        );
        break;
      }
      case "accept-acceptance-signature": {
        const metrics = participant.acceptAcceptanceSignature(
          event.data.role,
          event.data.signature,
        );
        respond(id, { snapshot: participant.snapshot(), metrics });
        break;
      }
      case "export": {
        const body = transferBytes(participant.exportAcceptedBody());
        const deal = transferBytes(participant.exportAcceptedDeal());
        const attestation = transferBytes(participant.exportVerificationAttestation());
        respond(
          id,
          { body, deal, attestation, snapshot: participant.snapshot() },
          [body, deal, attestation],
        );
        break;
      }
      case "export-accepted-body": {
        const body = transferBytes(participant.exportAcceptedBody());
        respond(id, { body, snapshot: participant.snapshot() }, [body]);
        break;
      }
      case "export-verification-attestation": {
        const attestation = transferBytes(participant.exportVerificationAttestation());
        respond(id, { attestation, snapshot: participant.snapshot() }, [attestation]);
        break;
      }
      case "seal-preimages": {
        try {
          const result = participant.sealRetainedPreimages(event.data.storageKey);
          const sealedPreimages = transferBytes(result.value);
          respond(
            id,
            { sealedPreimages, snapshot: participant.snapshot(), metrics: result.metrics },
            [sealedPreimages],
          );
        } finally {
          event.data.storageKey?.fill?.(0);
        }
        break;
      }
      case "reveal-local-preimage": {
        const preimage = transferBytes(participant.revealLocalPreimage(event.data.slot));
        respond(id, { preimage }, [preimage]);
        break;
      }
      case "clear":
        participant.clear();
        participant = undefined;
        wasmModule = undefined;
        clearReplaySecrets();
        respond(id, {});
        self.close();
        break;
      default:
        throw new Error(`unknown DEAL Worker request: ${String(type)}`);
    }
  } catch (error) {
    fail(id, error);
  } finally {
    const elapsedMs = Math.round(performance.now() - startedAt);
    if (elapsedMs >= 1_000) {
      console.debug("[BP52 DEAL Worker]", { operation: type, elapsedMs });
    }
  }
}

self.addEventListener("message", serializeAsync(handleMessage));
