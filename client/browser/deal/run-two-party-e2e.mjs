import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { Worker } from "node:worker_threads";


const wasmUrl = new URL(
  "../../crates/bp52-relay-server/web/wasm/deal.wasm",
  import.meta.url,
);
const workerUrl = new URL("./node-participant-worker.mjs", import.meta.url);
const wasm = await readFile(wasmUrl);

const hex = (value) => Uint8Array.from(Buffer.from(value, "hex"));
const secret = (marker) => {
  const bytes = new Uint8Array(32);
  bytes[31] = marker;
  return bytes;
};

const identityAlice = hex(
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
);
const identityBob = hex(
  "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
);

class ParticipantWorker {
  constructor(label) {
    this.label = label;
    this.worker = new Worker(workerUrl, { type: "module" });
    this.nextId = 1;
    this.pending = new Map();
    this.worker.on("message", (message) => {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.ok) pending.resolve(message);
      else pending.reject(new Error(`${this.label}: ${message.error}`));
    });
    this.worker.on("error", (error) => {
      for (const pending of this.pending.values()) pending.reject(error);
      this.pending.clear();
    });
  }

  call(type, fields = {}) {
    const id = this.nextId;
    this.nextId += 1;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, type, ...fields });
    });
  }

  terminate() {
    return this.worker.terminate();
  }
}

const alice = new ParticipantWorker("Alice worker");
const bob = new ParticipantWorker("Bob worker");
let initialWorkersClosed = false;
const sharedConfigHash = new Uint8Array(32).fill(0x31);
const sessionNonce = new Uint8Array(32).fill(0x42);
const gameId = new Uint8Array(32).fill(0x53);
const identityKeys = [identityBob, identityAlice]; // exercise canonical sorting

function report(phase, result, extra = {}) {
  console.log(
    JSON.stringify({
      phase,
      elapsedSeconds: Number((result.metrics.elapsedMs / 1_000).toFixed(6)),
      wasmMiB: result.metrics.wasmMiB,
      rssMiB: Number((process.memoryUsage().rss / 1_048_576).toFixed(2)),
      ...extra,
    }),
  );
}

try {
  const [aliceInit, bobInit] = await Promise.all([
    alice.call("init", {
      wasm,
      request: {
        sharedConfigHash,
        sessionNonce,
        gameId,
        localSecretKey: secret(1),
        identityKeys,
        entropy: new Uint8Array(32).fill(0xa1),
      },
    }),
    bob.call("init", {
      wasm,
      request: {
        sharedConfigHash,
        sessionNonce,
        gameId,
        localSecretKey: secret(2),
        identityKeys,
        entropy: new Uint8Array(32).fill(0xb2),
      },
    }),
  ]);
  report("Alice parameter setup", aliceInit);
  report("Bob parameter setup", bobInit);
  if (aliceInit.snapshot.localRole !== 0 || bobInit.snapshot.localRole !== 1) {
    throw new Error("identity roles did not canonicalize as expected");
  }

  let attempt = 0;
  let preparedAttempt = -1;
  let envelopes = 0;
  while (true) {
    const [aliceState, bobState] = await Promise.all([
      alice.call("snapshot"),
      bob.call("snapshot"),
    ]);
    if (
      aliceState.snapshot.status === "retry-approval" ||
      bobState.snapshot.status === "retry-approval"
    ) {
      if (
        aliceState.snapshot.status !== "retry-approval" ||
        bobState.snapshot.status !== "retry-approval"
      ) {
        throw new Error("workers disagreed on the neutral retry boundary");
      }
      const [aliceAttestation, bobAttestation] = await Promise.all([
        alice.call("export-verification-attestation"),
        bob.call("export-verification-attestation"),
      ]);
      if (
        aliceAttestation.attestation.byteLength === 0 ||
        bobAttestation.attestation.byteLength === 0
      ) {
        throw new Error("retry boundary did not produce verifier attestations");
      }
      attempt += 1;
      if (attempt > 16) throw new Error("too many honest collision retries");
      const [aliceRetry, bobRetry] = await Promise.all([
        alice.call("start-retry", { approvedAttempt: attempt }),
        bob.call("start-retry", { approvedAttempt: attempt }),
      ]);
      report("Alice verifier-authorized retry", aliceRetry, { attempt });
      report("Bob verifier-authorized retry", bobRetry, { attempt });
      continue;
    }
    if (
      aliceState.snapshot.status === "local-acceptance-signature" &&
      bobState.snapshot.status === "local-acceptance-signature"
    ) {
      break;
    }

    const aliceTurn = aliceState.snapshot.status === "local-envelope";
    const bobTurn = bobState.snapshot.status === "local-envelope";
    if (aliceTurn === bobTurn) {
      throw new Error("workers disagreed on the unique scheduled sender");
    }
    const sender = aliceTurn ? alice : bob;
    const receiver = aliceTurn ? bob : alice;
    const senderLabel = aliceTurn ? "Alice" : "Bob";
    const sequence = aliceTurn
      ? aliceState.snapshot.nextSequence
      : bobState.snapshot.nextSequence;
    if (sequence === 6 && preparedAttempt !== attempt) {
      const [alicePrepared, bobPrepared] = await Promise.all([
        alice.call("prepare-bundle"),
        bob.call("prepare-bundle"),
      ]);
      report("Alice prepare bundle proof", alicePrepared, { attempt });
      report("Bob prepare bundle proof", bobPrepared, { attempt });
      preparedAttempt = attempt;
      continue;
    }
    const generated = await sender.call("generate-envelope");
    report(`${senderLabel} generate envelope`, generated, {
      attempt,
      sequence,
      bytes: generated.envelope.byteLength,
    });
    const accepted = await receiver.call("accept-envelope", {
      envelope: generated.envelope,
    });
    report(`${senderLabel} peer verification`, accepted, { attempt, sequence });
    envelopes += 1;
  }

  const [aliceBody, bobBody] = await Promise.all([
    alice.call("export-accepted-body"),
    bob.call("export-accepted-body"),
  ]);
  if (!Buffer.from(aliceBody.body).equals(Buffer.from(bobBody.body))) {
    throw new Error("workers disagreed on the verifier-derived accepted body");
  }
  const [aliceVerification, bobVerification] = await Promise.all([
    alice.call("export-verification-attestation"),
    bob.call("export-verification-attestation"),
  ]);
  if (
    aliceVerification.attestation.byteLength === 0 ||
    bobVerification.attestation.byteLength === 0
  ) {
    throw new Error("accepted attempt did not produce verifier attestations");
  }

  const [aliceSignature, bobSignature] = await Promise.all([
    alice.call("make-acceptance-signature", { body: aliceBody.body }),
    bob.call("make-acceptance-signature", { body: bobBody.body }),
  ]);
  report("Alice accepted-body signature", aliceSignature);
  report("Bob accepted-body signature", bobSignature);

  const [aliceFinal, bobFinal] = await Promise.all([
    alice.call("accept-acceptance-signature", {
      role: 1,
      signature: bobSignature.signature,
    }),
    bob.call("accept-acceptance-signature", {
      role: 0,
      signature: aliceSignature.signature,
    }),
  ]);
  report("Alice accepted certificate", aliceFinal);
  report("Bob accepted certificate", bobFinal);
  if (
    aliceFinal.snapshot.status !== "accepted" ||
    bobFinal.snapshot.status !== "accepted" ||
    !aliceFinal.snapshot.hasRetainedPreimages ||
    !bobFinal.snapshot.hasRetainedPreimages
  ) {
    throw new Error("both workers did not reach accepted secret-owning state");
  }

  const [aliceExport, bobExport] = await Promise.all([
    alice.call("export"),
    bob.call("export"),
  ]);
  for (const field of ["body", "deal"]) {
    if (!Buffer.from(aliceExport[field]).equals(Buffer.from(bobExport[field]))) {
      throw new Error(`workers disagreed on exported ${field}`);
    }
  }
  if (aliceExport.deal.byteLength !== 774) {
    throw new Error(`unexpected accepted certificate length ${aliceExport.deal.byteLength}`);
  }
  if (
    aliceExport.attestation.byteLength === 0 ||
    bobExport.attestation.byteLength === 0
  ) {
    throw new Error("accepted exports omitted verifier attestations");
  }

  const aliceStorageKey = new Uint8Array(32).fill(0xc1);
  const aliceSealed = await alice.call("seal-preimages", {
    storageKey: aliceStorageKey,
  });
  report("Alice seal retained preimages", aliceSealed, {
    bytes: aliceSealed.sealedPreimages.byteLength,
  });
  if (!aliceSealed.snapshot.hasRetainedPreimages) {
    throw new Error("sealing did not reconstruct the live preimage owner");
  }

  aliceStorageKey.fill(0);
  const revealed = await alice.call("reveal-local-preimage", { slot: 0 });
  const actualHash = createHash("sha256").update(new Uint8Array(revealed.preimage)).digest();
  const expectedAliceSlotZeroHash = Buffer.from(aliceExport.body).subarray(38, 70);
  if (!actualHash.equals(expectedAliceSlotZeroHash)) {
    throw new Error("slot-zero preimage does not match the accepted hash lock");
  }

  await Promise.all([alice.call("clear"), bob.call("clear")]);
  await Promise.all([alice.terminate(), bob.terminate()]);
  initialWorkersClosed = true;

  console.log(
    JSON.stringify({
      phase: "complete",
      acceptedAttempt: attempt,
      transportedEnvelopes: envelopes,
      acceptedDealBytes: aliceExport.deal.byteLength,
      attestationBytes: aliceExport.attestation.byteLength,
      aliceWasmMiB: aliceExport.snapshot.wasmMiB,
      bobWasmMiB: bobExport.snapshot.wasmMiB,
      retainedPreimageVerified: true,
      rssMiB: Number((process.memoryUsage().rss / 1_048_576).toFixed(2)),
    }),
  );
} finally {
  if (!initialWorkersClosed) {
    await Promise.allSettled([alice.call("clear"), bob.call("clear")]);
    await Promise.allSettled([alice.terminate(), bob.terminate()]);
  }
}
