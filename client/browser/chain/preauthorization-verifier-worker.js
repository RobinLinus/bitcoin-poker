import { PreauthorizationBatchVerifier } from "./chain-runtime.js";

self.addEventListener("message", async (event) => {
  const { id, type, wasmModule, batch } = event.data ?? {};
  if (type === "clear") {
    self.close();
    return;
  }
  try {
    if (type !== "verify" && type !== "generate" && type !== "generate-lamport") {
      throw new Error("unknown preauthorization batch request");
    }
    const verifier = await PreauthorizationBatchVerifier.create(wasmModule);
    if (type === "verify") {
      const verifiedCount = verifier.verify(batch);
      batch?.fill?.(0);
      self.postMessage({ id, ok: true, verifiedCount });
    } else {
      const result = type === "generate"
        ? verifier.generate(batch)
        : verifier.generateLamport(batch);
      batch?.fill?.(0);
      self.postMessage({ id, ok: true, result }, [result.buffer]);
    }
    // The parent owns termination. Closing here can race delivery of the
    // result in Chromium, leaving the pool waiting for a reply from a Worker
    // that has already disappeared.
  } catch (error) {
    batch?.fill?.(0);
    self.postMessage({
      id,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
  }
});
