import { parentPort } from "node:worker_threads";

import { GameWasmSession, transferBytes } from "./game-runtime.js";

if (!parentPort) {
  throw new Error("node-game-worker must run in a worker thread");
}

let session;

function respond(id, payload, transfer = []) {
  parentPort.postMessage({ id, ok: true, ...payload }, transfer);
}

parentPort.on("message", async (message) => {
  const { id, type } = message ?? {};
  try {
    if (type === "init" || type === "replay") {
      if (session) {
        throw new Error("game-session Worker is already initialized");
      }
      session = await GameWasmSession.create(message.wasm);
      const result = type === "init"
        ? session.initialize(message.config)
        : session.replay({
            config: message.config,
            snapshot: message.snapshot,
          });
      respond(id, result);
      return;
    }
    if (!session) {
      throw new Error("game-session Worker is not initialized");
    }
    switch (type) {
      case "apply-event":
        respond(id, session.applyEvent(message.source, message.event));
        break;
      case "project":
        respond(id, { projection: session.project() });
        break;
      case "snapshot": {
        const snapshot = transferBytes(session.snapshot());
        respond(id, { snapshot, wasmMiB: session.memoryMiB() }, [snapshot]);
        break;
      }
      case "clear":
        session.clear();
        session = undefined;
        respond(id, {});
        parentPort.close();
        break;
      default:
        throw new Error(`unknown game-session Worker request: ${String(type)}`);
    }
  } catch (error) {
    parentPort.postMessage({
      id,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
  }
});
