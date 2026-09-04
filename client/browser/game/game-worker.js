import { GameWasmSession, transferBytes } from "./game-runtime.js";
import { serializeAsync } from "../worker/serial-dispatch.js";

let session;

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
  try {
    if (type === "init" || type === "replay") {
      if (session) {
        throw new Error("game-session Worker is already initialized");
      }
      session = await GameWasmSession.create(event.data.wasm);
      const result = type === "init"
        ? session.initialize(event.data.config)
        : session.replay({
            config: event.data.config,
            snapshot: event.data.snapshot,
          });
      respond(id, result);
      return;
    }
    if (!session) {
      throw new Error("game-session Worker is not initialized");
    }
    switch (type) {
      case "apply-event": {
        const result = session.applyEvent(event.data.source, event.data.event);
        respond(id, result);
        break;
      }
      case "apply-exchange-event": {
        const result = session.applyExchangeEvent(
          event.data.senderRole,
          event.data.event,
        );
        respond(id, {
          projection: result.value.projection,
          dealDispatch: result.value.dealDispatch,
          metrics: result.metrics,
        });
        break;
      }
      case "apply-graph-prepared-receipt": {
        const result = session.applyGraphPreparedReceipt(event.data.receipt);
        respond(id, { projection: result.value, metrics: result.metrics });
        break;
      }
      case "apply-runtime-authorization-receipt": {
        const result = session.applyRuntimeAuthorizationReceipt(event.data.receipt);
        respond(id, { projection: result.value, metrics: result.metrics });
        break;
      }
      case "apply-confirmed-state-receipt": {
        const result = session.applyConfirmedStateReceipt(event.data.receipt);
        respond(id, { projection: result.value, metrics: result.metrics });
        break;
      }
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
        self.close();
        break;
      default:
        throw new Error(`unknown game-session Worker request: ${String(type)}`);
    }
  } catch (error) {
    fail(id, error);
  }
}

self.addEventListener("message", serializeAsync(handleMessage));
