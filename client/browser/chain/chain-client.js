import { WorkerRpcClient } from "../worker/rpc-client.js?v=2";

const DEFAULT_TIMEOUT_MS = 15 * 60 * 1_000;

function bytes(value, label) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  throw new Error(`${label} must be bytes`);
}

function secretCopy(value, label) {
  if (value === undefined) return undefined;
  const source = bytes(value, label);
  const copy = Uint8Array.from(source);
  source.fill(0);
  return copy;
}

/** Browser-side request client for one dedicated secret CHAIN Worker. */
export class BrowserChainWorker {
  constructor({
    workerUrl = "/browser/chain/chain-worker.js?v=11",
    workerFactory,
    transportRole,
    chainExchangeKind,
    timeoutMs = DEFAULT_TIMEOUT_MS,
  } = {}) {
    if (transportRole !== "alice" && transportRole !== "bob") {
      throw new Error("BrowserChainWorker transportRole must be alice or bob");
    }
    if (
      typeof chainExchangeKind !== "string" ||
      !/^[a-z0-9][a-z0-9._-]{0,31}$/.test(chainExchangeKind)
    ) {
      throw new Error("BrowserChainWorker chainExchangeKind is required");
    }
    this.transportRole = transportRole;
    this.chainExchangeKind = chainExchangeKind;
    this.worker = workerFactory
      ? workerFactory(workerUrl)
      : new Worker(workerUrl, { type: "module", name: "bp52-chain-secret" });
    this.rpc = new WorkerRpcClient(this.worker, {
      timeoutMs,
      closedError: "CHAIN Worker client is closed",
      cancelledError: "CHAIN Worker client was cleared",
      timeoutError: (type) => `CHAIN Worker request timed out: ${type}`,
      rejectedError: "unknown CHAIN Worker error",
      workerError: "CHAIN Worker failed",
    });
  }

  async init({ wasm, config, identitySecret, entropy, deal, snapshotKey }) {
    if (this.rpc.isClosed) throw new Error("CHAIN Worker client is closed");
    const secret = secretCopy(identitySecret, "identitySecret");
    const random = secretCopy(entropy, "entropy");
    const stateKey = secretCopy(snapshotKey, "snapshotKey");
    const storageKey = secretCopy(deal?.storageKey, "DEAL storageKey");
    const request = {
      config: {
        ...config,
        transportRole: this.transportRole,
        chainExchangeKind: this.chainExchangeKind,
      },
      identitySecret: secret,
      entropy: random,
      snapshotKey: stateKey,
      deal: { ...deal, storageKey },
    };
    const transfer = [secret, random, stateKey, storageKey]
      .filter(Boolean)
      .map((value) => value.buffer);
    return this.#request("init", { wasm, request }, transfer);
  }

  signDescriptor(descriptor) { return this.#request("sign-descriptor", { descriptor }); }
  acceptSessionEvent(senderRole, event) {
    return this.#request("accept-session-event", { senderRole, event });
  }
  makeLamportBundle(bundle) { return this.#request("make-lamport-bundle", { bundle }); }
  makeRootCommitment() { return this.#request("make-root-commitment"); }
  openRoot() { return this.#request("open-root"); }
  makePreauthorizationCommitment() { return this.#request("make-preauthorization-commitment"); }
  openPreauthorizations() { return this.#request("open-preauthorizations"); }
  attestInventory() { return this.#request("attest-inventory"); }
  makeInventoryReady() { return this.#request("make-inventory-ready"); }
  signActivation(unsignedTransaction) {
    return this.#request("sign-activation", { unsignedTransaction });
  }
  acceptRelayMessage(message) {
    if (message?.kind !== this.chainExchangeKind) {
      throw new Error("BrowserChainWorker accepts only the configured CHAIN exchange kind");
    }
    return this.#request("accept-relay-message", { message });
  }
  confirmActivation(value) { return this.#request("confirm-activation", value); }
  observeTip(height) { return this.#request("observe-tip", { height }); }
  buildAction(action) { return this.#request("build-action", { action }); }
  buildEdge({ childNodeId }) { return this.#request("build-edge", { childNodeId }); }
  buildReveal() { return this.#request("build-reveal"); }
  buildAliceShowdown(value) { return this.#request("build-alice-showdown", value); }
  buildBobPayout(value) { return this.#request("build-bob-payout", value); }
  buildTimeout() { return this.#request("build-timeout"); }
  confirmChild(value) { return this.#request("confirm-child", value); }
  projectCards() { return this.#request("project-cards"); }
  status() { return this.#request("status"); }

  async clear() {
    await this.rpc.close();
  }

  #request(type, fields = {}, transfer = []) {
    return this.rpc.request(type, fields, { transfer });
  }
}
