import { createEsploraChainAdapter, WORKER_METHODS } from "./esplora-client.js";

  let adapter;
  let tail = Promise.resolve();
  self.addEventListener("message", (event) => {
    const { id, type } = event.data ?? {};
    const run = tail.then(async () => {
      if (type === "init") {
        if (adapter) throw new Error("chain-adapter Worker is already initialized");
        adapter = createEsploraChainAdapter(event.data.config, event.data.options);
        return null;
      }
      if (type !== "call" || !adapter || !WORKER_METHODS.includes(event.data.method)) {
        throw new Error("Unknown chain-adapter Worker request");
      }
      return adapter[event.data.method](...(event.data.args ?? []));
    });
    tail = run.catch(() => undefined);
    void run.then(
      (result) => self.postMessage({ id, ok: true, result }),
      (error) => self.postMessage({
        id,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }),
    );
  });
