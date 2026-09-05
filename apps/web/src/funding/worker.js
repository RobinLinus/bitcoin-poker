import { fundingEngine as hooks } from "./engine.js";

    let tail = Promise.resolve();
    self.addEventListener("message", (event) => {
      const { id, type, name, input } = event.data ?? {};
      const run = tail.then(async () => {
        if (type !== "call" || typeof hooks[name] !== "function") {
          throw new Error("Unknown origin Worker request.");
        }
        return hooks[name](input);
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
