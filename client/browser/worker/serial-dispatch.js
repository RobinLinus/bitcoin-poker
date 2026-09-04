/**
 * Serialize mutable Worker operations in arrival order.
 *
 * `message` listeners do not await one another. Without an explicit queue, an
 * IndexedDB or Wasm initialization await lets a later request mutate the same
 * runtime concurrently. Keep the queue alive after a rejected operation so
 * the worker can report the next request independently.
 */
export function serializeAsync(handler) {
  if (typeof handler !== "function") throw new TypeError("serialized handler is required");
  let tail = Promise.resolve();
  return (...args) => {
    const result = tail.then(() => handler(...args));
    tail = result.catch(() => undefined);
    return result;
  };
}
