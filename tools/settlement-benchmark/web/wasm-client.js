export function wasmClient(instance) {
  const exports = instance.exports;
  return {
    exports,
    call(name, bytes, ...args) {
      if (bytes) {
        const pointer = exports.tree_input(bytes.byteLength);
        if (!pointer) throw new Error("Wasm input exceeds limit");
        new Uint8Array(exports.memory.buffer, pointer, bytes.byteLength).set(bytes);
      }
      if (exports[name](...args) !== 1) {
        throw new Error(new TextDecoder().decode(new Uint8Array(exports.memory.buffer, exports.tree_error_ptr(), exports.tree_error_len())));
      }
      return new Uint8Array(exports.memory.buffer, exports.tree_output_ptr(), exports.tree_output_len()).slice();
    },
  };
}
export const joinBytes = (...parts) => {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.byteLength; }
  return result;
};
export const hex = bytes => Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
