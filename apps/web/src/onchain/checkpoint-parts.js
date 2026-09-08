// The immutable artifact is durable before its encrypted journal references it.
// Old pinned engines keep their original monolithic export/restore ABI.
const toBase64 = (value) => {
  let text = "";
  for (let i = 0; i < value.length; i += 32768)
    text += String.fromCharCode(...value.subarray(i, i + 32768));
  return btoa(text);
};
const fromBase64 = (value) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
const digest = async (value) => Array.from(
  new Uint8Array(await crypto.subtle.digest("SHA-256", value)),
  (b) => b.toString(16).padStart(2, "0"),
).join("");

export async function saveCheckpointParts(wasm, store, roomId, record) {
  if (wasm.checkpointPartsVersion !== 1) {
    record.checkpoint = toBase64(wasm.call(16));
    delete record.checkpointParts;
    return;
  }
  let artifact = record.checkpointParts?.artifact ?? null;
  if (record.prepared && !artifact) {
    const data = wasm.call(51);
    if (!data.length) throw new Error("Prepared recovery artifact missing");
    artifact = await digest(data);
    await store.save(`${roomId}/artifact/${artifact}`, roomId, data);
  }
  const journal = wasm.call(50);
  record.checkpointParts = { version: 1, journal: toBase64(journal), artifact };
  delete record.checkpoint;
}

export async function loadCheckpointParts(store, roomId, record) {
  if (!record.checkpointParts) return fromBase64(record.checkpoint);
  const { version, journal, artifact } = record.checkpointParts;
  if (version !== 1) throw new Error("Unsupported recovery journal");
  const metadata = fromBase64(journal);
  if (!artifact) {
    if (record.prepared) throw new Error("Prepared recovery artifact reference missing");
    return metadata;
  }
  const data = await store.load(`${roomId}/artifact/${artifact}`, roomId);
  if (await digest(data) !== artifact) throw new Error("Recovery artifact integrity mismatch");
  const checkpoint = new Uint8Array(metadata.length + data.length);
  checkpoint.set(metadata);
  checkpoint.set(data, metadata.length);
  return checkpoint;
}
