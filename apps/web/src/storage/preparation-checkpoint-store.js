import {isBinary,decodeBinary} from '../onchain/binary-codec.js';
/** Integrity-protected preparation cache. It does not assert chain freshness. */
export class PreparationCheckpointStore {
  constructor(name = "poker-preparation") { this.name = name; }
  async database() {
    if (!this.connection) this.connection = new Promise((resolve, reject) => {
      const request = indexedDB.open(this.name, 1);
      request.onupgradeneeded = () => { request.result.createObjectStore("keys"); request.result.createObjectStore("checkpoints"); };
      request.onsuccess = () => {
        const db = request.result;
        db.onversionchange = () => { db.close(); this.connection = null; };
        db.onclose = () => { this.connection = null; };
        resolve(db);
      };
      request.onerror = () => { this.connection = null; reject(request.error); };
    });
    return this.connection;
  }
  async read(store, id) {
    const db = await this.database();
    return await new Promise((resolve, reject) => {
      const request = db.transaction(store).objectStore(store).get(id);
      request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
    });
  }
  async write(store, id, value) {
    const db = await this.database();
    await new Promise((resolve, reject) => {
      const transaction = db.transaction(store, "readwrite");
      transaction.objectStore(store).put(value, id);
      transaction.oncomplete = resolve; transaction.onabort = () => reject(transaction.error); transaction.onerror = () => reject(transaction.error);
    });
  }
  async checkpointIds() {
    const db = await this.database();
    return await new Promise((resolve, reject) => {
      const request = db.transaction("checkpoints").objectStore("checkpoints").getAllKeys();
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  }
  // Caller holds this hand's exclusive player lock. Read durable references,
  // never in-memory ones: a failed save must retain the previous recovery data.
  async pruneSnapshots(gameId) {
    if (!/^[a-f0-9]{64}$/.test(gameId)) return;
    if (!await this.read("checkpoints", gameId)) return;
    const bytes=await this.load(gameId, gameId);
    const saved=isBinary(bytes)?decodeBinary(bytes):JSON.parse(new TextDecoder().decode(bytes));
    const keep = new Set([`${gameId}/artifact/${saved.artifact}`, `${gameId}/journal/${saved.journal}`]);
    const prefix = `${gameId}/`;
    const obsolete = (await this.checkpointIds()).filter(id => typeof id === "string" && id.startsWith(prefix) && /\/(artifact|journal)\/[a-f0-9]{64}$/.test(id) && !keep.has(id));
    if (!obsolete.length) return;
    const db = await this.database();
    await new Promise((resolve, reject) => {
      const transaction = db.transaction("checkpoints", "readwrite");
      const store = transaction.objectStore("checkpoints");
      for (const id of obsolete) store.delete(id);
      transaction.oncomplete = resolve;
      transaction.onabort = () => reject(transaction.error);
      transaction.onerror = () => reject(transaction.error);
    });
  }
  async deleteCheckpoints(ids) {
    if (!ids.length) return;
    const db = await this.database();
    await new Promise((resolve, reject) => {
      const transaction = db.transaction("checkpoints", "readwrite");
      for (const id of ids) transaction.objectStore("checkpoints").delete(id);
      transaction.oncomplete = resolve;
      transaction.onabort = () => reject(transaction.error);
      transaction.onerror = () => reject(transaction.error);
    });
  }
  async encryptionKey() {
    const existing = await this.read("keys", "local");
    if (existing) return existing;
    const candidate = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, false, ["encrypt", "decrypt"]);
    const db = await this.database();
    return await new Promise((resolve, reject) => {
      const transaction = db.transaction("keys", "readwrite");
      const store = transaction.objectStore("keys"), request = store.get("local");
      let key;
      request.onsuccess = () => { key = request.result ?? candidate; if (!request.result) store.put(key, "local"); };
      transaction.oncomplete = () => resolve(key);
      transaction.onabort = () => reject(transaction.error);
      transaction.onerror = () => reject(transaction.error);
    });
  }
  async save(id, binding, plaintext) {
    await this.saveBatch([{id,binding,plaintext}]);
  }
  // Replace snapshots and their durable references in one transaction. An abort
  // retains the complete previous checkpoint; success releases obsolete bytes.
  async saveBatch(entries, deleteIds = []) {
    const key = await this.encryptionKey();
    const records = await Promise.all(entries.map(async ({id,binding,plaintext}) => {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const additionalData = new TextEncoder().encode(`poker/preparation/v1/${id}/${binding}`);
      const ciphertext = await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData}, key, plaintext);
      return {id,value:{version:1,binding,iv,ciphertext}};
    }));
    const db = await this.database();
    await new Promise((resolve,reject) => {
      const transaction=db.transaction('checkpoints','readwrite'),store=transaction.objectStore('checkpoints');
      transaction.oncomplete=resolve;
      transaction.onabort=()=>reject(transaction.error ?? new Error('Checkpoint transaction aborted'));
      transaction.onerror=()=>reject(transaction.error);
      try {
        for(const id of deleteIds) store.delete(id);
        for(const {id,value} of records) store.put(value,id);
      } catch(error) {transaction.abort();reject(error);}
    });
  }
  async load(id, expectedBinding) {
    const [key, record] = await Promise.all([this.read("keys", "local"), this.read("checkpoints", id)]);
    if (!key || !record) throw new Error("Local checkpoint/key unavailable; verified import required");
    if (record.version !== 1 || record.binding !== expectedBinding) throw new Error("Checkpoint context mismatch; verified import required");
    const additionalData = new TextEncoder().encode(`poker/preparation/v1/${id}/${expectedBinding}`);
    return new Uint8Array(await crypto.subtle.decrypt({name: "AES-GCM", iv: record.iv, additionalData}, key, record.ciphertext));
  }
}
