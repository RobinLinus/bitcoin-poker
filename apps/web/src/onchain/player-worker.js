import { enrichDisplayView } from "./display-view.js";
import { saveCheckpointParts, loadCheckpointParts } from "./checkpoint-parts.js";
import { CryptoPool } from "./crypto-pool.js";
import {
  client,
  moduleBytes,
  encode,
  decode,
  hex,
  Rpc,
} from "./wasm-client.js";
import { createEsploraChainAdapter } from "../bitcoin/esplora-client.js";
import { PreparationCheckpointStore } from "../storage/preparation-checkpoint-store.js";
// Each worker owns exactly one player's seed and relay credential. These never
// leave this worker except in authenticated encrypted local storage.
let wasm,
  module,
  seed,
  room,
  terms,
  record,
  store,
  chain,
  lockRelease,
  pool,
  manifest,
  role;
let displayModule, displayWasm, displayUnavailable = false, payoutWasm;
const base64 = (b) => {
  let s = "";
  for (let i = 0; i < b.length; i += 32768)
    s += String.fromCharCode(...b.subarray(i, i + 32768));
  return btoa(s);
};
const bytes = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function api(path, options = {}) {
  const r = await fetch(`/api/v1/games/${room.gameId}${path}`, {
    ...options,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${room.playerToken}`,
    },
  });
  const b = await r.json();
  if (!r.ok) throw new Error(b?.error?.message ?? `Relay ${r.status}`);
  return b;
}
async function persist() {
  if (terms) await saveCheckpointParts(wasm, store, room.gameId, record);
  await store.save(room.gameId, room.gameId, encode(record));
}
async function flush() {
  for (const m of record.outbox)
    await api("/messages", { method: "POST", body: JSON.stringify(m) });
  if (record.outbox.length) {
    record.outbox = [];
    await persist();
  }
}
let sending = Promise.resolve();
function sendSerialized(kind, payload) {
  const work = sending.then(() => send(kind, payload));
  sending = work.catch(() => {});
  return work;
}
async function send(kind, payload) {
  record.outbox.push({
    messageId: hex(crypto.getRandomValues(new Uint8Array(32))),
    kind: `onchain.${kind}`,
    payload: base64(payload),
  });
  await persist();
  await flush();
}
async function messages() {
  const page = await api(`/messages?after=${record.cursor}&limit=64`);
  return page.messages ?? [];
}
async function acceptMessages(handler) {
  for (const m of await messages()) {
    if (m.sender !== room.sender && m.kind.startsWith("onchain."))
      await handler(m.kind, bytes(m.payload));
    record.cursor = m.cursor;
  }
  await persist();
}
async function deal() {
  if (record.prepared || record.preparationCursor !== undefined)
    return { accepted: true, peerScore: true };
  await flush();
  await acceptMessages(async (kind, b) => {
    if (kind === "onchain.deal") wasm.call(5, b);
    else if (kind === "onchain.score") {
      if (record.predealing) record.deferredScore = base64(b);
      else {
        wasm.call(9, b);
        record.peerScore = true;
      }
    } else throw new Error(`Unexpected setup frame ${kind}`);
  });
  let state = decode(wasm.call(7));
  if (state.retry) {
    wasm.call(6, encode(state.attempt + 1));
    await persist();
  }
  if (!state.accepted) {
    const outgoing = wasm.call(3);
    if (outgoing.length) {
      // The durable outbox precedes both protocol advancement and publication.
      record.outbox.push({
        messageId: hex(crypto.getRandomValues(new Uint8Array(32))),
        kind: "onchain.deal",
        payload: base64(outgoing),
      });
      record.pendingDealer = base64(outgoing);
      await persist();
      wasm.call(4, outgoing);
      delete record.pendingDealer;
      await persist();
      await flush();
    }
  }
  state = decode(wasm.call(7));
  if (state.accepted && !record.predealing && !record.scoreSent) {
    const score = wasm.call(8);
    record.scoreSent = true;
    await send("score", score);
  }
  return { ...state, scoreSent: record.scoreSent, peerScore: record.peerScore };
}
async function initializeCrypto() {
  const inventory = wasm.call(11),
    context = {
      inventory,
      key: Array.from(wasm.call(13)),
      material: decode(wasm.call(12)),
      regtest: terms.regtest,
    };
  role = context.material.role;
  pool = new CryptoPool(terms.full ? 4 : 2);
  manifest = await pool.initialize({ module, context });
  return {
    binding: hex(
      new Uint8Array(await crypto.subtle.digest("SHA-256", inventory)),
    ),
    requests: manifest.length / 2,
  };
}
function batches() {
  const jobs = [];
  let list = [],
    weight = 0;
  for (let i = 0; i < manifest.length / 2; i++) {
    if (manifest[2 * i] !== role) continue;
    const w = manifest[2 * i + 1] ? 64 : 1;
    if (weight + w > 512) {
      jobs.push(list);
      list = [];
      weight = 0;
    }
    list.push(i);
    weight += w;
  }
  if (list.length) jobs.push(list);
  return jobs;
}
async function prepare() {
  if (record.prepared) return record.prepared;
  if (record.preparationCursor === undefined)
    record.preparationCursor = record.cursor;
  else record.cursor = record.preparationCursor;
  await persist();
  const started = performance.now();
  wasm.call(10);
  const constructionMs = performance.now() - started;
  const info = await initializeCrypto();
  const cryptoInitializedMs = performance.now() - started;
  await send("inventory", encode(info));
  let bindingMatched = false,
    ownDone = false,
    peerDone = false,
    error,
    received = 0;
  let jobs = batches(),
    jobIndex = 0;
  // Signing and incoming verification share the local-role pool.
  // Private material never crosses the relay.
  const signing = (async () => {
    // Limit outgoing pipelines as well as active CPUs. At most four batches per
    // player are waiting for relay/storage, irrespective of graph size.
    let next = 0;
    await Promise.all(
      Array.from({ length: terms.full ? 4 : 2 }, async () => {
        while (next < jobs.length) {
          const list = jobs[next++];
          const b = new Uint8Array(list.length * 4);
          const v = new DataView(b.buffer);
          list.forEach((n, i) => v.setUint32(i * 4, n, true));
          const response = await pool.run("sign", b);
          const receipt = await pool.run("verify", response);
          wasm.call(14, receipt);
          await sendSerialized("batch", response);
          postMessage({
            event: "progress",
            phase: "signing",
            done: ++jobIndex,
            total: jobs.length,
          });
        }
      }),
    );
    ownDone = true;
    await sendSerialized("done", encode(info));
  })().catch((e) => {
    error = e;
  });
  const deadline = performance.now() + 180000;
  while (!ownDone || !peerDone) {
    if (error) throw error;
    if (performance.now() > deadline)
      throw new Error("Preparation exchange timed out");
    // Do not checkpoint each received batch: incomplete preparation can be
    // reconstructed after a crash from the durable relay log and local seed.
    const page = await messages();
    for (const m of page) {
      if (m.sender !== room.sender && m.kind.startsWith("onchain.")) {
        const b = bytes(m.payload);
        if (m.kind === "onchain.inventory") {
          const p = decode(b);
          if (p.binding !== info.binding)
            throw new Error("Inventory disagreement");
          bindingMatched = true;
        } else if (m.kind === "onchain.batch") {
          if (!bindingMatched)
            throw new Error("Batch before inventory binding");
          const receipt = await pool.run("verify", b);
          wasm.call(14, receipt);
          received++;
        } else if (m.kind === "onchain.done") {
          if (decode(b).binding !== info.binding)
            throw new Error("Completion binding mismatch");
          peerDone = true;
        } else if (m.kind === "onchain.score") {
          wasm.call(9, b);
        } else throw new Error(`Unexpected preparation frame ${m.kind}`);
      }
      record.cursor = m.cursor;
    }
    if (!page.length) await new Promise((r) => setTimeout(r, 50));
  }
  await signing;
  if (error) throw error;
  wasm.call(15);
  record.prepared = info;
  await persist();
  pool.close();
  const result = {
    ...info,
    constructionMs,
    cryptoInitializedMs,
    elapsedMs: performance.now() - started,
    received,
    workers: terms.full ? 4 : 2,
  };
  record.prepared = result;
  await persist();
  return result;
}
async function reconcileConfirmations() {
  for (const r of record.confirmations ?? []) {
    if (hex(await chain.blockHash(r.height)) !== r.hash)
      throw new Error("Confirmed branch changed; reconciliation required");
  }
}
async function publicView() {
  const view = decode(wasm.call(22));
  // Keep the saved signing engine, and use the current engine only to read
  // presentation fields from the independently replayed confirmed journal.
  if (displayModule && view.tip && !displayUnavailable &&
      (view.roundBets === undefined || (view.terminal && (view.opponentCards === undefined || view.nextStacks === undefined)))) {
    try {
      if (!displayWasm) {
        displayWasm = await client(displayModule);
        displayWasm.call(17, wasm.call(16));
      }
      return enrichDisplayView(view, decode(displayWasm.call(22)));
    } catch {
      // Incompatible script revisions must retain their original display.
      displayWasm = null;
      displayUnavailable = true;
    }
  }
  return view;
}
async function command(method, args) {
  switch (method) {
    case "init": {
      room = args;
      chain = createEsploraChainAdapter(args.config);
      await chain.verifyProfile();
      store = new PreparationCheckpointStore(
        `poker-onchain-player-${room.sender}`,
      );
      await new Promise((resolve, reject) =>
        navigator.locks
          .request(
            `poker-onchain/${room.gameId}/${room.sender}`,
            { ifAvailable: true },
            async (lock) => {
              if (!lock) {
                reject(new Error("Player already active"));
                return;
              }
              resolve();
              await new Promise((r) => (lockRelease = r));
            },
          )
          .catch(reject),
      );
      const existing = await store.read("checkpoints", room.gameId);
      if (existing) record = decode(await store.load(room.gameId, room.gameId));
      let raw = await moduleBytes();
      let hash = hex(
        new Uint8Array(await crypto.subtle.digest("SHA-256", raw)),
      );
      const expected = record?.moduleHash ?? args.expectedWasm;
      if (existing && expected && expected !== hash) {
        displayModule = await WebAssembly.compile(raw);
        const cached = await store.read("checkpoints", `engine-${expected}`);
        if (!cached?.bytes)
          throw new Error(
            "Saved game requires its previous Wasm engine; no cached engine is available",
          );
        raw = cached.bytes;
        hash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", raw)));
        if (hash !== expected)
          throw new Error("Cached engine integrity mismatch");
      }
      module = await WebAssembly.compile(raw);
      wasm = await client(module);
      await store.write("checkpoints", `engine-${hash}`, { bytes: raw });
      if (existing) {
        record.moduleHash = hash;
        seed = bytes(record.seed);
        terms = record.terms;
        if (record.checkpoint || record.checkpointParts)
          wasm.call(17, await loadCheckpointParts(store, room.gameId, record));
        if (record.pendingDealer) {
          const pending = bytes(record.pendingDealer);
          if (hex(wasm.call(3)) !== hex(pending))
            throw new Error("Pending dealer replay mismatch");
          wasm.call(4, pending);
          delete record.pendingDealer;
          await persist();
        }
      } else {
        seed = crypto.getRandomValues(new Uint8Array(32));
        record = {
          moduleHash: hash,
          seed: base64(seed),
          outbox: [],
          cursor: 0,
          scoreSent: false,
        };
        await persist();
      }
      await reconcileConfirmations();
      await persist();
      return {
        engineHash: hash,
        keys: decode(wasm.call(2, seed)),
        resumed: !!existing,
        prepared: record.prepared ?? null,
      };
    }
    case "configurePredeal": {
      if (terms) {
        if (JSON.stringify(terms) !== JSON.stringify(args)) throw new Error("Predeal terms changed");
        return;
      }
      terms = args;
      record.terms = args;
      record.predealing = true;
      wasm.call(1, encode({ seed: Array.from(seed), terms }));
      await persist();
      return;
    }
    case "configure": {
      if (record.predealing) {
        wasm.call(29, encode(args));
        terms = args;
        record.terms = args;
        record.predealing = false;
        if (record.deferredScore) {
          wasm.call(9, bytes(record.deferredScore));
          record.peerScore = true;
          delete record.deferredScore;
        }
        await persist();
        return;
      }
      if (terms) {
        if (JSON.stringify(terms) !== JSON.stringify(args))
          throw new Error("Terms changed");
        return;
      }
      terms = args;
      record.terms = args;
      wasm.call(1, encode({ seed: Array.from(seed), terms }));
      await persist();
      return;
    }
    case "deal":
      return deal();
    case "prepare":
      return prepare();
    case "history":
      return (record.confirmations ?? []).map(({ txid, height }) => ({
        txid,
        height,
      }));
    case "view":
      return publicView();
    case "rolloverInfo":
    case "cashout":
    case "rolloverSign": {
      // A fresh wallet operation spends an already-settled payout. The old
      // transaction tree continues to use its pinned engine and checkpoint.
      if (!payoutWasm) {
        payoutWasm = await client(displayModule ?? module);
        payoutWasm.call(17, await loadCheckpointParts(store, room.gameId, record));
      }
      if (method === "cashout") return payoutWasm.call(82, encode(args));
      return method === "rolloverInfo"
        ? decode(payoutWasm.call(25))
        : payoutWasm.call(26, encode(args));
    }
    case "activationSig":
      return wasm.call(18);
    case "activation": {
      const tx = wasm.call(19, args.bytes);
      await persist();
      return tx;
    }
    case "refundSig":
      if (args.buyin) return wasm.call(80, encode(args.buyin));
      return args.rollover
        ? wasm.call(27, encode(args.rollover))
        : wasm.call(23, args.script);
    case "refund": {
      if (args.buyin) return wasm.call(81, encode({buyin:args.buyin,peer:hex(args.peer)}));
      if (args.rollover)
        return wasm.call(
          28,
          encode({ rollover: args.rollover, peer: hex(args.peer) }),
        );
      const b = new Uint8Array(64 + args.script.length);
      b.set(args.peer);
      b.set(args.script, 64);
      return wasm.call(24, b);
    }
    case "action": {
      const tx = wasm.call(20, encode(args));
      await persist();
      return tx;
    }
    case "observe": {
      const fact = await chain.spendFact({
        spentOutpoint: args.spentOutpoint,
        expectedSpendingDisplayTxid: args.expectedTxid,
        minConfirmations: 1,
      });
      if (!fact) throw new Error("Spend is not independently confirmed");
      const observation = {
        transaction: Array.from(fact.spendingTransaction),
        height: fact.confirmedIn.height,
        block_hash: hex(fact.confirmedIn.displayHash),
      };
      wasm.call(21, encode(observation));
      if (displayWasm) {
        try {
          displayWasm.call(21, encode(observation));
        } catch {
          displayWasm = null;
          displayUnavailable = true;
        }
      }
      record.confirmations ??= [];
      if (!record.confirmations.some((r) => r.txid === hex(args.expectedTxid)))
        record.confirmations.push({
          txid: hex(args.expectedTxid),
          height: observation.height,
          hash: observation.block_hash,
        });
      await persist();
      return publicView();
    }
    case "reload": {
      await reconcileConfirmations();
      const saved = await store.load(room.gameId, room.gameId);
      record = decode(saved);
      wasm = await client(module);
      wasm.call(17, await loadCheckpointParts(store, room.gameId, record));
      return publicView();
    }
    default:
      throw new Error("Unknown player command");
  }
}
let serial = Promise.resolve();
self.onmessage = ({ data: { id, method, args } }) => {
  serial = serial.then(async () => {
    try {
      const value = await command(method, args);
      postMessage({ id, value });
    } catch (e) {
      postMessage({ id, error: e.message });
    }
  });
};
