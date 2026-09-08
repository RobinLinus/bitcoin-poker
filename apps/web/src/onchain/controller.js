import { accountReport } from "./report.js";
import { isTransientChainIndexError } from "./chain-retry.js";
import { Rpc, hex, unhex, encode, decode } from "./wasm-client.js";
import { createBrowserEsploraChainAdapter } from "../bitcoin/esplora-client.js";
import { PreparationCheckpointStore } from "../storage/preparation-checkpoint-store.js";
const $ = (s) => document.querySelector(s),
  random = () => hex(crypto.getRandomValues(new Uint8Array(32)));
const store = new PreparationCheckpointStore("poker-onchain-campaign");
let config,
  chain,
  wallet,
  players = [],
  campaign,
  paused = false;
const status = (text) => {
  $("#status").textContent = text;
};
function render() {
  if (!campaign) return;
  $("#report").textContent = JSON.stringify(campaign.report, null, 2);
  $("#transactions").replaceChildren(
    ...campaign.report.transactions.map((t) => {
      const li = document.createElement("li"),
        a = document.createElement("a");
      a.href = `${config.chain.explorerUrl.replace(/\/$/, "")}/tx/${t.txid}`;
      a.textContent = `${t.label} · block ${t.height} · ${t.txid}`;
      a.target = "_blank";
      li.append(a);
      return li;
    }),
  );
}
async function save() {
  accountReport(campaign.report);
  const data = encode(campaign);
  await store.save(campaign.rooms[0].gameId, "onchain-campaign-v1", data);
  await store.save("latest", "onchain-campaign-v1", data);
  render();
}
async function api(path, body) {
  const r = await fetch(`/api/v1${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const d = await r.json();
  if (!r.ok) throw new Error(d?.error?.message ?? `Relay ${r.status}`);
  return d;
}
async function initialize() {
  config = await (await fetch("/api/v1/config")).json();
  if (config.mode !== "onchainTest" || !config.chain.allowBroadcast)
    throw new Error("Start relay with deployments/mutinynet/onchain-test.json");
  chain = await createBrowserEsploraChainAdapter(config);
  await chain.verifyProfile();
  wallet = new Rpc(new URL("./funding-worker.js", import.meta.url));
}
async function startPlayers() {
  players = campaign.rooms.map(
    () => new Rpc(new URL("./player-worker.js", import.meta.url)),
  );
  const startup = performance.now();
  const keys = await Promise.all(
    players.map((p, i) =>
      p.call("init", {
        ...campaign.rooms[i],
        config,
        expectedWasm: campaign.report.wasm?.sha256,
      }),
    ),
  );
  campaign.report.playerStartupMs ??= performance.now() - startup;
  players.forEach(
    (p, i) =>
      (p.onprogress = (d) => {
        $(i === 0 ? "#alice" : "#bob").textContent = JSON.stringify(d, null, 2);
      }),
  );
  if (!campaign.terms) {
    const order = [0, 1].sort((a, b) =>
      hex(keys[a].keys.identity).localeCompare(hex(keys[b].keys.identity)),
    );
    campaign.order = order;
    campaign.publicKeys = order.map((i) => keys[i].keys);
  }
  return keys;
}
const ordered = () => campaign.order.map((i) => players[i]);
async function views() {
  const v = await Promise.all(ordered().map((p) => p.call("view")));
  v.forEach(
    (x, i) =>
      ($(i === 0 ? "#alice" : "#bob").textContent = JSON.stringify(x, null, 2)),
  );
  return v;
}
function check() {
  if (paused) throw new Error("Paused; use Resume saved test to continue.");
}
async function until(label, operation) {
  status(label);
  const end = Date.now() + 20 * 60 * 1000;
  while (Date.now() < end) {
    check();
    let result;
    try {
      result = await operation();
    } catch (e) {
      if (!isTransientChainIndexError(e)) throw e;
      status(`${label} · waiting for consistent chain indexing`);
    }
    if (result) return result;
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(
    `${label}: confirmation deadline exceeded; test remains resumable`,
  );
}
async function publish(bytes) {
  const info = await wallet.call("inspect", { bytes });
  const s = await chain.transactionStatus(unhex(info.txid));
  if (!["confirmed", "mempool"].includes(s.state)) await chain.publish(bytes);
  return info;
}
async function confirmedOrigin() {
  const info = await wallet.call("inspect", { bytes: unhex(campaign.funding) });
  const output = info.outputs[0];
  return until("Waiting for origin confirmation…", () =>
    chain.originFact({
      outpoint: { displayTxid: unhex(info.txid), vout: 0 },
      valueSat: output.value,
      scriptPubkey: unhex(output.script),
      minConfirmations: 1,
    }),
  );
}
async function recordTransaction(label, bytes, fact) {
  const info = await wallet.call("inspect", { bytes });
  if (!campaign.report.transactions.some((t) => t.txid === info.txid)) {
    const inputValue =
      label === "funding"
        ? campaign.report.funding.inputValue
        : campaign.report.transactions.at(-1).outputs[0].value;
    const fee = inputValue - info.outputs.reduce((sum, o) => sum + o.value, 0);
    if (fee < 0) throw new Error("Transaction value accounting failed");
    campaign.report.transactions.push({
      ...info,
      fee,
      label,
      height: fact.confirmedIn.height,
      blockHash: hex(fact.confirmedIn.displayHash),
    });
    await save();
  }
}
async function execute(bytes, label, spent) {
  campaign.pending = { raw: hex(bytes), label, spent };
  await save();
  const info = await publish(bytes);
  const fact = await until(`Waiting for ${label} confirmation…`, () =>
    chain.spendFact({
      spentOutpoint: {
        displayTxid: unhex(spent.split(":")[0]),
        vout: Number(spent.split(":")[1]),
      },
      expectedSpendingDisplayTxid: unhex(info.txid),
      minConfirmations: 1,
    }),
  );
  if (label !== "refund") {
    await until("Checking confirmation in both player sessions…", async () => {
      await Promise.all(
        players.map((p) =>
          p.call("observe", {
            spentOutpoint: {
              displayTxid: unhex(spent.split(":")[0]),
              vout: Number(spent.split(":")[1]),
            },
            expectedTxid: unhex(info.txid),
          }),
        ),
      );
      return true;
    });
  }
  await recordTransaction(label, bytes, fact);
  campaign.pending = null;
  await save();
  return fact;
}
async function create() {
  const text = $("#key").value.trim();
  $("#key").value = "";
  const secret = unhex(text);
  if ($("#scenario").value !== "setup" && secret.length !== 32)
    throw new Error("Expected a 32-byte test key");
  campaign = {
    rooms: [
      { gameId: random(), playerToken: random(), sender: "alice" },
      { playerToken: random(), sender: "bob" },
    ],
    scenario: $("#scenario").value,
    full: $("#profile").value === "full",
    report: {
      network: "mutinynet",
      startedAt: new Date().toISOString(),
      transactions: [],
      ok: false,
    },
  };
  campaign.rooms[1].gameId = campaign.rooms[0].gameId;
  campaign.report.gameId = campaign.rooms[0].gameId;
  location.hash = campaign.rooms[0].gameId;
  const inviteSecret = random();
  await api("/games", {
    gameId: campaign.rooms[0].gameId,
    playerToken: campaign.rooms[0].playerToken,
    inviteSecret,
  });
  await api(`/games/${campaign.rooms[0].gameId}/join`, {
    playerToken: campaign.rooms[1].playerToken,
    inviteSecret,
  });
  await save();
  await startPlayers();
  if (campaign.scenario === "setup") {
    campaign.terms = {
      regtest: false,
      identities: campaign.publicKeys.map((k) => k.identity),
      reveal_keys: [
        campaign.publicKeys[1].reveal,
        campaign.publicKeys[0].reveal,
      ],
      origin: `${random()}:0`,
      origin_value: (campaign.full ? 40000 : 400) + 45500,
      nonce: Array.from(crypto.getRandomValues(new Uint8Array(32))),
      full: campaign.full,
      fee_multiplier: 1,
      csv: 2,
    };
    campaign.report.browser = navigator.userAgent;
    campaign.report.hardwareConcurrency = navigator.hardwareConcurrency;
    campaign.report.wasm = (
      await (await fetch("/wasm/manifest.json")).json()
    ).artifacts.find((a) => a.name === "session");
    campaign.report.scope =
      "Unfunded setup benchmark; no transactions published";
    await Promise.all(players.map((p) => p.call("configure", campaign.terms)));
    await save();
    return;
  }
  const address = await wallet.call("address", { secret });
  const utxos = await chain.addressUtxos(address.address);
  campaign.report.browser = navigator.userAgent;
  campaign.report.hardwareConcurrency = navigator.hardwareConcurrency;
  campaign.report.wasm = (
    await (await fetch("/wasm/manifest.json")).json()
  ).artifacts.find((a) => a.name === "session");
  const fees = await chain.feeEstimates();
  const estimate = fees["1"] ?? fees["2"] ?? 1;
  const selectedFee = $("#fee-policy").value;
  const multiplier =
    selectedFee === "auto"
      ? Math.max(1, Math.ceil(estimate))
      : Number(selectedFee);
  if (!Number.isInteger(multiplier) || multiplier < 1 || multiplier > 3)
    throw new Error("Invalid fee policy");
  campaign.report.feeEstimate = estimate;
  if (multiplier > 3)
    throw new Error("Current fees exceed this test campaign's budget");
  const value = (campaign.full ? 40000 : 400) + 45500 * multiplier,
    fee = 1000 * multiplier;
  const utxo = utxos
    .filter((u) => u.status.confirmed && u.value >= value + fee + 330)
    .sort((a, b) => a.value - b.value)[0];
  if (!utxo) throw new Error("No suitable confirmed funding output");
  const previous = await chain.rawTransaction(unhex(utxo.txid));
  const raw = await wallet.call("fund", {
    secret: Array.from(secret),
    previous: hex(previous.raw),
    vout: utxo.vout,
    identities: campaign.publicKeys.map((k) => k.identity),
    value,
    fee,
  });
  secret.fill(0);
  const funding = await wallet.call("inspect", { bytes: raw });
  campaign.funding = hex(raw);
  campaign.terms = {
    regtest: false,
    identities: campaign.publicKeys.map((k) => k.identity),
    reveal_keys: [campaign.publicKeys[1].reveal, campaign.publicKeys[0].reveal],
    origin: `${funding.txid}:0`,
    origin_value: value,
    nonce: Array.from(crypto.getRandomValues(new Uint8Array(32))),
    full: campaign.full,
    fee_multiplier: multiplier,
    csv: 2,
  };
  campaign.report.funding = {
    address: address.address,
    inputValue: utxo.value,
    escrowValue: value,
    fee,
    change: funding.outputs[1].value,
  };
  await save();
  await Promise.all(players.map((p) => p.call("configure", campaign.terms)));
  const script = unhex(address.script),
    sigs = await Promise.all(
      ordered().map((p) => p.call("refundSig", { script })),
    );
  const refund = await ordered()[0].call("refund", { script, peer: sigs[1] });
  campaign.refund = hex(refund);
  await save();
  // The exact return is durable before any origin funding is published.
  await publish(raw);
  const fact = await confirmedOrigin();
  await recordTransaction("funding", raw, fact);
  campaign.funded = true;
  await save();
}
async function continueCampaign() {
  check();
  if (campaign.scenario !== "setup" && !campaign.refund)
    throw new Error(
      "Funding/refund construction incomplete; no funding was published",
    );
  if (campaign.scenario !== "setup" && !campaign.funded) {
    await publish(unhex(campaign.funding));
    const f = await confirmedOrigin();
    await recordTransaction("funding", unhex(campaign.funding), f);
    campaign.funded = true;
    await save();
  }
  if (campaign.scenario === "refund") {
    await execute(unhex(campaign.refund), "refund", campaign.terms.origin);
    campaign.report.ok = true;
    await save();
    status("PASS — origin funding and return confirmed");
    return;
  }
  if (!campaign.prepared) {
    status("Authenticating the deal through the relay…");
    const deadline = Date.now() + 180000;
    const setupStarted = performance.now();
    while (true) {
      check();
      const states = await Promise.all(players.map((p) => p.call("deal")));
      if (states.every((s) => s.accepted && s.peerScore)) break;
      if (Date.now() > deadline) throw new Error("Dealing timed out");
    }
    status("Deriving and signing the complete graph in both player sessions…");
    const results = await Promise.all(players.map((p) => p.call("prepare")));
    if (results[0].binding !== results[1].binding)
      throw new Error("Inventory mismatch");
    campaign.report.preparation = results;
    campaign.report.initialSetupMs = performance.now() - setupStarted;
    campaign.report.setupTargetMet = campaign.report.initialSetupMs <= 30000;
    campaign.prepared = true;
    await save();
    // Explicit reload before activation proves preparation and private state survive.
    const start = performance.now();
    await Promise.all(players.map((p) => p.call("reload")));
    campaign.report.localReloadMs = performance.now() - start;
    await save();
  }
  if (campaign.scenario === "setup") {
    campaign.report.ok = true;
    campaign.report.finishedAt = new Date().toISOString();
    await save();
    status("PASS — unfunded full preparation and recovery complete");
    return;
  }
  if (campaign.pending)
    await execute(
      unhex(campaign.pending.raw),
      campaign.pending.label,
      campaign.pending.spent,
    );
  let state = await views();
  if (!state[0].tip) {
    const signatures = await Promise.all(
      ordered().map((p) => p.call("activationSig")),
    );
    const raw = await ordered()[0].call("activation", { bytes: signatures[1] });
    await execute(raw, "activation", campaign.terms.origin);
  }
  for (let step = 0; step < 40; step++) {
    check();
    state = await views();
    if (state.every((s) => s.terminal)) {
      campaign.report.totalFees = campaign.report.transactions.reduce(
        (sum, t) => sum + (t.fee ?? 0),
        0,
      );
      campaign.report.payouts = campaign.report.transactions.at(-1).outputs;
      delete campaign.report.error;
      campaign.report.ok = true;
      campaign.report.finishedAt ??= new Date().toISOString();
      await save();
      status("PASS — complete on-chain scenario and payout confirmed");
      return;
    }
    const current = state[0];
    let actor = current.actor,
      edge = null;
    if (
      campaign.scenario === "fold" &&
      current.actions.some((a) => a.kind.includes("Fold"))
    )
      edge = current.actions.find((a) => a.kind.includes("Fold")).index;
    if (campaign.scenario === "timeout") {
      const t = current.actions.find((a) => a.timeoutHeight !== null);
      actor = t.beneficiary;
      edge = t.index;
      await until(
        `Waiting for unilateral timeout height ${t.timeoutHeight}…`,
        async () => {
          const tip = await chain.tip();
          return tip.block.height + 1 >= t.timeoutHeight;
        },
      );
    }
    const tip = await chain.tip();
    const raw = await ordered()[actor].call("action", {
      edge,
      height: tip.block.height + 1,
    });
    const pending = await ordered()[actor].call("reload");
    if (!pending.pending)
      throw new Error("Pending transaction lost after reload");
    await execute(
      raw,
      edge === null ? current.phase : `edge ${edge}`,
      current.tip,
    );
  }
  throw new Error("Unexpected path length");
}
async function run(resume, returnFunds = false) {
  $("#run").disabled =
    $("#resume").disabled =
    $("#return-funds").disabled =
      true;
  $("#stop").disabled = false;
  paused = false;
  try {
    status("Verifying MutinyNet and loading the player engine…");
    config = await (await fetch("/api/v1/config")).json();
    if (resume) {
      campaign = decode(
        await store.load(
          /^[0-9a-f]{64}$/.test(location.hash.slice(1))
            ? location.hash.slice(1)
            : "latest",
          "onchain-campaign-v1",
        ),
      );
      render();
    } else campaign = null;
    await initialize();
    if (resume) {
      await startPlayers();
      render();
      if (returnFunds) {
        if (
          campaign.report.transactions.some((t) => t.label === "activation") ||
          (campaign.pending && campaign.pending.label !== "refund")
        )
          throw new Error(
            "Activation may already be published; continue the saved game instead",
          );
        campaign.scenario = "refund";
        await save();
      }
    } else await create();
    await continueCampaign();
  } catch (e) {
    status(`STOPPED — ${e.message}`);
    if (campaign) {
      campaign.report.error = e.message;
      await save();
    }
  } finally {
    for (const p of players) p.close();
    players = [];
    wallet?.close();
    $("#run").disabled =
      $("#resume").disabled =
      $("#return-funds").disabled =
        false;
    $("#stop").disabled = true;
  }
}
$("#run").onclick = () => void run(false);
$("#resume").onclick = () => void run(true);
$("#stop").onclick = () => {
  paused = true;
  status("Pausing at the next durable boundary…");
};
$("#download").onclick = () => {
  if (!campaign) return;
  const a = document.createElement("a");
  a.href = URL.createObjectURL(
    new Blob([JSON.stringify(campaign.report, null, 2)], {
      type: "application/json",
    }),
  );
  a.download = "mutinynet-onchain-report.json";
  a.click();
  URL.revokeObjectURL(a.href);
};

$("#return-funds").onclick = () => void run(true, true);

// List only public campaign summaries; credentials and checkpoints stay local.
$("#list-saved").onclick = async () => {
  try {
    const db = await store.database();
    let ids;
    try {
      ids = await new Promise((resolve, reject) => {
        const request = db
          .transaction("checkpoints")
          .objectStore("checkpoints")
          .getAllKeys();
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
    } finally {
      db.close();
    }
    const summaries = [];
    for (const id of ids.filter((id) => /^[0-9a-f]{64}$/.test(id))) {
      const saved = decode(await store.load(id, "onchain-campaign-v1"));
      summaries.push({
        id,
        scenario: saved.scenario,
        startedAt: saved.report.startedAt,
        ok: saved.report.ok,
      });
    }
    summaries.sort((a, b) => b.startedAt.localeCompare(a.startedAt));
    $("#saved-tests").replaceChildren(
      new Option("Choose a saved test", ""),
      ...summaries.map(
        (s) =>
          new Option(
            `${s.scenario} · ${s.ok ? "complete" : "in progress"} · ${s.startedAt} · ${s.id}`,
            s.id,
          ),
      ),
    );
  } catch (e) {
    status(`Cannot list saved tests: ${e.message}`);
  }
};
$("#saved-tests").onchange = () => {
  if ($("#saved-tests").value) location.hash = $("#saved-tests").value;
};
