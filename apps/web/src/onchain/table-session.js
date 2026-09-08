import {traceState,traceOperation} from './diagnostics.js';
import {encodeBinary,decodeBinary,encodeProtocol,decodeProtocol} from './binary-codec.js';
import {createRelayPort} from './relay-socket.js';
import {releaseChannelRoom as releaseRelayRoom} from './channel-inbox.js';
import { receiveRelayMessages, sendRelayMessage, sendRelayMessages } from "./relay-inbox.js";
import { HandBuffer, cleanupClosedBuffers } from "./hand-buffer.js";
import { localWallet } from "./local-wallet.js";
import {continueChannelHand} from './channel-redeal.js';
import { playerName, savedPlayerName } from "../practice/render-table.js";
import { formatBitcoinAmount } from "../ui/bitcoin-amount.js";
import { transactionKind, confirmationTitle, actionSubmission } from "./table-feedback.js";
import { Rpc, hex, unhex, encode, decode, sessionEngine, channelWorker } from "./wasm-client.js";
import { PreparationCheckpointStore } from "../storage/preparation-checkpoint-store.js";

// MutinyNet nodes use minrelaytxfee=0.00000100 BTC/kvB.
const WALLET_FEE_RATE = 0.1;
const random = () => hex(crypto.getRandomValues(new Uint8Array(32)));
const outpoint = (text) => ({
  displayTxid: unhex(text.split(":")[0]),
  vout: Number(text.split(":")[1]),
});
export const tableStorage = new PreparationCheckpointStore("poker-playable-table");
const storage = tableStorage;
export function inviteUrl(gameId, secret) {
  return `${location.origin}/#/join/${gameId}/${secret}`;
}
export function parseInvite(text) {
  let hash = text.trim();
  try {
    hash = new URL(hash).hash;
  } catch {}
  const m = hash.match(/^#?\/join\/([a-f0-9]{64})\/([a-f0-9]{64})$/i);
  if (!m) throw new Error("Paste a valid table invitation.");
  return { gameId: m[1].toLowerCase(), inviteSecret: m[2].toLowerCase() };
}
export async function tableApi(path, body, token) {
  const response = await fetch(`/api/v1${path}`, {
    method: body ? "POST" : "GET",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const value = await response.json();
  if (!response.ok)
    throw new Error(
      value?.error?.message ?? `Relay request failed (${response.status})`,
    );
  return value;
}
const api=tableApi;
export class TableSession {
  constructor(config, render) {
    this.config = config;
    this.render = render;
    this.busy = false;
    this.stopped = false;
    this.stage = "Connecting";
  }
  async save() {
    const id = `${this.data.gameId}-${this.data.sender}`;
    const snapshot = encodeBinary(this.data);
    this.saveTask = (this.saveTask ?? Promise.resolve()).catch(() => {}).then(async () => {
      const end=traceOperation('storage.save',{gameId:this.data.gameId,sender:this.data.sender,bytes:snapshot.length},true);
      try {await storage.save(id,"table-v1",snapshot);end();}catch(error){end(error);throw error;}
    });
    return this.saveTask;
  }
  async create(name = savedPlayerName()) {
    this.data = {
      gameId: random(),
      protocol: "channel-v1",
      sender: "alice",
      playerName: playerName(name),
      playerToken: random(),
      inviteSecret: random(),
      cursor: 0,
      peer: {},
      sent: {},
      outbox: [],
      log: [],
    };
    await api("/games", {
      gameId: this.data.gameId,
      playerToken: this.data.playerToken,
      inviteSecret: this.data.inviteSecret,
    });
    await this.save();
    await this.open();
  }
  async join(invite, name = savedPlayerName()) {
    // A revisited invitation restores the existing local guest seat.
    const id = `${invite.gameId}-bob`;
    if (await storage.read("checkpoints", id)) {
      await this.resume(invite.gameId, "bob");
      return;
    }
    this.data = {
      ...invite,
      protocol: "channel-v1",
      sender: "bob",
      playerName: playerName(name),
      playerToken: random(),
      cursor: 0,
      peer: {},
      sent: {},
      outbox: [],
      log: [],
    };
    await api(`/games/${invite.gameId}/join`, {
      playerToken: this.data.playerToken,
      inviteSecret: invite.inviteSecret,
    });
    await this.save();
    await this.open();
  }
  async resume(gameId, sender) {
    this.data = decodeBinary(await storage.load(`${gameId}-${sender}`, "table-v1"));
    if (this.data.successor) return this.resume(this.data.successor, sender);
    await this.open();
  }
  async restoreFundingKey(store = storage) {
    if (this.background || this.data.sender !== "alice") return;
    let record = this.data;
    const visited = new Set();
    while (!record.fundingWalletId && record.previous && !visited.has(record.gameId)) {
      visited.add(record.gameId);
      const id = `${record.previous.gameId}-${record.previous.sender}`;
      if (!(await store.read("checkpoints", id))) break;
      record = decodeBinary(await store.load(id, "table-v1"));
    }
    this.data.fundingWalletId = record.fundingWalletId ?? record.gameId;
    const id = `funding-wallet-${this.data.fundingWalletId}`;
    if (!this.fundingKey && await store.read("checkpoints", id)) {
      const saved = decode(await store.load(id, "funding-wallet-v1"));
      if (!/^[a-f0-9]{64}$/i.test(saved.secret)) throw new Error("Saved wallet is invalid");
      this.fundingKey = saved.secret;
    }
  }
  async rememberFundingKey(secret, store = storage) {
    this.data.fundingWalletId ??= this.data.gameId;
    await store.save(`funding-wallet-${this.data.fundingWalletId}`, "funding-wallet-v1", encode({secret}));
    this.fundingKey = secret;
  }
  async open() {
    try {
      if(!this.background)await cleanupClosedBuffers();
      return await this.openPlayer();
    }
    catch (error) { this.close(); throw error; }
  }
  async openPlayer() {
    if (this.data.protocol !== "channel-v1") throw new Error("Start a new table to use off-chain play.");
    // Load independent resources together, then announce the complete seat once.
    this.data.playerName ??= savedPlayerName();
    const walletReady=localWallet(this.config);walletReady.catch(()=>{});
    const engineReady=sessionEngine();engineReady.catch(()=>{});
    if (this.stopped) throw new Error("Table connection cancelled");
    this.data.walletMode = true;
    this.data.playerName ??= savedPlayerName();
    if (!this.background) location.hash = `/table/${this.data.gameId}/${this.data.sender}`;
    if (this.stopped) throw new Error("Table connection cancelled");
    this.player = channelWorker();
    this.player.onprogress = (progress) => {
      this.progress = progress;
      this.notify();
    };
    this.player.diagnostics={...this.player.diagnostics,gameId:this.data.gameId,sender:this.data.sender,background:!!this.background};
    const relayPort=createRelayPort();
    const initialized = await this.player.call("init", {
      engine:await engineReady,
      relayPort,
      gameId: this.data.gameId,
      sender: this.data.sender,
      playerToken: this.data.playerToken,
      inviteSecret: this.data.inviteSecret,
      config: this.config,
      expectedWasm: this.data.engine,
      previousGameId: this.data.previous?.gameId,
      dealGameId:this.data.dealGameId, candidateTerms:this.data.terms, speculative:!!this.data.bufferCandidate, deferredPayouts:!!this.data.deferredPayouts,
      deckOnly:!!this.data.bufferSlot,
    },[relayPort]);
    this.localWallet=await walletReady;
    // Funding operations are stateless and the lobby already owns this worker.
    this.wallet=this.localWallet.rpc;this.sharedWallet=true;
    this.fundingKey=this.localWallet.secret;
    this.chain ??= this.localWallet.chain;
    if(this.stopped)throw new Error('Table connection cancelled');
    if(this.data.bufferSlot && !initialized.resumed) {await this.player.call("configurePredeal",this.data.terms);this.data.predealConfigured=true;}
    if (!initialized?.keys) throw new Error("Player initialization returned no keys");
    if (this.data.terms) {
      this.view = await this.player.call("view");
      const history = await this.player.call("history");
      for (const item of history)
        if (!this.data.log.some((t) => t.txid === item.txid))
          this.data.log.push({ ...item, label: "Recovered transaction confirmed" });
      if (history.length) this.data.activated = true;
      if (history.length && !this.view.pending) this.data.pending = null;
    }
    this.data.keys = initialized.keys;
    this.data.engine = initialized.engineHash;
    await this.save();
    this.notify();
    if (!this.data.cashout && !this.data.left) await this.sendMany([
      ['keys',{keys:initialized.keys,engine:initialized.engineHash}],
      ['profile',{name:this.data.playerName}],
      ['wallet',{address:this.localWallet.address,script:this.localWallet.script}],
    ]);
    this.timer = setInterval(() => void this.step(), 100);
    await this.step();
  }
  notify() {
    if (this.stopped) return;
    traceState(`table/${this.data?.gameId}/${this.data?.sender}`,'table.state',{
      gameId:this.data?.gameId,sender:this.data?.sender,background:!!this.background,
      stage:this.stage,node:this.view?.node,actor:this.view?.actor,pending:!!this.view?.pendingMove,
      terminal:!!this.view?.terminal,phase:this.progress?.phase,
      percent:this.progress?.total?Math.floor(10*this.progress.done/this.progress.total)*10:undefined,
      queued:this.data?.outbox?.length,error:this.actionError??this.error,
    },{heartbeat:15000});
    this.render({
      activeSession: this,
      data: this.data,
      view: this.view,
      stage: this.stage,
      error: this.actionError ?? this.error,
      busy: this.busy,
      busyAction: this.busyAction,
      hasFundingWallet: !!this.fundingKey,
      walletAddress: this.localWallet?.address,
      walletBalance: this.localWallet?.balance,
      submission: this.submission,
      progress: this.progress,
      chainHeight: this.chainHeight,
    });
  }
  async send(kind, value) {
    if (this.data.sent[kind]) return;
    const payload = encodeProtocol(value);
    this.data.sent[kind] = true;
    this.data.outbox.push({
      messageId: random(),
      kind: `table.${kind}`,
      payload,
    });
    await this.save();
    await this.flush();
  }
  async sendMany(entries) {
    for(const [kind,value] of entries) {
      if(this.data.sent[kind])continue;
      this.data.sent[kind]=true;
      this.data.outbox.push({messageId:random(),kind:`table.${kind}`,payload:encodeProtocol(value)});
    }
    await this.save();await this.flush();
  }
  async flush() {
    if (this.flushTask) return this.flushTask;
    this.flushTask = this.flushOutbox();
    try { await this.flushTask; } finally { this.flushTask = null; }
  }
  async postMessage(message) { return sendRelayMessage(this.data, message); }
  async flushOutbox() {
    while (this.data.outbox.length) {
      if (this.data.outbox[0].kind === "table.nextReady") {
        this.data.outbox[0].kind = "table.nextready";
        await this.save();
      }
      try {
        const batch=this.data.outbox.slice(0,32);
        if (await (batch.length===1?this.postMessage(batch[0]):sendRelayMessages(this.data,batch)) === false) return;
        this.data.outbox.splice(0,batch.length-1);
      } catch (e) {
        if (e.message.includes("both player capabilities must be fixed"))
          return;
        throw e;
      }
      this.data.outbox.shift();
      await this.save();
    }
  }
  async receive() {
    const page = await receiveRelayMessages(this.data, this.data.cursor,{kindPrefix:"table."});
    if(!page.messages?.length)return false;
    for (const message of page.messages ?? []) {
      if (
        message.sender !== this.data.sender &&
        message.kind.startsWith("table.")
      ) {
        const kind = message.kind.slice(6),
          value = decodeProtocol(message.payload);
        if(kind === "buffer") {
          if(!Number.isSafeInteger(value.revision) || value.revision<0) throw new Error("Invalid buffer revision");
          if(!this.data.peer.buffer || value.revision>this.data.peer.buffer.revision) this.data.peer.buffer=value;
          this.data.cursor=message.cursor;continue;
        }
        if (
          ![
            "keys",
            "profile",
            "wallet",
            "buyincoin",
            "buyinsig",
            "leave",
            "proposal",
            "refund",
            "ready",
            "boundready",
            "activation",
            "nextready",
            "predeal",
            "next",
            "rollover",
          ].includes(kind)
        )
          throw new Error("Unknown table message");
        if (
          this.data.peer[kind] &&
          JSON.stringify(this.data.peer[kind]) !== JSON.stringify(value)
        )
          throw new Error("Opponent changed agreed table data");
        this.data.peer[kind] = value;
        if (kind === "profile") this.notify();
      }
      this.data.cursor = message.cursor;
    }
    await this.save();
    return (page.messages ?? []).length === 64;
  }
  keys() {
    if (!this.data.peer.keys) return null;
    const peer = this.data.peer.keys;
    if (peer.engine !== this.data.engine)
      throw new Error(
        "Both players need the same game version. Start a fresh table after updating.",
      );
    return [this.data.keys, peer.keys].sort((a, b) =>
      hex(a.identity).localeCompare(hex(b.identity)),
    );
  }
  async previousPlayer() {
    if (!this.priorPlayer) {
      this.priorPlayer = new Rpc(
        new URL("./player-worker.js", import.meta.url),
      );
      try {
        await this.priorPlayer.call("init", {
          ...this.data.previous,
          config: this.config,
        });
      } catch (error) {
        this.priorPlayer.close();
        this.priorPlayer = null;
        throw error;
      }
    }
    return this.priorPlayer;
  }
  async nextHand() {
    if(this.data.protocol==='channel-v1') {await this.setSitOutNext(false);return this.step();}
    if (this.busy || !this.view?.terminal || this.data.sitOutNext) return;
    if (this.pollTask) return this.afterPoll(() => this.nextHand(), "next-hand");
    this.busy = true;
    this.busyAction = "next-hand";
    this.error = null;
    this.actionError = null;
    this.notify();
    try {
      const info = await this.player.call("rolloverInfo");
      if (info.nextStacks.some((n) => n < 200))
        throw new Error(
          "A player is below the ₿200 minimum. Start a new table to rebuy.",
        );
      this.data.wantsNext = true;
      await this.save();
      await this.send("nextready", { tip: this.view.tip });
    } catch (e) {
      this.actionError = this.error = e.message;
    } finally {
      this.busy = false;
      this.busyAction = null;
      this.notify();
    }
    await this.step();
  }
  startPredeal() {
    if(this.background || this.stopped || this.data.leaveRequested || this.data.peer.leave) return;
    this.handBuffer ??= new HandBuffer(this);
    this.handBuffer.pump();
  }
  async tickPredeal() {
    await this.flush();
    while (await this.receive()) {}
    if(this.data.bufferCandidate) return this.advanceChannel();
    const keys = this.keys();
    if(this.data.channelContinuation) return this.advanceChannel();
    if (!keys || this.data.deckReady) return;
    const role = keys.findIndex(key => hex(key.identity) === hex(this.data.keys.identity));
    const terms = this.data.bufferSlot ? this.data.terms : this.data.channelParentTerms ? {
      ...this.data.channelParentTerms, nonce:this.data.predealContext.nonce,
      predeal_anchor:Array.from(unhex(this.data.gameId)), button:1-(this.data.channelParentTerms.button??0),
    } : {
      regtest: false, identities: keys.map(key => key.identity),
      reveal_keys: [keys[1].reveal, keys[0].reveal],
      origin: `${"01".repeat(32)}:0`, origin_value: 85500,
      nonce: this.data.predealContext.nonce, predeal_anchor: Array.from(unhex(this.data.gameId)),
      full: true, fee_multiplier: 1, csv: 12, stacks: [20000, 20000],
      button: this.data.sender === this.data.predealContext.buttonSender ? role : 1 - role,
    };
    if (!this.data.predealConfigured) {
      await this.player.call("configurePredeal", terms);
      this.data.predealConfigured = true;
      await this.save();
    }
    const state = await this.player.call("deal");
    if (state.accepted) {
      this.data.deckReady = true;
      clearInterval(this.timer);
      await this.save();
    }
  }
  async setSitOutNext(value) {
    if(this.data?.protocol==='channel-v1' && this.data.wantsNext) {this.notify();return;}
    if (!this.data || this.data.successor || this.data.leaveRequested || this.data.peer.leave || this.data.cashout || this.data.left) {
      this.notify();
      return;
    }
    this.data.sitOutNext = value;
    this.notify();
    try {
      await this.save();
      if (!value) await this.step();
    } catch (error) {
      this.actionError = error.message;
      this.notify();
    }
  }
  async continueHand() {
    if(this.data.protocol === "channel-v1") return continueChannelHand.call(this);
    if (!this.view?.terminal) return;
    this.handEndedAt ??= Date.now();
    if (this.data.sitOutNext || this.data.peer.leave || this.data.cashout) return this.cashOut();
    if (!this.data.wantsNext) {
      this.stage = "Hand settled";
      if (Date.now() - this.handEndedAt < 3000) return;
      const info = await this.player.call("rolloverInfo");
      if (info.nextStacks.some((amount) => amount < 200)) return this.cashOut();
      if (this.data.sitOutNext || this.data.peer.leave) return;
      this.data.wantsNext = true;
      this.notify();
      await this.save();
    }
    this.stage = "Waiting for your opponent’s next-hand confirmation";
    await this.send("nextready", { tip: this.view.tip });
    if (!this.data.peer.nextready || this.data.sitOutNext) return;
    if (this.data.peer.nextready.tip !== this.view.tip)
      throw new Error(
        "Next hand does not reference the same confirmed payout.",
      );
    if (this.predealTask) await this.predealTask;
    if (this.data.sender === "alice") {
      this.data.next ??= {
        gameId: this.data.predealPlan?.gameId ?? random(),
        inviteSecret: this.data.predealPlan?.inviteSecret ?? random(),
        tip: this.view.tip,
      };
      this.data.nextToken ??= random();
      await this.save();
      await api("/games", {
        gameId: this.data.next.gameId,
        inviteSecret: this.data.next.inviteSecret,
        playerToken: this.data.nextToken,
      });
      await this.send("next", this.data.next);
    }
    const next =
      this.data.sender === "alice" ? this.data.next : this.data.peer.next;
    if (!next || this.data.sitOutNext) return;
    if (
      !/^[a-f0-9]{64}$/.test(next.gameId) ||
      !/^[a-f0-9]{64}$/.test(next.inviteSecret) ||
      next.tip !== this.view.tip ||
      next.gameId === this.data.gameId
    )
      throw new Error("Invalid next-hand invitation.");
    this.data.nextToken ??= random();
    await this.save();
    if (this.data.sender === "bob")
      await api(`/games/${next.gameId}/join`, {
        inviteSecret: next.inviteSecret,
        playerToken: this.data.nextToken,
      });
    const info = await this.player.call("rolloverInfo");
    if (this.data.sitOutNext || this.data.peer.leave) return;
    const old = this.data;
    if (this.nextSession?.data.gameId === next.gameId) {
      const warm = this.nextSession;
      if (warm.pollTask) await warm.pollTask;
      if (old.sitOutNext) return;
      old.successor = next.gameId;
      this.notify();
      await this.save();
      const fundingKey = this.fundingKey;
      this.nextSession = null;
      this.close();
      warm.background = false;
      clearInterval(warm.timer);
      warm.timer = setInterval(() => void warm.step(), 1500);
      warm.render = this.render;
      warm.fundingKey = fundingKey;
      warm.localWallet = this.localWallet;
      warm.data.fundingWalletId = old.fundingWalletId;
      warm.data.predealOnly = false;
      warm.data.previous = { gameId: old.gameId, sender: old.sender, playerToken: old.playerToken, expectedWasm: old.engine };
      warm.data.continuation = { previous: info.previous, stacks: info.nextStacks, role: info.role, button: info.button, feeMultiplier: old.terms.fee_multiplier };
      warm.stage = "Connecting the next hand";
      location.hash = `/table/${warm.data.gameId}/${warm.data.sender}`;
      await warm.save();
      warm.notify();
      await warm.step();
      return;
    }
    const id = `${next.gameId}-${old.sender}`;
    let child;
    if (await storage.read("checkpoints", id))
      child = decodeBinary(await storage.load(id, "table-v1"));
    else {
      child = {
        gameId: next.gameId,
        inviteSecret: next.inviteSecret,
        sender: old.sender,
        playerToken: old.nextToken,
        handNumber: (old.handNumber ?? 1) + 1,
        cursor: 0,
        peer: {},
        sent: {},
        outbox: [],
        log: [],
        previous: {
          gameId: old.gameId,
          sender: old.sender,
          playerToken: old.playerToken,
          expectedWasm: old.engine,
        },
        continuation: {
          previous: info.previous,
          stacks: info.nextStacks,
          role: info.role,
          button: info.button,
          feeMultiplier: old.terms.fee_multiplier,
        },
      };
      await storage.save(id, "table-v1", encodeBinary(child));
    }
    if (old.sitOutNext) return;
    child.playerName = old.playerName;
    child.opponentName = old.peer.profile?.name ?? old.opponentName;
    child.fundingWalletId = old.fundingWalletId;
    child.predealOnly = false;
    child.previous = { gameId: old.gameId, sender: old.sender, playerToken: old.playerToken, expectedWasm: old.engine };
    child.continuation = { previous: info.previous, stacks: info.nextStacks, role: info.role, button: info.button, feeMultiplier: old.terms.fee_multiplier };
    await storage.save(id, "table-v1", encodeBinary(child));
    old.successor = next.gameId;
    this.notify();
    await this.save();
    const fundingKey = this.fundingKey;
    this.close();
    this.fundingKey = fundingKey;
    this.handEndedAt = null;
    this.data = child;
    this.view = null;
    this.progress = null;
    this.error = null;
    this.priorPlayer = null;
    this.stopped = false;
    this.busy = false;
    this.stage = "Connecting the next hand";
    await this.open();
  }
  nextTerms(keys) {
    if (!this.data.continuation) return { stacks: [20000, 20000], button: 0 };
    const c = this.data.continuation;
    const newRole = keys.findIndex(
      (k) => hex(k.identity) === hex(this.data.keys.identity),
    );
    const stacks = newRole === c.role ? c.stacks : [...c.stacks].reverse();
    const button = newRole === c.role ? 1 - c.button : c.button;
    return { stacks, button };
  }
  async requiredReserve(multiplier, stacks=[20000,20000], button=0) {
    const keys=this.keys();
    const cacheKey=JSON.stringify([multiplier,stacks,button]);
    this.reserveQuotes ??= new Map();
    if(this.reserveQuotes.has(cacheKey)) return this.reserveQuotes.get(cacheKey);
    const reserve = await this.wallet.call("reserve",{regtest:false,identities:keys.map(k=>k.identity),reveal_keys:[keys[1].reveal,keys[0].reveal],origin:`${"01".repeat(32)}:0`,origin_value:stacks[0]+stacks[1]+45500*multiplier,nonce:Array(32).fill(1),full:true,fee_multiplier:multiplier,csv:12,stacks,button});
    this.reserveQuotes.set(cacheKey,reserve);
    return reserve;
  }
  async startInitialDeal(plan,value) {
    if(this.initialDealError) {const error=this.initialDealError;this.initialDealError=null;throw error;}
    if(!this.data.predealConfigured) {
      const keys=this.keys();
      this.data.predealContext={nonce:plan.nonce};
      await this.player.call('configurePredeal',{regtest:false,identities:keys.map(k=>k.identity),reveal_keys:[keys[1].reveal,keys[0].reveal],
        origin:`${'01'.repeat(32)}:0`,origin_value:value,predeal_anchor:Array.from(unhex(this.data.gameId)),nonce:plan.nonce,
        full:true,fee_multiplier:plan.multiplier,fee_reserve:plan.reserve,csv:12});
      this.data.predealConfigured=true;await this.save();
    }
    if(this.initialDealTask || this.data.initialDeckReady || this.initialDealBinding)return;
    this.initialDealTask=(async()=>{
      while(!this.stopped && !this.initialDealBinding && !this.data.proposal && !this.data.peer.proposal) {
        const state=await this.player.call('deal');
        if(state.accepted) {this.data.initialDeckReady=true;await this.save();return;}
        await new Promise(resolve=>setTimeout(resolve,25));
      }
    })().catch(error=>{if(!this.stopped)this.initialDealError=error;}).finally(()=>{this.initialDealTask=null;});
  }
  async prepareBuyIn() {
    const plan=await this.openingPlan();
    const reserve=plan.reserve;
    const value = 40000 + reserve + 1000 * plan.multiplier;
    await this.startInitialDeal(plan,value);
    // Two Taproot inputs and three outputs: 255 virtual bytes when signed.
    const fee = Math.ceil(255 * plan.multiplier);
    const index = this.data.sender === "alice" ? 0 : 1;
    const needed = value/2 + Math.floor(fee/2) + (index ? fee%2 : 0) + 330;
    if (!this.data.peer.wallet) {this.stage="Waiting for your opponent’s wallet";return;}
    const sharedWallet=this.data.peer.wallet.script===this.localWallet.script;
    // One browser profile can host both seats. Let Alice choose first so Bob
    // can exclude that exact outpoint before announcing his immutable input.
    if(sharedWallet && index===1 && !this.data.peer.buyincoin) {
      this.stage="Waiting for the host’s buy-in";return;
    }
    if (!this.data.buyincoin) {
      if(Date.now()<(this.walletCheckAt??0)) return;
      this.walletCheckAt=Date.now()+3000;
      const coins = await this.localWallet.refresh();
      const peerCoin=this.data.peer.buyincoin;
      const peerTxid=peerCoin ? (await this.wallet.call('inspect',{bytes:unhex(peerCoin.previous)})).txid : null;
      const coin = coins.filter(c=>c.value>=needed && !(c.txid===peerTxid && c.vout===peerCoin?.vout))
        .sort((a,b)=>Number(b.status.confirmed)-Number(a.status.confirmed)||a.value-b.value||a.txid.localeCompare(b.txid)||a.vout-b.vout)[0];
      if (!coin) {
        this.data.walletNeeded = needed;
        this.data.walletSeparatePayment = !!(sharedWallet && peerCoin);
        this.stage = sharedWallet && peerCoin ? "Send another payment to this wallet" : "Waiting for wallet funds";
        this.notify(); return;
      }
      const previous = await this.chain.rawTransaction(unhex(coin.txid));
      this.data.buyincoin = {previous:hex(previous.raw),vout:coin.vout,script:this.localWallet.script};
      delete this.data.walletNeeded;
      delete this.data.walletSeparatePayment;
      await this.save();
    }
    await this.send("buyincoin",this.data.buyincoin);
    if (!this.data.peer.buyincoin || !this.data.peer.wallet) {this.stage="Waiting for your opponent’s buy-in";return;}
    if (this.data.sender !== "alice") return;
    const keys = this.keys();
    const buyin = {coins:[this.data.buyincoin,this.data.peer.buyincoin],identities:keys.map(k=>k.identity),value,fee};
    const raw = await this.wallet.call("buyinPreview",buyin);
    const info = await this.wallet.call("inspect",{bytes:raw});
    this.data.proposal = {funding:hex(raw),buyin,returnScript:this.localWallet.script,terms:{regtest:false,identities:buyin.identities,reveal_keys:[keys[1].reveal,keys[0].reveal],origin:`${info.txid}:0`,origin_value:value,predeal_anchor:Array.from(unhex(this.data.gameId)),nonce:plan.nonce,full:true,fee_multiplier:plan.multiplier,fee_reserve:reserve,csv:12}};
    await this.save();await this.send("proposal",this.data.proposal);
  }
  async verifyBuyIn(p) {
    const b=p.buyin, index=this.data.sender === "alice" ? 0 : 1;
    const plan=await this.openingPlan();
    if (this.data.continuation || !plan || p.terms.fee_multiplier!==plan.multiplier || JSON.stringify(p.terms.nonce)!==JSON.stringify(plan.nonce) ||
        JSON.stringify(b.coins?.[index])!==JSON.stringify(this.data.buyincoin) ||
        JSON.stringify(b.coins?.[1-index])!==JSON.stringify(this.data.peer.buyincoin) ||
        b.coins[index].script!==this.localWallet.script || b.coins[1-index].script!==this.data.peer.wallet?.script ||
        p.terms.fee_reserve!==plan.reserve || b.value!==p.terms.origin_value || b.fee!==Math.ceil(255*plan.multiplier) || JSON.stringify(b.identities)!==JSON.stringify(p.terms.identities) ||
        hex(await this.wallet.call("buyinPreview",b))!==p.funding) throw new Error("Buy-in changed the agreed wallet inputs or amounts");
    await this.checkBuyInCoins(b,false);
  }
  async openingPlan() {
    // The opening stakes, rate and topology are fixed by this protocol. The
    // unique room ID supplies the public nonce; no extra negotiation is needed.
    if(!this.data.buyinplan) {
      this.data.buyinplan={multiplier:WALLET_FEE_RATE,reserve:await this.requiredReserve(WALLET_FEE_RATE),nonce:Array.from(unhex(this.data.gameId))};
      await this.save();
    }
    return this.data.buyinplan;
  }
  async checkBuyInCoins(b,requireConfirmed) {
    for(const coin of b.coins) {
      const info=await this.wallet.call('inspect',{bytes:unhex(coin.previous)}),output=info.outputs[coin.vout];
      if(!output || output.script!==coin.script) throw new Error('Buy-in output changed');
      const status=await this.chain.outpointStatus(outpoint(`${info.txid}:${coin.vout}`));
      if(status.state!=='unspent' || !['mempool','confirmed'].includes(status.creatingStatus?.state)) throw new Error('Buy-in coin is unavailable');
      if(requireConfirmed && status.creatingStatus.state!=='confirmed') return false;
    }
    return true;
  }
  async leaveTable() {
    if (!this.view?.terminal || !this.data.sitOutNext || this.data.wantsNext || this.data.handoffStarted || this.data.left || this.data.leaveRequested) return;
    this.data.leaveRequested = true;
    this.stage = "Cashing out…";
    this.actionError = null;
    this.notify();
    try { await this.save(); await this.step(); }
    catch (error) { this.actionError = error.message; this.notify(); }
  }
  async cashOut() {
    if (this.data.left) return;
    if (!this.view?.terminal || this.data.handoffStarted) throw new Error("Cannot cash out during a hand transition");
    const settlement = {hand:this.view.hand,node:this.view.node};
    const peer = this.data.peer.leave;
    if (peer && (peer.hand !== settlement.hand || peer.node !== settlement.node)) throw new Error("Cashout settlement mismatch");
    this.data.leaveRequested = true;
    this.stage = "Cashing out…";
    this.notify();
    await this.save();
    this.handBuffer?.close();
    this.nextSession?.close(); this.nextSession = null;
    if (!this.data.cashout) {
      await this.send("leave",settlement);
      if (!peer) {this.stage="Waiting for your opponent to cash out…";return;}
      const scripts = [];
      scripts[this.view.role] = Array.from(unhex(this.localWallet.script));
      scripts[1-this.view.role] = Array.from(unhex(this.data.peer.wallet.script));
      this.view = await this.player.call("cashout",{scripts});
      if (!this.view.cashout) return;
      this.data.cashout = this.view.cashout;
      await this.save();
    }
    if(Date.now()<(this.cashoutCheckAt??0)) return;
    this.cashoutCheckAt=Date.now()+3000;
    const info = await this.publish(unhex(this.data.cashout));
    const status = await this.chain.transactionStatus(unhex(info.txid));
    if (status.state !== "confirmed") return;
    this.data.cashoutTxid = info.txid;
    this.data.cashoutOutputs = info.outputs;
    this.data.left = true;
    await this.save();
    clearInterval(this.timer);
    this.stage = "Funds returned";
    this.notify();
    await this.handBuffer?.discardUnused();
    await this.localWallet.refresh();
  }
  async fund(secretText, { fromPoll = false } = {}) {
    if (this.busy || this.data.sender !== "alice" || this.data.proposal) return;
    if (this.pollTask && !fromPoll) return this.afterPoll(() => this.fund(secretText), "fund");
    this.busy = true;
    this.busyAction = "fund";
    this.error = null;
    this.actionError = null;
    this.stage = "Preparing table funding";
    this.notify();
    let secret;
    try {
      secret = unhex(secretText.trim());
      if (secret.length !== 32)
        throw new Error("Invalid wallet key.");
      const keys = this.keys();
      if (!keys) throw new Error("Wait for your opponent to join.");
      const address = await this.wallet.call("address", { secret });
      const feeMultiplier = Math.max(
        this.data.continuation?.feeMultiplier ?? 0.1,
        WALLET_FEE_RATE,
      );
      if (feeMultiplier > 3)
        throw new Error("Network fees exceed this table’s funding limit.");
      const { stacks, button } = this.nextTerms(keys);
      let reserve = await this.requiredReserve(feeMultiplier,stacks,button);
      let value = stacks[0] + stacks[1] + reserve + 1000 * feeMultiplier;
      const
        fee = Math.ceil((this.data.continuation ? 269 : 154) * feeMultiplier);
      let previousPayout,
        payoutValue = 0;
      if (this.data.continuation) {
        const previous = await this.previousPlayer();
        const info = await previous.call("rolloverInfo");
        if (info.previous !== this.data.continuation.previous)
          throw new Error("Saved settlement changed.");
        previousPayout = info.previous;
        payoutValue = info.payouts.reduce((a, b) => a + b, 0);
        reserve = Math.max(reserve, payoutValue - stacks[0] - stacks[1] + 330);
        value = stacks[0] + stacks[1] + reserve + 1000 * feeMultiplier;
      }
      const utxos = await this.chain.addressUtxos(address.address);
      const coin = utxos
        .filter(
          (u) =>
            u.status.confirmed && u.value >= value + fee + 330 - payoutValue,
        )
        .sort((a, b) => a.value - b.value)[0];
      if (!coin) {
        this.data.walletNeeded = Math.max(0,value + fee + 330 - payoutValue);
        this.stage = "Waiting for wallet funds";
        if (this.localWallet) await this.localWallet.refresh();
        return;
      }
      delete this.data.walletNeeded;
      const previous = await this.chain.rawTransaction(unhex(coin.txid));
      const rollover = previousPayout
        ? {
            previous: previousPayout,
            sponsor_previous: hex(previous.raw),
            sponsor_vout: coin.vout,
            sponsor_script: address.script,
            identities: keys.map((k) => k.identity),
            value,
            fee,
          }
        : null;
      const rolloverFunding = rollover
        ? await this.wallet.call("rollover", {
            rollover,
            secret: Array.from(secret),
          })
        : null;
      const raw = rollover
        ? unhex(rolloverFunding.funding)
        : await this.wallet.call("fund", {
            secret: Array.from(secret),
            previous: hex(previous.raw),
            vout: coin.vout,
            identities: keys.map((k) => k.identity),
            value,
            fee,
          });
      const info = await this.wallet.call("inspect", { bytes: raw });
      this.data.proposal = {
        funding: hex(raw),
        returnScript: address.script,
        ...(rollover
          ? { rollover, sponsorSignature: rolloverFunding.signature }
          : {}),
        terms: {
          regtest: false,
          identities: keys.map((k) => k.identity),
          reveal_keys: [keys[1].reveal, keys[0].reveal],
          origin: `${info.txid}:0`,
          origin_value: value,
          nonce: this.data.predealContext?.nonce ?? Array.from(crypto.getRandomValues(new Uint8Array(32))),
          ...(this.data.predealContext ? { predeal_anchor: Array.from(unhex(this.data.gameId)) } : {}),
          full: true,
          fee_multiplier: feeMultiplier,
          fee_reserve: reserve,
          csv: 12,
          ...(rollover ? { stacks, button } : {}),
        },
      };
      this.fundingKey = secretText.trim();
      await this.save();
      await this.send("proposal", this.data.proposal);
    } catch (e) {
      this.actionError = this.error = e.message;
    } finally {
      secret?.fill(0);
      this.busy = false;
      this.busyAction = null;
      this.notify();
    }
  }
  async configure() {
    if(this.data.terms) return true;
    if (this.data.refund) {
      if (!this.data.sent.refund)
        await this.send(
          "refund",
          hex(
            await this.player.call("refundSig", {
              script: unhex(this.data.proposal.returnScript),
              rollover: this.data.proposal.rollover,
              buyin: this.data.proposal.buyin,
            }),
          ),
        );
      return true;
    }
    const p = this.data.proposal ?? this.data.peer.proposal;
    if (!p) return false;
    this.initialDealBinding=true;
    if(this.initialDealTask) await this.initialDealTask;
    if(this.initialDealError) {const error=this.initialDealError;this.initialDealError=null;throw error;}
    const keys = this.keys(),
      t = p.terms;
    const expected = keys && this.nextTerms(keys);
    if(p.buyin && !this.data.predealContext) {
      const plan=await this.openingPlan();
      if(plan)this.data.predealContext={nonce:plan.nonce};
    }
    if (JSON.stringify(t.predeal_anchor ?? null) !== JSON.stringify(this.data.predealContext ? Array.from(unhex(this.data.gameId)) : null) ||
        (this.data.predealContext && JSON.stringify(t.nonce) !== JSON.stringify(this.data.predealContext.nonce)))
      throw new Error("Funding changed the prepared deck context");
    if (
      !keys ||
      t.regtest ||
      t.full !== true ||
      t.csv !== 12 ||
      !Number.isFinite(t.fee_multiplier) ||
      t.fee_multiplier < 0.1 ||
      t.fee_multiplier > 3 ||
      t.origin_value !==
        expected.stacks[0] + expected.stacks[1] + (t.fee_reserve ?? 45000*t.fee_multiplier) + 1000*t.fee_multiplier ||
      JSON.stringify(t.stacks ?? [20000, 20000]) !==
        JSON.stringify(expected.stacks) ||
      (t.button ?? 0) !== expected.button ||
      !!p.rollover !== !!this.data.continuation ||
      JSON.stringify(t.identities) !==
        JSON.stringify(keys.map((k) => k.identity)) ||
      JSON.stringify(t.reveal_keys) !==
        JSON.stringify([keys[1].reveal, keys[0].reveal])
    )
      throw new Error("Table terms do not match the agreed stakes.");
    if (t.fee_reserve !== undefined) {
      let minimum = await this.requiredReserve(t.fee_multiplier,expected.stacks,expected.button);
      if (p.rollover) {
        const previous = await this.previousPlayer();
        const info = await previous.call("rolloverInfo");
        minimum = Math.max(minimum,info.payouts.reduce((a,b)=>a+b,0)-expected.stacks[0]-expected.stacks[1]+330);
      }
      if(t.fee_reserve !== minimum) throw new Error("Funding exceeds the required reserve");
    }
    if (p.buyin) await this.verifyBuyIn(p);
    else if (this.data.buyincoin && !this.data.continuation) throw new Error("Missing agreed buy-in");
    if (p.rollover) {
      const r = p.rollover,
        c = this.data.continuation;
      if (
        r.previous !== c.previous ||
        r.value !== t.origin_value ||
        r.sponsor_script !== p.returnScript ||
        ![Math.ceil(269 * t.fee_multiplier), 1000 * t.fee_multiplier].includes(r.fee) ||
        t.fee_multiplier < c.feeMultiplier ||
        JSON.stringify(r.identities) !== JSON.stringify(t.identities) ||
        hex(await this.wallet.call("rolloverPreview", r)) !== p.funding
      )
        throw new Error(
          "Rollover does not match the settled payouts and next hand.",
        );
    }
    const funding = await this.wallet.call("inspect", {
      bytes: unhex(p.funding),
    });
    if (
      t.origin !== `${funding.txid}:0` ||
      funding.outputs[0].value !== t.origin_value
    )
      throw new Error("Funding transaction does not match the table.");
    if (
      this.data.terms &&
      JSON.stringify(this.data.terms) !== JSON.stringify(t)
    )
      throw new Error("Funded table terms changed.");
    this.data.proposal = p;
    this.data.terms = t;
    await this.player.call("configure", t);
    const configured = await this.player.call("view");
    this.view = configured;
    if (configured.originScript !== funding.outputs[0].script)
      throw new Error("Funding pays the wrong escrow script.");
    await this.save();
    return true;
  }

  async publish(raw) {
    const info = await this.wallet.call("inspect", { bytes: raw });
    const state = await this.chain.transactionStatus(unhex(info.txid));
    if (!["confirmed", "mempool"].includes(state.state))
      await this.chain.publish(raw);
    return info;
  }
  async publishFunding(raw, now=Date.now()) {
    if(now<(this.data.fundingRetryAt??0)) return;
    this.data.fundingIntent=true;
    this.data.fundingAttempts=(this.data.fundingAttempts??0)+1;
    // Persist before the network call: an ambiguous response or reload must
    // not cause the fast table poll to submit the same transaction again.
    this.data.fundingRetryAt=now+Math.min(30000,1000*2**Math.min(this.data.fundingAttempts,5));
    await this.save();
    await this.publish(raw); // Checks mempool/confirmation before broadcasting.
    this.data.fundingRetryAt=now+30000;
    await this.save();
  }
  async remember(raw, fact, label) {
    const info = await this.wallet.call("inspect", { bytes: raw });
    if (!this.data.log.some((t) => t.txid === info.txid))
      this.data.log.push({
        txid: info.txid,
        height: fact.confirmedIn.height,
        label,
        outputs: info.outputs,
      });
    await this.save();
  }
  async afterPoll(operation, busyAction = null) {
    const gameId = this.data.gameId,
      node = this.view?.node;
    this.busy = true;
    this.busyAction = busyAction;
    this.notify();
    try {
      await this.pollTask;
      this.busy = false;
      // A confirmed action may have changed the available choices while waiting.
      if (!this.stopped && this.data.gameId === gameId && this.view?.node === node)
        await operation();
    } finally {
      this.busy = false;
      this.busyAction = null;
      this.notify();
    }
  }
  step() {
    if (this.busy || this.pollTask || this.stopped || this.pollPaused || Date.now()<(this.pollRetryAt??0)) return Promise.resolve();
    this.pollTask = Promise.resolve().then(async () => {
      const end=traceOperation('table.poll',{gameId:this.data?.gameId,sender:this.data?.sender,stage:this.stage},true);
      try {
        if(this.reconnectRequired) {
          // Preparation stops its worker after an interrupted exchange. Retry
          // from its durable checkpoint, rather than repeatedly calling that
          // halted worker while displaying "retrying" forever.
          this.reconnectRequired=false;
          this.player?.close();releaseRelayRoom(this.data);clearInterval(this.timer);
          try {await this.openPlayer();}
          catch(error){this.reconnectRequired=true;throw error;}
          finally {
            if(!this.stopped){clearInterval(this.timer);this.timer=setInterval(()=>void this.step(),100);}
          }
        }
        await this.tick();
        this.error = null;this.pollFailures=0;this.pollRetryAt=0;
      } catch (e) {
        end(e);
        this.pollFailures=(this.pollFailures??0)+1;
        this.pollRetryAt=Date.now()+Math.min(30000,(/429/.test(e.message)?2000:500)*2**Math.min(this.pollFailures,5));
        this.error = e.message;
        if(/^(Relay (connection interrupted|response timed out|worker timed out)|(?:Preparation|Channel commitment|Launch preparation) exchange timed out|Failed to fetch)$/.test(e.message))this.reconnectRequired=true;
        this.pollPaused = !/fetch|network|connection|timed? ?out|timeout|HTTP|Relay [45]/i.test(e.message);
        this.stage = !this.pollPaused
          ? "Connection paused — retrying"
          : this.data.leaveRequested ? "Cashout paused" : "Table paused";
      } finally {
        end();
        this.pollTask = null;
        this.notify();
        // Protocol round trips should not each pay the idle table's polling
        // interval. Keep ordinary waiting-for-action traffic at its usual rate.
        clearTimeout(this.protocolTimer);
        if ((!this.background || this.data.entrySelected) && !this.stopped && !this.error && this.view &&
            (this.view.pendingMove || (!this.view.betting && !this.view.terminal) ||
             (this.view.terminal && this.data.wantsNext && !this.data.sitOutNext)))
          this.protocolTimer = setTimeout(() => void this.step(), 25);
      }
    });
    return this.pollTask;
  }
  async tick() {
    if (this.data.left) {clearInterval(this.timer);return;}
    // Both signatures are already durable. Completing a cashout must not wait
    // for the opponent or a relay room to come back after a disconnect.
    if (this.data.cashout) return this.cashOut();
    if (this.background) return this.tickPredeal();
    await this.flush();
    while (await this.receive()) {}
    if (this.view?.channelReady) this.startPredeal();
    if (this.view?.terminal) return this.continueHand();
    if (!this.keys()) {
      this.stage = "Waiting for your opponent";
      return;
    }
    if (!this.data.proposal && !this.data.peer.proposal) {
      if (!this.data.continuation && this.localWallet) return this.prepareBuyIn();
      if (this.data.sender === "alice" && this.fundingKey && !this.actionError)
        return this.fund(this.fundingKey, { fromPoll: true });
      this.stage =
        this.data.sender === "alice"
          ? "Fund the table"
          : "Waiting for the host to fund the table";
      return;
    }
    if (this.data.sender === "alice" && this.data.proposal)
      await this.send("proposal", this.data.proposal);
    if (!(await this.configure())) {
      this.stage = "Saving the funding return";
      return;
    }
    return this.advanceChannel();
  }
  async advanceChannel() {
    const p = this.data.proposal;
    if (!this.data.prepared) {
      this.stage = "Shuffling together";this.notify();
      const deadline = Date.now()+180000;
      while (true) {
        if(this.stopped) return;
        const state=await this.player.call("deal");
        if(state.accepted && state.peerScore) break;
        if(Date.now()>deadline) throw new Error("Opponent setup timed out");
        await new Promise(resolve=>setTimeout(resolve,25));
      }
      this.progress = {done:0,total:2};
      this.stage="Preparing the full game";this.notify();
      this.data.prepared=await this.player.call("prepare");await this.save();
    }
    const readyKind=this.data.payoutsBound?"boundready":"ready";
    await this.send(readyKind,{binding:this.data.prepared.binding});
    if(!this.data.peer[readyKind]) {this.stage="Waiting for your opponent’s preparation";return;}
    if(this.data.peer[readyKind].binding!==this.data.prepared.binding) throw new Error("Players prepared different games");
    if(this.data.bufferCandidate && !this.data.entrySelected) {
      this.stage="Future hand prepared";clearInterval(this.timer);return;
    }
    // Obtain both enforceable private recovery roots before releasing funding.
    // No unrestricted refund of the unchanged channel funding is pre-signed.
    this.view=await this.player.call("advance",{allowWatch:!!this.data.funded});
    if(!this.view.recoveryReady) {this.stage="Starting the funded hand";return;}
    if(!this.data.funded) {
      if(p.buyin && !this.data.fundingInputsConfirmed) {
        this.stage='Waiting for wallet funding confirmation';
        if(Date.now()<(this.fundingParentsCheckAt??0)) return;
        this.fundingParentsCheckAt=Date.now()+3000;
        if(!await this.checkBuyInCoins(p.buyin,true)) return;
        this.data.fundingInputsConfirmed=true;await this.save();
      }
      if(p.buyin && !this.data.signedFunding) {
        const own=hex(await this.wallet.call("buyinSign",{buyin:p.buyin,secret:Array.from(unhex(this.localWallet.secret)),index:this.data.sender==="alice"?0:1}));
        await this.send("buyinsig",own);
        if(!this.data.peer.buyinsig) return;
        const signatures=this.data.sender==="alice"?[own,this.data.peer.buyinsig]:[this.data.peer.buyinsig,own];
        this.data.signedFunding=hex(await this.wallet.call("buyinFinish",{buyin:p.buyin,signatures}));await this.save();
      }
      if(this.data.signedFunding)this.startPredeal();
      this.stage="Waiting for table funding confirmation";
      if(Date.now()<(this.fundingCheckAt??0)) return;
      this.fundingCheckAt=Date.now()+3000;
      const raw=unhex(this.data.signedFunding??p.funding);
      if(this.data.sender==="alice") await this.publishFunding(raw);
      const info=await this.wallet.call("inspect",{bytes:raw});
      const fact=await this.chain.originFact({outpoint:outpoint(p.terms.origin),valueSat:p.terms.origin_value,scriptPubkey:unhex(info.outputs[0].script),minConfirmations:1});
      if(!fact) return;
      this.data.funded=true;await this.remember(raw,fact,"Channel funded");
      if(this.localWallet) await this.localWallet.refresh();
      this.view=await this.player.call("advance",{allowWatch:true});
    }
    this.data.activated=!!this.view.channelReady;
    if(!this.view.pendingMove) this.data.pendingInfo=null;
    if(this.view.terminal) return this.continueHand();
    if(!this.view.channelReady) {this.stage="Starting the funded hand";return;}
    if(this.data.channelContinuation && !this.data.parentHandoffDone) {this.stage='Next hand ready';return;}
    this.startPredeal();
    if(this.view.pendingMove) {this.stage="Waiting for your opponent";return;}
    if(!this.view.betting && this.view.actor===this.view.role) {await this.submit(null);return;}
    this.stage=this.view.actor===this.view.role?"Your turn":"Opponent’s turn";
  }
  async submit(edge) {
    this.submission=actionSubmission(this.view,edge);this.data.pendingInfo=this.submission;this.notify();
    try {
      this.view=await this.player.call("action",{edge});
      this.stage="Waiting for your opponent";
    } catch(error) {this.data.pendingInfo=null;throw error;}
    finally {this.submission=null;this.notify();}
  }
  async act(edge) {
    if (this.busy || !this.view?.channelReady || this.view.pendingMove) return;
    if (this.pollTask) {
      this.submission = actionSubmission(this.view, edge);
      try {
        return await this.afterPoll(() => this.act(edge));
      } finally {
        this.submission = null;
        this.notify();
      }
    }
    this.busy = true;
    this.error = null;
    this.actionError = null;
    this.notify();
    try {
      await this.submit(edge);
    } catch (e) {
      this.actionError = this.error = e.message;
    } finally {
      this.busy = false;
      this.notify();
    }
  }
  async returnFunds() {
    if (
      this.busy ||
      !this.data.refund ||
      this.data.activated ||
      this.data.sent.activation ||
      this.view?.pending
    )
      return;
    if (this.pollTask) return this.afterPoll(() => this.returnFunds());
    this.busy = true;
    try {
      this.data.returning = true;
      await this.save();
      await this.publish(unhex(this.data.refund));
    } catch (e) {
      this.error = e.message;
    } finally {
      this.busy = false;
      this.notify();
    }
  }
  close() {
    this.handBuffer?.close();
    this.nextSession?.close();
    this.nextSession = null;
    this.fundingKey = null;
    this.stopped = true;
    clearTimeout(this.protocolTimer);
    clearInterval(this.timer);
    this.player?.close();
    if(!this.sharedWallet)this.wallet?.close();
    this.priorPlayer?.close();
    releaseRelayRoom(this.data);
  }
}
