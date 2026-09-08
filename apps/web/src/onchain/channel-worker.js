import {trace,traceOperation} from './diagnostics.js';
import {encodeBinary,decodeBinary,encodeProtocol,decodeProtocol} from './binary-codec.js';
import {preparationBatches,packPreparation,unpackPreparation} from './preparation-wire.js';
import {setRelayPort,relayConnection} from './relay-socket.js';
import { BrowserDefense } from "./browser-defense.js";
import { compactChannelPreparation, canCompactPreparationJournal, warmChannelTransport, receiveChannelMessages as receiveRelayMessages, sendChannelMessages as sendRelayMessages } from "./channel-inbox.js";
import { client, moduleBytes, encode, decode, hex, acquirePlayerLock, Rpc } from "./wasm-client.js";
import { advanceDealerRetry } from './dealer-progress.js';
import { CryptoPool } from "./crypto-pool.js";
import { PreparationCheckpointStore } from "../storage/preparation-checkpoint-store.js";
let engine, wasm, module, seed, room, terms, record, store;
let preparationMetrics, defense, prioritizingEntry=false;
let owner = 0, artifactDirty = true, halted = false, fatalError, releaseLock, cachedView, journalDirty=true;
let constructionJobs=[];
let warmConstruction=[],warmPools=[];
// Reserve only this channel seat. Unrelated tables and the opposite seat must
// remain able to sign while this hand waits for its peer's payout exchange.
const payoutPriority=()=>`poker-payout-cpu/${terms.slot ? hex(terms.slot.channel) : room.gameId}/${room.sender}`;
const workerCount=()=>terms.full ? Math.min(room.speculative && !record.payoutBinding ? 2 : 4,
  Math.max(1,Math.floor(((navigator.hardwareConcurrency||4)-2)/2))) : 1;
function warmPreparationWorkers() {
  // Buffered decks are forked into a different candidate worker. They never
  // construct or sign a tree themselves, so warming pools here only leaks idle
  // workers for the lifetime of every buffered slot.
  if(room.deckOnly || warmConstruction.length || record.prepared)return;
  warmConstruction=[0,1].map(()=>new Rpc(new URL('./construction-worker.js',import.meta.url)));
  warmPools=[0,1].map(()=>new CryptoPool(workerCount()));
}
const publicView=()=>cachedView ??= decode(engine.call(68));
const bytes = value => {
  if(!(value instanceof Uint8Array)) throw new Error('Expected binary channel data');
  return value;
};
const messageBytes = message => ["channel.frame","channel.launches"].includes(message.kind)
  ? encode(decodeProtocol(message.payload)) : bytes(message.payload);
const hash = async value => hex(new Uint8Array(await crypto.subtle.digest("SHA-256",value)));
function setup(op, payload=new Uint8Array(), variant=owner) {
  cachedView=null;
  if([4,5,6,8,9,15,29,53].includes(op)) journalDirty=true;
  const input=new Uint8Array(payload.length+2); input.set([variant,op]);input.set(payload,2);
  const started=performance.now(),result=engine.call(61,input);
  if([4,5,6].includes(op))trace('dealer.step',{gameId:room.gameId,sender:room.sender,
    method:op===4?'sent':op===5?'received':'retry',stage:payload.length>=72?new DataView(payload.buffer,payload.byteOffset).getUint16(70,true):undefined,
    durationMs:Math.round(performance.now()-started)});
  return result;
}
let persistence=Promise.resolve();
function persist() {
  const work=persistence.then(persistSnapshot);
  persistence=work.catch(()=>{});
  return work;
}
async function persistSnapshot() {
  if(halted) throw new Error(fatalError ?? "Storage failed; reload the table before continuing");
  const end=traceOperation('channel.persist',{gameId:room?.gameId,sender:room?.sender},true);
  const started=performance.now();
  try {
    const snapshotsChanged = terms && (artifactDirty || journalDirty || !record.artifact || !record.journal);
    // Capture the journal, metadata and artifact together before yielding.
    // Network delivery can update live cursors while encryption is in flight.
    const next=structuredClone(record),entries=[];
    const artifact=terms && (artifactDirty || !record.artifact) ? engine.call(70) : null;
    const journal=terms && (journalDirty || !record.journal) ? engine.call(69) : null;
    if(artifact)artifactDirty=false;
    if(journal)journalDirty=false;
    if(terms) {
      if(artifact) {
        const digest=await hash(artifact);
        entries.push({id:`${room.gameId}/artifact/${digest}`,binding:room.gameId,plaintext:artifact});
        next.artifact=digest;
      }
      if(journal) {
        const digest=await hash(journal);
        entries.push({id:`${room.gameId}/journal/${digest}`,binding:room.gameId,plaintext:journal});
        next.journal=digest;
      }
    }
    entries.push({id:room.gameId,binding:room.gameId,plaintext:encodeBinary(next)});
    const keep=new Set([`${room.gameId}/artifact/${next.artifact}`,`${room.gameId}/journal/${next.journal}`]);
    const obsolete=snapshotsChanged ? (await store.checkpointIds()).filter(id=>typeof id==='string' && id.startsWith(`${room.gameId}/`) && /\/(artifact|journal)\/[a-f0-9]{64}$/.test(id) && !keep.has(id)) : [];
    await store.saveBatch(entries,obsolete);
    if(terms){record.artifact=next.artifact;record.journal=next.journal;}
  } catch(error) {end(error);halted=true;fatalError=error.message||error.name;throw error;}
  finally {end();if(preparationMetrics) preparationMetrics.persistMs+=performance.now()-started;}
}
async function restore(source=record, id=room.gameId) {
  const journal=await store.load(`${id}/journal/${source.journal}`,id), artifact=await store.load(`${id}/artifact/${source.artifact}`,id);
  if(await hash(journal)!==source.journal) throw new Error("Channel journal integrity mismatch");
  if(await hash(artifact)!==source.artifact) throw new Error("Channel artifact integrity mismatch");
  const input=new Uint8Array(4+journal.length+artifact.length);
  new DataView(input.buffer).setUint32(0,journal.length,true);input.set(journal,4);input.set(artifact,4+journal.length);
  engine.call(71,input);artifactDirty=false;cachedView=null;journalDirty=false;
}
let flushing,preparationTransportError,dealerTransportError;
const regenerablePreparation=message=>/^channel\.(?:payout\.)?[01]\.(inventory|batch|done)$/.test(message.kind);
const loggedSetup=message=>regenerablePreparation(message)||['channel.deal','channel.score'].includes(message.kind);
async function flush() {
  if(flushing)return flushing;
  flushing=(async()=>{
    while(record.outbox.length) {
      const batch=record.outbox.slice(0,32);
      if(!await sendRelayMessages(room,batch))return;
      record.outbox.splice(0,batch.length);
      if(!batch.every(loggedSetup))await persist();
    }
  })();
  try {await flushing;} finally {flushing=null;}
}
async function send(kind,payload) {
  if(["frame","launches"].includes(kind))payload=encodeProtocol(decode(payload));
  record.outbox.push({messageId:hex(crypto.getRandomValues(new Uint8Array(32))),kind:`channel.${kind}`,payload});
  await persist();await flush();
}
let sending=Promise.resolve();
function queueCommitments(variant,payload) {
  for(let offset=0;offset<payload.length;offset+=131072){
    const chunk=new Uint8Array(8+Math.min(131072,payload.length-offset)),v=new DataView(chunk.buffer);
    v.setUint32(0,payload.length,true);v.setUint32(4,offset,true);chunk.set(payload.subarray(offset,offset+131072),8);
    record.outbox.push({messageId:hex(crypto.getRandomValues(new Uint8Array(32))),kind:`channel.${variant}.commitments`,payload:chunk});
  }
}
function acceptCommitmentChunk(owner,payload){
  if(payload.length<9)throw Error('Truncated commitment chunk');
  const v=new DataView(payload.buffer,payload.byteOffset,payload.byteLength),total=v.getUint32(0,true),offset=v.getUint32(4,true);
  if(total>4000000||offset%131072||offset>=total||payload.length!==8+Math.min(131072,total-offset))throw Error('Invalid commitment chunk');
  record.commitmentParts??=[null,null];
  const parts=record.commitmentParts[owner]??={total,chunks:[]};
  if(parts.total!==total)throw Error('Conflicting commitment length');
  const previous=parts.chunks[offset/131072];
  if(previous && hex(previous)!==hex(payload.subarray(8)))throw Error('Conflicting commitment chunk');
  parts.chunks[offset/131072]=payload.slice(8);
  if(Array.from({length:Math.ceil(total/131072)},(_,i)=>parts.chunks[i]).some(c=>!c))return;
  const joined=new Uint8Array(total);parts.chunks.forEach((c,i)=>joined.set(c,i*131072));
  setup(53,joined,owner);record.commitments[owner]=true;record.commitmentParts[owner]=null;
}
async function messages() {return (await receiveRelayMessages(room, record.cursor,{bulk:!!record.bulkTransport,payout:!!record.payoutBinding})).messages;}
const retryDealer=()=>advanceDealerRetry(setup,persist,[0]);
function deliverDealer() {
  if(!flushing)void flush().catch(error=>{dealerTransportError=error;});
}
async function deal() {
  if(record.prepared || record.preparationCursors.some(n=>n!==null)) return {accepted:true,peerScore:true};
  if(dealerTransportError) {const error=dealerTransportError;dealerTransportError=null;throw error;}
  // Outgoing frames are already durable. Consume a peer's next frame as soon
  // as it arrives rather than waiting for the relay's upload response.
  deliverDealer();
  await retryDealer();
  for(const message of await messages()) {
    if(message.sender!==room.sender && message.kind.startsWith("channel.")) {
      const payload=messageBytes(message);
      if(message.kind==="channel.deal") {
        // A page can contain the previous attempt's final frame followed by
        // the peer's first retry frame. Persist the retry before consuming it.
        await retryDealer();
        setup(5,payload,0);
      }
      else if(message.kind==="channel.score") {
        if(!record.dealerShared) {engine.call(103);record.dealerShared=true;journalDirty=true;}
        if(record.predealing) record.deferredScore=payload;
        else {for(let i=0;i<2;i++) setup(9,payload,i);record.peerScore=true;}
      }
      else record.deferred.push(message);
    }
    record.cursor=message.cursor;
  }
  let state=decode(setup(7));
  if(state.retry) await retryDealer();
  if(!state.accepted) {
    const outgoing=setup(3);
    if(outgoing.length) {
      record.pendingDealer=outgoing;
      record.outbox.push({messageId:hex(crypto.getRandomValues(new Uint8Array(32))),kind:"channel.deal",payload:outgoing});
      await persist();setup(4,outgoing,0);delete record.pendingDealer;
      await persist();deliverDealer();
    }
  }
  state=decode(setup(7));
  if(state.accepted && !record.dealerShared) {
    engine.call(103);record.dealerShared=true;journalDirty=true;await persist();
  }
  if(state.accepted && !record.predealing && !record.scoreSent) {
    const score=setup(8);
    if(hex(score)!==hex(setup(8,new Uint8Array(),1))) throw new Error("Owner score contexts differ");
    record.scoreSent=true;await send("score",score);
  }
  await persist();
  return {...state,peerScore:record.peerScore};
}
async function prepare() {
  if(record.prepared) return record.prepared;
  const started=performance.now();
  preparationMetrics={persistMs:0};
  record.bulkTransport=true;
  const constructionWorkers=warmConstruction;warmConstruction=[];
  const preparedPools=warmPools;warmPools=[];
  constructionJobs=[];
  try {
  postMessage({event:"progress",phase:"preparing",done:0,total:2});
  // Exchange both independent commitment sets in one flight. Start each
  // construction as soon as its own set is complete, without waiting for the other.
  for(let i=0;i<2;i++) if(!record.commitments[i]) queueCommitments(i,setup(52,new Uint8Array(),i));
  await persist();
  const commitmentsDelivery=flush();commitmentsDelivery.catch(()=>{});
  const startConstruction=i=>{
    if(record.preparations[i] || record.payoutBinding || constructionJobs[i])return;
    const worker=constructionWorkers[i]??=new Rpc(new URL('./construction-worker.js',import.meta.url));
    const job=worker.call('construct',{module,job:setup(39,new Uint8Array(),i)}).finally(()=>worker.close());
    job.catch(()=>{});constructionJobs[i]=job;
  };
  for(let i=0;i<2;i++)if(record.commitments[i])startConstruction(i);
  const commitmentDeadline=Date.now()+180000;
  while(record.commitments.some(c=>!c)) {
    const page=[...record.deferred,...await messages()];record.deferred=[];
    for(const message of page) {
      if(message.sender!==room.sender) {
        const match=/^channel\.([01])\.commitments$/.exec(message.kind);
        if(match) {const i=Number(match[1]);acceptCommitmentChunk(i,messageBytes(message));if(record.commitments[i])startConstruction(i);}
        else record.deferred.push(message);
      }
      record.cursor=Math.max(record.cursor,message.cursor);
    }
    await persist();
    if(Date.now()>commitmentDeadline)throw new Error('Channel commitment exchange timed out');
    if(record.commitments.some(c=>!c))await new Promise(r=>setTimeout(r,10));
  }
  await commitmentsDelivery;
  // Both owner variants share one bounded CPU budget. No mutable owner global
  // participates in signing or message routing after commitment construction.
  owner=0;
  const contexts = [null, null];
  // Reserve capacity for the table UI and its background deal; cap private
  // inventory copies at eight workers per player on larger machines.
  const workersPerOwner = workerCount();
  const pools = [];
  const signingTasks = [];
  let failure;
  try {
    for(let i=0;i<2;i++) if(!record.preparations[i]) {
      record.preparationCursors[i] ??= record.cursor;
    }
    const cursors=record.preparationCursors.filter(n=>n!==null);
    if(cursors.length) record.cursor=Math.min(record.cursor,...cursors);
    await persist();
    await Promise.all([0,1].map(async i=>{
      if(record.preparations[i]) return;
      const constructed=record.payoutBinding ? {constructionMs:0,phases:{}} : await constructionJobs[i];
      const call=(op,bytes=new Uint8Array())=>setup(op,bytes,i);
      if(!record.payoutBinding) call(37,constructed.receipt);
      const inventory=call(11), material=decode(call(12));
      const localPool=preparedPools[i]??new CryptoPool(workersPerOwner);pools.push(localPool);
      const initStart=performance.now();
      const localManifest=await localPool.initialize({module,priority:payoutPriority(),speculative:!!room.speculative&&!record.payoutBinding,context:{inventory,key:Array.from(call(13)),material,regtest:terms.regtest}});
      const info={binding:await hash(inventory),requests:localManifest.length/2};
      const context={call,pool:localPool,info,manifest:localManifest,jobs:preparationBatches(localManifest,material.role,decode(call(38))),
        peerJobs:preparationBatches(localManifest,1-material.role,decode(call(38))),
        matched:false,ownDone:false,peerDone:false,received:0,signed:0,dealAttempt:decode(call(7)).attempt,
        constructionMs:constructed.constructionMs,constructionPhases:constructed.phases,
        cryptoInitializationMs:performance.now()-initStart};
      contexts[i]=context;
      await sendPrepared(i,'inventory',encode(info));
      const task=(async()=>{
        let next=0;
        await Promise.all(Array.from({length:workersPerOwner},async()=>{
          while(next<context.jobs.length) {
            const batchId=next++,list=context.jobs[batchId],indices=new Uint8Array(list.length*4),v=new DataView(indices.buffer);
            list.forEach((n,j)=>v.setUint32(j*4,n,true));
            const receipt=await localPool.run('signReceipt',indices,true);
            call(14,receipt);
            await sendPrepared(i,'batch',packPreparation(receipt.subarray(0,receipt.length-32),list,context.manifest,batchId));
            context.signed++;
            postMessage({event:'progress',phase:'signing',done:contexts.reduce((n,c)=>n+(c?0.9*c.signed/c.jobs.length:0),0),total:2});
          }
        }));
        await sendPrepared(i,'done',encode(info));context.ownDone=true;
      })().catch(error=>{failure=error;});
      signingTasks.push(task);
    }));
    const deadline=performance.now()+180000;
    while(contexts.some(c=>c && (!c.ownDone || !c.peerDone))) {
      if(failure || preparationTransportError) throw failure ?? preparationTransportError;
      if(performance.now()>deadline) throw new Error('Preparation exchange timed out');
      const page=[...record.deferred,...await messages()];record.deferred=[];
      const receipts=[];
      for(const message of page) {
        if(message.sender===room.sender || !message.kind.startsWith('channel.')) continue;
        const match=(record.payoutBinding ? /^channel\.payout\.([01])\.(.+)$/ : /^channel\.([01])\.(.+)$/).exec(message.kind);
        if(!match) {record.deferred.push(message);continue;}
        const i=Number(match[1]),kind=match[2],c=contexts[i];
        if(!c) continue; // This owner was durably completed before a restart.
        const payload=messageBytes(message);
        if(kind==='inventory') {
          if(decode(payload).binding!==c.info.binding) throw new Error('Inventory disagreement');
          c.matched=true;
        } else if(kind==='batch') {
          if(!c.matched) throw new Error('Batch before inventory binding');
          receipts.push(c.pool.run('verify',unpackPreparation(payload,c.peerJobs,c.manifest),true).then(receipt=>c.call(14,receipt)));c.received++;
        } else if(kind==='done') {
          if(!c.matched || decode(payload).binding!==c.info.binding) throw new Error('Completion binding mismatch');
          c.peerDone=true;
        } else if(kind!=='commitments') throw new Error(`Unexpected preparation frame ${message.kind}`);
      }
      await Promise.all(receipts);
      for(const message of page) record.cursor=Math.max(record.cursor,message.cursor);
      if(!receipts.length) await new Promise(resolve=>setTimeout(resolve,10));
    }
    await Promise.all(signingTasks);
    if(failure) throw failure;
    for(let i=0;i<2;i++) {
      const c=contexts[i];if(!c) continue;
      c.call(15);
      record.preparations[i]={...c.info,dealAttempt:c.dealAttempt,constructionMs:c.constructionMs,constructionPhases:c.constructionPhases,
        cryptoInitializationMs:c.cryptoInitializationMs,received:c.received,workers:workersPerOwner};
    }
    artifactDirty=true;
    if(!record.deferredPayouts) {
    if(!record.launchesSent) {record.launchesSent=true;await send('launches',engine.call(99));}
    const launchDeadline=Date.now()+180000;
    while(!record.peerLaunches) {
      const page=[...record.deferred,...await messages()];record.deferred=[];
      for(const message of page) {
        if(message.sender!==room.sender && message.kind==='channel.launches') {
          engine.call(100,messageBytes(message));journalDirty=true;record.peerLaunches=true;
        } else if(message.sender!==room.sender && message.kind==='channel.frame') record.deferred.push(message);
        record.cursor=Math.max(record.cursor,message.cursor);
      }
      await persist();
      if(Date.now()>launchDeadline) throw new Error('Launch preparation exchange timed out');
      if(!record.peerLaunches) await new Promise(resolve=>setTimeout(resolve,10));
    }
    }
    record.prepared={partial:!!record.deferredPayouts,binding:record.preparations.map(p=>p.binding).join(':'),owners:record.preparations};
    await persist();
    if(record.deferredPayouts)void warmChannelTransport(room,{payout:true}).catch(()=>{});
    record.prepared.elapsedMs=performance.now()-started;
    record.prepared.metrics={...preparationMetrics};preparationMetrics=null;
    await persist();
    return record.prepared;
  } finally {for(const p of pools) p.close();}
  } finally {for(const worker of constructionWorkers) worker?.close();for(const pool of preparedPools)pool.close();constructionJobs=[];}
}
function sendPrepared(variant,kind,payload) {
  const work=sending.then(async()=>{
    record.outbox.push({messageId:hex(crypto.getRandomValues(new Uint8Array(32))),kind:`channel.${record.payoutBinding?'payout.':''}${variant}.${kind}`,payload});
    // The relay inbox durably saves these exact bytes before upload. Partial
    // preparation is deterministically regenerated after a crash; copying the
    // growing outbox into the channel checkpoint again adds no recovery data.
    // Entry, launch, move and retirement frames still use persist-before-send.
    const delivery=flush();delivery.catch(error=>{preparationTransportError=error;});
    // Let CPU workers sign the next batch while the previous one is in flight.
    if(record.outbox.length>=32)await delivery;
  });
  sending=work.catch(()=>{});return work;
}

async function watch() {
  await persist();
  const payload=engine.call(65), digest=hex(engine.call(66));
  const receipt=await defense.register(room.gameId,payload,digest);
  if(receipt.closing) {record.closing=true;await persist();throw new Error("Channel is closing on chain");}
  cachedView=null;journalDirty=true;
  const frame=decode(engine.call(67,Uint8Array.from(digest.match(/../g),h=>parseInt(h,16))));
  if(frame) await send("frame",encode(frame));else await persist();
}
async function advancedView() {
  const view=publicView();
  if(!record.preparationCompacted && view.channelReady) {
    await compactChannelPreparation(room);
    record.preparationCompacted=true;await persist();
  }
  // Keep future uploads paused through entry, old-hand retirement and hole-card
  // exchange, not merely until the payout signatures are ready.
  if(prioritizingEntry && (view.terminal || view.betting && !view.pendingMove)) {
    await relayConnection.prioritizePayout(room,false);prioritizingEntry=false;
  }
  return view;
}
async function advance({allowWatch=true}={}) {
  if(record.closing) throw new Error("Channel is closing on chain");
  await flush();
  if(!record.entrySent) {record.entrySent=true;await send("frame",engine.call(62));}
  const messagesToAccept=[...record.deferred,...await messages()];record.deferred=[];
  if(!messagesToAccept.length && !decode(engine.call(73))) return advancedView();
  for(const message of messagesToAccept) {
    if(message.sender!==room.sender && message.kind==="channel.cashout") {
      if(!record.cashoutStarted) record.deferred.push(message);
      else {engine.call(77,messageBytes(message));cachedView=null;journalDirty=true;}
      record.cursor=Math.max(record.cursor,message.cursor);
    } else if(message.sender!==room.sender && message.kind==="channel.frame") {
      const payload=messageBytes(message),frame=decode(payload);
      // The peer can finish retiring the parent before our acknowledgement
      // arrives. Save its early play frames, but keep processing Entry/Ready;
      // the parent still needs those to complete the local handover.
      if(!publicView().playAllowed && (Object.hasOwn(frame,"Move") || Object.hasOwn(frame,"Ack"))) {
        record.deferred.push(message);
        if(message.cursor>record.cursor)trace('channel.frame.deferred',{gameId:room.gameId,sender:room.sender,reason:'parent handover pending'});
        record.cursor=Math.max(record.cursor,message.cursor);
        continue;
      }
      cachedView=null;journalDirty=true;
      const response=decode(engine.call(63,payload));
      record.cursor=Math.max(record.cursor,message.cursor);
      await persist();
      if(response) await send("frame",encode(response));
      if(allowWatch && decode(engine.call(73))) await watch();
    } else record.cursor=Math.max(record.cursor,message.cursor);
  }
  if(allowWatch && decode(engine.call(73))) await watch();
  await persist();
  return advancedView();
}
async function command(method,args) {
  if(halted) throw new Error(fatalError ?? "Storage failed; reload the table before continuing");
  switch(method) {
    case "init": {
      if(args.relayPort) {setRelayPort(args.relayPort);delete args.relayPort;}
      room=args;void warmChannelTransport(room).catch(()=>{});store=new PreparationCheckpointStore(`poker-channel-player-${room.sender}`);
      defense=new BrowserDefense(room.config,store);
      releaseLock = await acquirePlayerLock(`poker-channel/${room.gameId}/${room.sender}`);
      // Clean abandoned snapshots from inactive hands as well as this seat.
      for (const id of await store.checkpointIds()) {
        if (typeof id !== "string" || !/^[a-f0-9]{64}$/.test(id)) continue;
        const clean=async()=>{
          await store.pruneSnapshots(id);
          const saved=decodeBinary(await store.load(id,id));
          if(saved.journal && !saved.preparationCompacted) {
            const journal=await store.load(`${id}/journal/${saved.journal}`,id);
            if(await hash(journal)===saved.journal && canCompactPreparationJournal(journal)) {
              await compactChannelPreparation({gameId:id,sender:room.sender});
              saved.preparationCompacted=true;await store.save(id,id,encodeBinary(saved));
            }
          }
        };
        if (id === room.gameId) await clean();
        else await navigator.locks.request(`poker-channel/${id}/${room.sender}`, {ifAvailable:true}, async lock => {
          if (lock) { try { await clean(); } catch { /* Preserve unreadable recovery records. */ } }
        });
      }
      const existing=await store.read("checkpoints",room.gameId);
      if(existing) record=decodeBinary(await store.load(room.gameId,room.gameId));
      const compiled=room.engine ?? await (async()=>{
        const raw=await moduleBytes();return {module:await WebAssembly.compile(raw),digest:await hash(raw)};
      })();
      delete room.engine;
      const digest=compiled.digest;
      if(record?.moduleHash && record.moduleHash!==digest) throw new Error("Start a new table after rebuilding the channel engine");
      module=compiled.module;engine=await client(module);wasm={call:setup};
      if(record) {
        seed=bytes(record.seed);terms=record.terms;
        if(terms) await restore();
        if(record.pendingDealer) {setup(4,bytes(record.pendingDealer),0);delete record.pendingDealer;await persist();}
        if(record.prepared && publicView().entryAllowed) {
          const receipt=await defense.register(room.gameId,engine.call(65),hex(engine.call(66)));
          if(receipt.closing && !publicView().cashoutStarted) {
            record.closing=true;throw new Error("Saved channel state is closing");
          }
        }
      } else {
        seed=room.previousGameId ? bytes(decodeBinary(await store.load(room.previousGameId,room.previousGameId)).seed) : crypto.getRandomValues(new Uint8Array(32));
        record={moduleHash:digest,seed,outbox:[],cursor:0,deferred:[],preparations:[null,null],preparationCursors:[null,null],commitments:[false,false]};
      }
      if(!existing && room.dealGameId) {
        const source=decodeBinary(await store.load(room.dealGameId,room.dealGameId));
        await restore(source,room.dealGameId);
        engine.call(97,encode(source.terms));
        engine.call(98,encode(room.candidateTerms));
        terms=room.candidateTerms;record.terms=terms;
        if(room.deferredPayouts) {engine.call(101);record.deferredPayouts=true;}
        artifactDirty=true;journalDirty=true;cachedView=null;
      }
      if(record.payoutBinding && !publicView().betting && !publicView().terminal) {
        await relayConnection.prioritizePayout(room,true);prioritizingEntry=true;
      }
      await persist();return {keys:decode(engine.call(2,seed)),engineHash:digest,resumed:!!existing,prepared:record.prepared};
    }
    case "configurePredeal":
      if(terms) return;
      engine.call(60,encode({seed:Array.from(seed),terms:args,contest_blocks:6}));
      record.predealing=true;
      terms=args;record.terms=args;cachedView=null;journalDirty=true;
      warmPreparationWorkers();
      await persist();return;
    case "configure":
      if(record.predealing) {
        for(let i=0;i<2;i++) setup(29,encode(args),i);
        terms=args;record.terms=args;record.predealing=false;
        if(record.deferredScore) {for(let i=0;i<2;i++) setup(9,bytes(record.deferredScore),i);delete record.deferredScore;record.peerScore=true;}
        await persist();return;
      }
      if(terms) {if(JSON.stringify(terms)!==JSON.stringify(args)) throw new Error("Channel terms changed");return;}
      terms=args;record.terms=args;cachedView=null;journalDirty=true;engine.call(60,encode({seed:Array.from(seed),terms,contest_blocks:6}));await persist();return;
    case "deal": return deal();
    case "futureTerms": return decode(engine.call(90,encode(args)));
    case "bindPayouts": return navigator.locks.request(payoutPriority(),async()=>{
      // Finish this candidate's last internal frames before pausing bulk lanes.
      await flush();
      await relayConnection.prioritizePayout(room,true);
      prioritizingEntry=true;
      try {
      if(record.payoutBinding && JSON.stringify(record.terms.stacks)!==JSON.stringify(args.stacks)) throw new Error('Payout balances already bound');
      if(!record.payoutBinding) {
        const reused=decode(engine.call(102,encode(args.stacks)));
        terms={...terms,stacks:args.stacks};record.terms=terms;
        record.payoutBinding=true;record.deferredPayouts=false;record.reusedAuthorizations=reused;
        record.prepared=null;record.preparations=[null,null];record.preparationCursors=[null,null];
        artifactDirty=true;journalDirty=true;cachedView=null;await persist();
      }
      return await prepare();
      } catch(error) {
        await relayConnection.prioritizePayout(room,false);prioritizingEntry=false;throw error;
      }
    });
    case "outcomes": return decode(engine.call(96));
    case "preparedCertificate": await persist();return engine.call(91);
    case "selectCandidate": {
      const view=publicView(),id=`frontier/${hex(view.slot.channel)}`;
      return navigator.locks.request(`${store.name}/${id}`,async()=>{
        const old=await store.read('checkpoints',id)?decode(await store.load(id,id)):{index:0};
        if(old.index!==view.slot.index) throw new Error('Stale channel activation');
        const certificate=engine.call(92,args.certificate);
        const digest=await hash(certificate);
        if(old.selected && old.selected!==digest) throw new Error('Conflicting channel selection');
        journalDirty=true;cachedView=null;await persist();
        await store.save(id,id,encode({...old,selected:digest}));return certificate;
      });
    }
    case "authorizeEntry": {
      const view=publicView(),id=`frontier/${hex(view.slot.channel)}`;
      const frontier=decode(await store.load(id,id));
      if(frontier.index+1!==view.slot.index || frontier.selected!==await hash(args.certificate)) throw new Error('Candidate outside activation frontier');
      engine.call(93,args.certificate);journalDirty=true;cachedView=null;await persist();return publicView();
    }
    case "playCertificate": return engine.call(94);
    case "authorizePlay": {
      const view=publicView(),id=`frontier/${hex(view.slot.channel)}`;
      return navigator.locks.request(`${store.name}/${id}`,async()=>{
        const frontier=decode(await store.load(id,id));
        if(frontier.index!==view.slot.index-1 && frontier.index!==view.slot.index) throw new Error('Stale play activation');
        engine.call(95,args.certificate);journalDirty=true;cachedView=null;await persist();
        await store.save(id,id,encode({index:view.slot.index,hand:view.hand}));return publicView();
      });
    }
    case "prepare":
      try {return await prepare();} catch(error) {fatalError=error.message;halted=true;throw error;}
    case "view": return publicView();
    case "history": return [];
    case "reload": await restore();return publicView();
    case "advance": return advance(args);
    case "cashout": {
      const signature=engine.call(76,encode(args.scripts));
      if(!record.cashoutStarted) {
        cachedView=null;journalDirty=true;record.cashoutStarted=true;await send("cashout",signature);
      }
      return advance({allowWatch:false});
    }
    case "successorCertificate": await persist();return engine.call(74);
    case "handoff":
      if(!record.handoffStarted) {
        const frame=engine.call(75,args.certificate);
        cachedView=null;journalDirty=true;record.handoffStarted=true;
        await send("frame",frame);
      }
      return advance();
    case "action":
      cachedView=null;journalDirty=true;engine.call(64,encode(args.edge ?? null));await persist();await watch();return publicView();
    default: throw new Error(`Unsupported channel command: ${method}`);
  }
}
let serial=Promise.resolve();
self.onmessage=({data:{id,method,args}})=>{serial=serial.then(async()=>{
  try {postMessage({id,value:await command(method,args)});} catch(error) {postMessage({id,error:error?.message || String(error) || `Channel ${method} failed`});}
});};
