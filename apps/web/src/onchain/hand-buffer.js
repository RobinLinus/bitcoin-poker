import {discardChannelInbox} from './channel-inbox.js';
import {traceState} from './diagnostics.js';
import {decodeBinary,encodeBinary,encodeProtocol} from './binary-codec.js';
import {PreparationCheckpointStore} from '../storage/preparation-checkpoint-store.js';
import {TableSession,tableStorage,tableApi} from './table-session.js';
import {encode,decode,hex,unhex} from './wasm-client.js';
const random=()=>hex(crypto.getRandomValues(new Uint8Array(32)));
const hash=async value=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',encode(value))));
const pairKey=pair=>pair.join(':');
const retrying=child=>!!child.error && child.pollPaused===false;
export function validateBufferPlan(plan,index) {
  if(!Array.isArray(plan.slots)||plan.slots.length>3||!Array.isArray(plan.jobs)||plan.jobs.length>8) throw new Error('Invalid hand buffer plan');
  const ids=new Set();
  for(const slot of plan.slots) {
    if(!Number.isSafeInteger(slot.index)||slot.index<=index||slot.index>index+3||ids.has(slot.index)||
      !/^[a-f0-9]{64}$/.test(slot.gameId)||!/^[a-f0-9]{64}$/.test(slot.inviteSecret)) throw new Error('Invalid future slot');
    ids.add(slot.index);
  }
  const jobs=new Set(),jobIds=new Set();
  for(const job of plan.jobs) {
    const key=`${job.index}/${pairKey(job.stacks??[])}`;
    if(!/^[a-f0-9]{64}$/.test(job.id)||jobIds.has(job.id)||!ids.has(job.index)||!Array.isArray(job.stacks)||job.stacks.length!==2||job.stacks.some(n=>!Number.isSafeInteger(n)||n<200)||typeof job.deferredPayouts!=="boolean"||jobs.has(key)) throw new Error('Invalid future candidate');
    jobs.add(key);jobIds.add(job.id);
  }
  if(plan.active!=null && !jobIds.has(plan.active)) throw new Error('Invalid active candidate');
}

// Read only the authenticated journal header for conservative garbage collection.
// Any entry authorization, recovery root, or unknown format preserves the record.
export function isUnactivatedJournal(bytes) {
  if(new TextDecoder().decode(bytes.subarray(0,8))!=='CHJOUR01' || bytes.length<12) return false;
  const size=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint32(8,true);
  if(size>bytes.length-12) return false;
  try {
    const j=decode(bytes.subarray(12,12+size));
    return j.version===1 && j.entry_authorization===null && j.play_authorization===null &&
      j.selection===null && j.root===null && j.handoff===null && j.cashout===null &&
      j.entered===false && j.closing===false && j.pending===null && Array.isArray(j.accepted) && j.accepted.length===0;
  } catch {return false;}
}
async function discardFuture(gameId,sender) {
  return navigator.locks.request(`poker-channel/${gameId}/${sender}`,{ifAvailable:true},async lock=>{
    if(!lock) return false;
    const store=new PreparationCheckpointStore(`poker-channel-player-${sender}`);
    if(await store.read('checkpoints',gameId)) {
      const record=decodeBinary(await store.load(gameId,gameId));
      if(!record.terms?.slot?.index || !record.journal) return false;
      const journal=await store.load(`${gameId}/journal/${record.journal}`,gameId);
      if(hex(new Uint8Array(await crypto.subtle.digest('SHA-256',journal)))!==record.journal || !isUnactivatedJournal(journal)) return false;
      await store.deleteCheckpoints((await store.checkpointIds()).filter(id=>id===gameId || typeof id==='string' && id.startsWith(`${gameId}/`)));
    }
    await navigator.locks.request(`relay-inbox/${gameId}/${sender}`,async()=>{
      const inbox=new PreparationCheckpointStore(`poker-relay-inbox-${sender}`);
      await inbox.deleteCheckpoints((await inbox.checkpointIds()).filter(id=>typeof id==='string' && id.startsWith(`${gameId}/`)));
    });
    await discardChannelInbox({gameId,sender});
    await tableStorage.deleteCheckpoints([`${gameId}-${sender}`]);
    return true;
  });
}

// Closed tables cannot activate any of their unused candidates. Keep all
// funded/selected journals and wallet records; discardFuture verifies each one.
export async function cleanupClosedBuffers() {
  for(const id of await tableStorage.checkpointIds()) {
    if(typeof id!=='string' || !/^[a-f0-9]{64}-(alice|bob)$/.test(id))continue;
    try {
      const data=decodeBinary(await tableStorage.load(id,'table-v1'));
      if(!data.left || !data.cashoutTxid || !data.buffer)continue;
      if(await discardBuffer(data.buffer,data.sender)) {
        delete data.buffer;await tableStorage.save(id,'table-v1',encodeBinary(data));
      }
    } catch(error) {traceState(`storage-cleanup/${id}`,'storage.cleanup.error',{error:error.message||error.name});}
  }
}
async function discardBuffer(buffer,sender) {
  const ids=new Set([...(buffer.slots??[]).map(s=>s.gameId),...(buffer.jobs??[]).map(j=>j.id),...(buffer.garbage??[])]);
  let complete=true;
  for(const id of ids)if(!await discardFuture(id,sender))complete=false;
  return complete;
}

// One preparation job at a time per seat, never one signing pool per candidate.
// Completed candidates remain private and cannot enter until the parent selects one.
export class HandBuffer {
  constructor(table) {this.table=table;this.sessions=new Map();this.closed=false;this.task=null;}
  pump() {
    if(this.closed||this.task) return;
    this.task=this.run().then(()=>{this.error=null;}).catch(error=>{if(this.closed) return;traceState(`buffer-error/${this.table.data.gameId}/${this.table.data.sender}`,'buffer.error',{gameId:this.table.data.gameId,sender:this.table.data.sender,error:error.message});this.error=error.message;})
      .finally(()=>{this.task=null;});
  }
  async announce() {
    const t=this.table,s=t.data.buffer;
    const payload=t.data.sender==='alice'?{slots:s.slots,jobs:s.jobs,active:s.active,done:s.done}:{done:s.done};
    const fingerprint=JSON.stringify([t.data.gameId,payload]);
    if(this.announced===fingerprint) return;
    traceState(`buffer/${t.data.gameId}/${t.data.sender}`,'buffer.state',{gameId:t.data.gameId,sender:t.data.sender,slots:s.slots.length,queued:s.jobs.length,ready:s.done.length,active:s.active??''});
    s.revision=(s.revision??0)+1;await t.save();
    const bytes=encodeProtocol({...payload,revision:s.revision});
    t.data.outbox.push({messageId:random(),kind:'table.buffer',payload:bytes});
    await t.save();await t.flush();this.announced=fingerprint;
  }
  async run() {
    const t=this.table,index=t.view?.slot?.index;
    if(index===undefined||!t.view?.channelReady && !t.view?.terminal && !(t.view?.recoveryReady && t.data.signedFunding)||t.data.leaveRequested||t.data.peer.leave) return;
    if(Date.now()>(this.capacityAt??0)) {
      const estimate=await navigator.storage?.estimate?.().catch(()=>null);
      this.storageLimited=!!(estimate?.quota && estimate.quota-(estimate.usage??0)<256*1024*1024);
      this.capacityAt=Date.now()+5000;
    }
    const nearestOnly=this.storageLimited || t.view.terminal || (t.view.channelReady && t.view.betting===false);
    const s=t.data.buffer??={slots:[],jobs:[],done:[],revision:0,seedGameId:t.data.gameId};
    const previousIds=[...s.slots.map(x=>x.gameId),...s.jobs.map(x=>x.id)];
    if(t.data.sender==='alice') {
      s.slots=s.slots.filter(slot=>slot.index>index);
      s.jobs=s.jobs.filter(job=>job.index>index);
      for(let next=index+1;next<=index+3;next++) if(!s.slots.some(slot=>slot.index===next))
        s.slots.push({index:next,gameId:random(),inviteSecret:random()});
      const stacks=t.data.terms.stacks??[20000,20000],total=stacks[0]+stacks[1];
      const canonical=[Math.floor(total/2),total-Math.floor(total/2)];
      // One reusable internal tree per future hand. Exact short-stack trees are
      // created only when selected, because their betting topology is different.
      if(canonical.every(n=>n>4800)) for(const slot of s.slots) {
        if(!s.jobs.some(j=>j.index===slot.index && j.deferredPayouts)) await this.addJob(slot.index,canonical,true);
      }
      if(this.required && !this.required.every(n=>n>4800)
          && !s.jobs.some(j=>j.index===index+1 && !j.deferredPayouts && pairKey(j.stacks)===pairKey(this.required)))
        await this.addJob(index+1,this.required,false);
      if(!s.jobs.some(j=>j.id===s.active) || s.done.includes(s.active) && t.data.peer.buffer?.done?.includes(s.active)) {
        s.active=s.jobs.find(j=>!s.done.includes(j.id) && this.required && j.index===index+1 && (j.deferredPayouts ? this.required.every(n=>n>4800) : pairKey(j.stacks)===pairKey(this.required)))?.id
          ??s.jobs.find(j=>!s.done.includes(j.id))?.id??null;
      }
    } else {
      const plan=t.data.peer.buffer;
      if(!plan?.slots) return;
      // An old announcement can remain in flight while both seats adopt a hand.
      if(plan.slots.some(slot=>slot.index<=index)) return;
      validateBufferPlan(plan,index);
      for(const job of plan.jobs) {
        const slot=plan.slots.find(s=>s.index===job.index);
        if(job.id!==await hash(['channel-candidate',slot.gameId,job.stacks])) throw new Error('Candidate identity mismatch');
      }
      s.slots=plan.slots;s.jobs=plan.jobs;s.active=plan.active;
    }
    const currentIds=new Set([...s.slots.map(x=>x.gameId),...s.jobs.map(x=>x.id)]);
    s.garbage=[...new Set([...(s.garbage??[]),...previousIds.filter(id=>!currentIds.has(id))])];
    s.done=s.done.filter(id=>s.jobs.some(j=>j.id===id));
    // Reclaim obsolete slots before allocating their replacements, including
    // when the next preparation fails or is still waiting for its peer.
    await this.evict();
    await this.announce();
    for(const slot of s.slots) {
      if(this.closed) return;
      if(nearestOnly && slot.index>index+1)continue;
      if(!this.sessions.has(slot.gameId)) {
        const terms=await t.player.call('futureTerms',{index:slot.index,anchor:Array.from(unhex(slot.gameId)),stacks:t.data.terms.stacks??[20000,20000]});
        await this.open(slot.gameId,slot.inviteSecret,terms,{bufferSlot:true});
      }
    }
    const job=s.jobs.find(j=>j.id===s.active && !s.done.includes(j.id));
    if(!job) {await this.evict();return;}
    if(nearestOnly && job.index>index+1)return;
    const slot=s.slots.find(slot=>slot.index===job.index),deck=this.sessions.get(slot.gameId);
    if(retrying(deck))return;
    if(deck.error) throw new Error(deck.error);
    if(!deck.data.deckReady) return;
    const terms=await t.player.call('futureTerms',{index:job.index,anchor:Array.from(unhex(slot.gameId)),stacks:job.stacks});
    const candidate=await this.open(job.id,await hash(['candidate-invite',slot.inviteSecret,job.id]),terms,{bufferCandidate:true,deferredPayouts:!!job.deferredPayouts,dealGameId:slot.gameId});
    // open() starts its own serial polling loop. Do not occupy the table poll.
    if(retrying(candidate))return;
    if(candidate.error) throw new Error(candidate.error);
    if(candidate.data.prepared && candidate.data.peer.ready) {
      if(!s.done.includes(job.id)) s.done.push(job.id);
      await candidate.save();await this.announce();await this.evict();
    }
  }
  async addJob(index,stacks,deferredPayouts=false) {
    const slot=this.table.data.buffer.slots.find(s=>s.index===index);
    const id=await hash(['channel-candidate',slot.gameId,stacks]);
    this.table.data.buffer.jobs.push({index,stacks,id,deferredPayouts});
  }
  async open(gameId,inviteSecret,terms,flags) {
    if(this.closed) throw new Error('Hand buffer closed');
    if(this.sessions.has(gameId)) return this.sessions.get(gameId);
    const t=this.table,id=`${gameId}-${t.data.sender}`;
    const child=new TableSession(t.config,()=>{});child.background=true;child.chain=t.chain;
    if(await tableStorage.read('checkpoints',id)) child.data=decodeBinary(await tableStorage.load(id,'table-v1'));
    else {
      const playerToken=random();
      if(t.data.sender==='alice') await tableApi('/games',{gameId,inviteSecret,playerToken});
      else await tableApi(`/games/${gameId}/join`,{inviteSecret,playerToken});
      child.data={...flags,protocol:'channel-v1',gameId,inviteSecret,playerToken,sender:t.data.sender,
        playerName:t.data.playerName,opponentName:t.data.peer.profile?.name??t.data.opponentName,
        previous:{gameId:t.data.buffer.seedGameId,sender:t.data.sender},terms,
        proposal:flags.bufferCandidate?{terms}:null,funded:!!flags.bufferCandidate,
        channelContinuation:!!flags.bufferCandidate,handNumber:terms.slot.index+1,
        cursor:0,peer:{},sent:{},outbox:[],log:[]};
      await child.save();
    }
    if(this.closed) throw new Error('Hand buffer closed');
    this.sessions.set(gameId,child);
    try {await child.open();if(this.closed) throw new Error('Hand buffer closed');} catch(error) {child.close();this.sessions.delete(gameId);throw error;}
    return child;
  }
  async candidate(stacks) {
    this.required=stacks;this.pump();
    const index=this.table.view.slot.index+1;
    const job=this.table.data.buffer?.jobs.find(j=>j.index===index&&(j.deferredPayouts ? stacks.every(n=>n>4800) : pairKey(j.stacks)===pairKey(stacks)));
    if(!job) return null;
    let child=this.sessions.get(job.id);
    if(!child && this.table.data.buffer.done.includes(job.id)) {
      const slot=this.table.data.buffer.slots.find(s=>s.index===index);
      const terms=await this.table.player.call('futureTerms',{index,anchor:Array.from(unhex(slot.gameId)),stacks:job.stacks});
      child=await this.open(job.id,await hash(['candidate-invite',slot.inviteSecret,job.id]),terms,{bufferCandidate:true,deferredPayouts:!!job.deferredPayouts,dealGameId:slot.gameId});
    }
    if(retrying(child??{}))return null;
    if(!child?.data.prepared || !child.data.peer.ready) return null;
    if(child.error)throw new Error(child.error);
    if(job.deferredPayouts) {
      if(!child.data.payoutsBound) {
        if(child.pollTask) await child.pollTask;
        clearInterval(child.timer);
        child.data.prepared=await child.player.call('bindPayouts',{stacks});
        child.data.terms={...child.data.terms,stacks};child.data.proposal={terms:child.data.terms};
        child.data.payoutsBound=true;await child.save();
        child.timer=setInterval(()=>void child.step(),100);void child.step();
      }
      // The local native preparation is durable, so the parent can validate
      // its selection while boundready is in flight. advanceChannel still
      // requires the peer's matching binding before exchanging entry frames.
    }
    return child;
  }
  async evict() {
    const t=this.table,s=t.data.buffer,keep=new Set([...s.slots.map(x=>x.gameId),...s.jobs.map(x=>x.id)]);
    for(const [id,child] of this.sessions) if(!keep.has(id)) {child.close();this.sessions.delete(id);}
    const garbageBefore=JSON.stringify(s.garbage??[]);
    s.garbage=(s.garbage??[]).filter(id=>id!==t.data.gameId && id!==s.seedGameId && id!==t.data.entrySelection?.gameId);
    for(const id of s.garbage.slice()) {
      if(id===t.data.gameId || id===s.seedGameId || id===t.data.entrySelection?.gameId || keep.has(id)) continue;
      if(await discardFuture(id,t.data.sender)) s.garbage=s.garbage.filter(x=>x!==id);
    }
    if(JSON.stringify(s.garbage)!==garbageBefore) await t.save();
    // Keep the four nearest ready engines hot; all other complete artifacts are durable.
    const ready=s.jobs.filter(j=>s.done.includes(j.id) && t.data.peer.buffer?.done?.includes(j.id)).sort((a,b)=>a.index-b.index);
    for(const job of ready.slice(4)) {
      const child=this.sessions.get(job.id);
      if(child && !child.data.entrySelected) {child.close();this.sessions.delete(job.id);}
    }
  }
  adopt(child) {this.sessions.delete(child.data.gameId);this.required=null;this.node=null;this.announced=null;}
  async discardUnused() {this.close();if(this.task)await this.task;await discardBuffer(this.table.data.buffer??{},this.table.data.sender);}
  close() {this.closed=true;for(const child of this.sessions.values()) child.close();this.sessions.clear();}
}
