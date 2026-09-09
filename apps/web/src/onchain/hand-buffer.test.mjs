import test from 'node:test';
import assert from 'node:assert/strict';
import {HandBuffer,validateBufferPlan,isUnactivatedJournal} from './hand-buffer.js';
test('buffer rejects oversized, repeated or out-of-sequence slots and jobs',()=>{
 const slot={index:1,gameId:'aa'.repeat(32),inviteSecret:'bb'.repeat(32)};
 validateBufferPlan({slots:[slot],jobs:[{id:"cc".repeat(32),index:1,stacks:[20000,20000],deferredPayouts:true}]},0);
 for(const plan of [{slots:[slot,slot],jobs:[]},{slots:[{...slot,index:4}],jobs:[]},{slots:[slot],jobs:[{index:2,stacks:[20000,20000]}]}])
 assert.throws(()=>validateBufferPlan(plan,0));
});
for(const fundingPending of [false,true]) test(`buffer fills three reusable future hands ${fundingPending?'while signed funding is confirming':'during play'}`,async()=>{
 let opened=0;
 const table={data:{sender:'alice',signedFunding:fundingPending?'signed':null,gameId:'cc'.repeat(32),terms:{stacks:[20000,20000]},peer:{}},
 view:{slot:{index:0},channelReady:!fundingPending,recoveryReady:true,node:'active'},save:async()=>{},
 player:{call:async(method,args)=>method==='outcomes'?[[20000,20000],[19900,20100],[19800,20200],[20200,19800]]:{slot:{index:args.index}}}};
 const b=new HandBuffer(table);b.announce=async()=>{};
 b.open=async(id,invite,terms,flags)=>{
   let c=b.sessions.get(id);if(!c) {c={data:{...flags,deckReady:true,prepared:!!flags.bufferCandidate,peer:{ready:true}},save:async()=>{},close(){}};b.sessions.set(id,c);if(flags.bufferCandidate)opened++;}
   return c;
 };
 for(let i=0;i<3;i++) {
  await b.run();assert.equal(opened,i+1);
  // Until peer completion is acknowledged, the host cannot advance the queue.
  await b.run();assert.equal(opened,i+1);
  table.data.peer.buffer={done:[...table.data.buffer.done]};
 }
 await b.run();
 assert.equal(table.data.buffer.slots.length,3);assert.equal(table.data.buffer.jobs.length,3);
 assert.equal(table.data.buffer.done.length,3);assert.ok(b.sessions.size<=7);
 b.close();assert.equal(b.sessions.size,0);
});

test('garbage collection preserves selected and enforceable journals',()=>{
 const meta={version:1,entry_authorization:null,play_authorization:null,selection:null,root:null,handoff:null,cashout:null,entered:false,closing:false,pending:null,accepted:[]};
 const bytes=value=>{const json=new TextEncoder().encode(JSON.stringify(value)),out=new Uint8Array(12+json.length);out.set(new TextEncoder().encode('CHJOUR01'));new DataView(out.buffer).setUint32(8,json.length,true);out.set(json,12);return out;};
 assert.equal(isUnactivatedJournal(bytes(meta)),true);
 for(const change of [{entry_authorization:[1]},{selection:[1]},{root:[1]},{entered:true},{closing:true},{accepted:[{}]},{version:2}]) assert.equal(isUnactivatedJournal(bytes({...meta,...change})),false);
 assert.equal(isUnactivatedJournal(new Uint8Array(1)),false);
});

test('low storage reserves preparation for the nearest hand and evicts before allocating',async t=>{
 const previous=Object.getOwnPropertyDescriptor(navigator,'storage');
 Object.defineProperty(navigator,'storage',{configurable:true,value:{estimate:async()=>({quota:512*1024*1024,usage:400*1024*1024})}});
 t.after(()=>{if(previous)Object.defineProperty(navigator,'storage',previous);else delete navigator.storage;});
 const calls=[],table={data:{sender:'alice',gameId:'cc'.repeat(32),terms:{stacks:[20000,20000]},peer:{}},view:{slot:{index:0},channelReady:true},save:async()=>{},player:{call:async(_,args)=>({slot:{index:args.index}})}};
 const b=new HandBuffer(table);b.announce=async()=>{};b.evict=async()=>calls.push('evict');
 b.open=async(id,invite,terms,flags)=>{
  calls.push(terms.slot.index);const child={data:{...flags,deckReady:true,prepared:true,peer:{ready:true}},save:async()=>{},close(){}};b.sessions.set(id,child);return child;
 };
 await b.run();
 assert.equal(calls[0],'evict');assert.deepEqual(calls.filter(n=>typeof n==='number'),[1,1]);
 assert.equal(table.data.buffer.slots.length,3,'both peers retain the same agreed plan');
 b.close();
});

test('local payout completion can overlap selection with the peer readiness exchange',async()=>{
 const child={data:{prepared:{binding:'final'},payoutsBound:true,peer:{ready:{binding:'internal'}}}};
 const table={view:{slot:{index:0}},data:{buffer:{jobs:[{id:'candidate',index:1,deferredPayouts:true}],done:['candidate']}}};
 const buffer=new HandBuffer(table);buffer.pump=()=>{};buffer.sessions.set('candidate',child);
 assert.equal(await buffer.candidate([20100,19900]),child);
 assert.equal(child.data.entrySelected,undefined,'local readiness does not authorize entry');
 child.error='Inventory disagreement';
 await assert.rejects(buffer.candidate([20100,19900]),/Inventory disagreement/);
});

test('a retrying candidate does not restart or pause its parent hand',async()=>{
 const child={data:{prepared:{},peer:{ready:true}},error:'Preparation exchange timed out',pollPaused:false};
 const table={view:{slot:{index:0}},data:{buffer:{jobs:[{id:'candidate',index:1,deferredPayouts:true}],done:['candidate']}}};
 const buffer=new HandBuffer(table);buffer.pump=()=>{};buffer.sessions.set('candidate',child);
 assert.equal(await buffer.candidate([20000,20000]),null);
 child.pollPaused=true;
 await assert.rejects(buffer.candidate([20000,20000]),/timed out/);
 child.error=null;child.data.payoutsBound=true;
 assert.equal(await buffer.candidate([20000,20000]),child);
});


for(const view of [{terminal:true},{betting:false}])test(`handover reserves preparation for the nearest hand ${JSON.stringify(view)}`,async()=>{
 const opened=[],table={data:{sender:'alice',gameId:'cc'.repeat(32),terms:{stacks:[20000,20000]},peer:{}},view:{slot:{index:0},channelReady:true,...view},save:async()=>{},player:{call:async(_,args)=>({slot:{index:args.index}})}};
 const buffer=new HandBuffer(table);buffer.announce=async()=>{};buffer.evict=async()=>{};
 buffer.open=async(id,invite,terms,flags)=>{
  opened.push(terms.slot.index);const child={data:{...flags,deckReady:true,prepared:true,peer:{ready:true}},save:async()=>{},close(){}};buffer.sessions.set(id,child);return child;
 };
 await buffer.run();assert.deepEqual(opened,[1,1]);
 table.data.peer.buffer={done:[...table.data.buffer.done]};table.view={...table.view,terminal:false,betting:true};
 await buffer.run();assert.ok(opened.includes(2),'normal buffer preparation resumes during play');buffer.close();
});
