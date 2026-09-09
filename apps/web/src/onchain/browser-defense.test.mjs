import test from 'node:test';
import assert from 'node:assert/strict';
import { BrowserDefense } from './browser-defense.js';
const txid='11'.repeat(32), funding='22'.repeat(32)+':0';
const pkg={funding,roots:[txid,'33'.repeat(32)],penalties:[[1]],paths:[[[2],[3],[4]],[]]};
test('browser defense waits for an observed root, prioritizes justice, and respects CSV',async()=>{
 let spent=false; const published=[];
 const chain={
  outpointStatus:async point=>point.displayTxid ? (spent?{state:'spent',spendingDisplayTxid:Uint8Array.from({length:32},()=>17)}:{state:'unspent'}) : {state:'unspent',creatingStatus:{state:'confirmed',block:{height:100}}},
  tip:async()=>({block:{height:105}}), publish:async raw=>published.push(raw[0]),
 };
 const inspect=async raw=>({inputs:[{previousOutpoint:{id:raw[0]},sequence:raw[0]===3?7:raw[0]===4?0x400001:0xffffffff}]});
 const monitor=new BrowserDefense(null,null,chain,inspect);
 await monitor.defend(pkg); assert.deepEqual(published,[]);
 spent=true;await monitor.defend(pkg); assert.deepEqual(published,[1,2]);
});
test('local recovery package is durable before authorizing a move; conflicting revisions fail',async()=>{
 const records=new Map(), events=[];
 const store={read:async(_,id)=>records.get(id),load:async id=>records.get(id),save:async(id,_,bytes)=>{events.push('saved');records.set(id,bytes)}};
 const chain={outpointStatus:async()=>{events.push('observed');return{state:'unspent',creatingStatus:{state:'confirmed'}}}};
 const monitor=new BrowserDefense(null,store,chain);
 const payload=new TextEncoder().encode(JSON.stringify({...pkg,revision:1}));
 const digest=Buffer.from(await crypto.subtle.digest('SHA-256',payload)).toString('hex');
 assert.deepEqual(await monitor.register('game',payload,digest),{closing:false});
 assert.deepEqual(events,['saved','observed']);
 const changed=new TextEncoder().encode(JSON.stringify({...pkg,revision:1,penalties:[]}));
 await assert.rejects(monitor.register('game',changed,Buffer.from(await crypto.subtle.digest('SHA-256',changed)).toString('hex')),/stale/);
});

test('cooperative registrations stay local after funding verification and honor background closure',async()=>{
 const records=new Map();let observations=0;
 const store={read:async(_,id)=>records.get(id),load:async id=>records.get(id),save:async(id,_,bytes)=>records.set(id,bytes)};
 const monitor=new BrowserDefense(null,store,{outpointStatus:async()=>{observations++;return {state:'unspent',creatingStatus:{state:'confirmed'}}}});
 for(let revision=0;revision<3;revision++) {
  const payload=new TextEncoder().encode(JSON.stringify({...pkg,revision}));
  const digest=Buffer.from(await crypto.subtle.digest('SHA-256',payload)).toString('hex');
  if(revision===2) records.set(`closing/${funding}`,new Uint8Array([1]));
  assert.deepEqual(await monitor.register('game',payload,digest),{closing:revision===2});
 }
 assert.equal(observations,1);
});

test('background monitoring observes shared channel funding once per pass',async()=>{
 let observed=0;
 const monitor=new BrowserDefense(null,{checkpointIds:async()=>['defense/a','defense/b'],load:async()=>new TextEncoder().encode(JSON.stringify(pkg))},
 {outpointStatus:async()=>{observed++;return {state:'unspent'};}});
 await monitor.tick();assert.equal(observed,1);
});

test('reconnect permits initial entry progress within revision 1, but never rewrites an entered path',async()=>{
 const records=new Map(),store={read:async(_,id)=>records.get(id),load:async id=>records.get(id),save:async(id,_,bytes)=>records.set(id,bytes)};
 const monitor=new BrowserDefense(null,store,{outpointStatus:async()=>({state:'unspent',creatingStatus:{state:'confirmed'}})});
 const initial={version:1,revision:1,hand:'44'.repeat(32),...pkg,paths:[[],[]],penalties:[]};
 const entered={...initial,paths:[[[10]],[[20]]]};
 const register=async p=>{const bytes=new TextEncoder().encode(JSON.stringify(p));return monitor.register('entry',bytes,Buffer.from(await crypto.subtle.digest('SHA-256',bytes)).toString('hex'));};
 await register(initial);
 const initialBytes=records.get('defense/entry');
 for(const invalid of [
  {...entered,hand:'55'.repeat(32)}, {...entered,funding:'66'.repeat(32)+':0'},
  {...entered,roots:[txid,'77'.repeat(32)]}, {...entered,version:2},
  {...entered,paths:[[[10]],[]]}, {...entered,paths:[[[10],[11]],[[20]]]},
  {...entered,penalties:[[1]]},
 ]){await assert.rejects(register(invalid),/stale/);assert.equal(records.get('defense/entry'),initialBytes);}
 await register(entered);
 await register(entered); // Exact reconnect replay is idempotent.
 const enteredBytes=records.get('defense/entry');
 await assert.rejects(register(initial),/stale/);
 await assert.rejects(register({...entered,paths:[[[11]],[[20]]]}),/stale/);
 assert.equal(records.get('defense/entry'),enteredBytes);
 await register({...entered,revision:2});
 await assert.rejects(register(entered),/stale/);
});
