import {test, beforeEach} from 'node:test';
import assert from 'node:assert/strict';
import {Matchmaking,walletMatchId,pendingMatch,forgetMatch} from './matchmaking.js';
let calls, replies;
beforeEach(()=>{
  const values=new Map();globalThis.localStorage={getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)};
  Object.defineProperty(globalThis,'navigator',{configurable:true,value:{locks:{request:async(_name,_options,run)=>run({})}}});
  calls=[];replies=[];
  globalThis.fetch=async(_url,options)=>{calls.push(JSON.parse(options.body));const reply=replies.shift();if(reply instanceof Error)throw reply;assert.ok(reply,'Unexpected matchmaking request');return {ok:true,json:async()=>reply};};
});
const matched={status:'matched',gameId:'a'.repeat(64),sender:'alice',inviteSecret:'b'.repeat(64)};
test('lost enter response retries the same ticket and preserves the assigned seat',async()=>{
  replies.push(new Error('Disconnected'));
  await assert.rejects(new Matchmaking(()=>{},'11'.repeat(32)).find(),/Disconnected/);
  assert.ok(pendingMatch());const original=calls[0];
  replies.push(matched);
  const a=await new Matchmaking(()=>{},'11'.repeat(32)).find();assert.equal(calls[1].ticket,original.ticket);assert.equal(a.playerToken,original.playerToken);
  const b=await new Matchmaking(()=>{},'11'.repeat(32)).find();assert.deepEqual(b,a);assert.equal(calls.length,2);
});
test('refresh polls the existing waiting ticket instead of creating another room',async()=>{
  replies.push({status:'waiting'},new Error('Page closed'));
  await assert.rejects(new Matchmaking(()=>{},'11'.repeat(32)).find());
  replies.push(matched);await new Matchmaking(()=>{},'11'.repeat(32)).find();
  assert.equal(calls[2].action,'poll');assert.equal(calls[2].ticket,calls[0].ticket);
});
test('cancellation before entry sends only a cancellation tombstone',async()=>{
  const m=new Matchmaking(()=>{},'11'.repeat(32));await m.cancel();replies.push({status:'cancelled'});
  assert.equal(await m.find(),null);assert.equal(calls.length,1);assert.equal(calls[0].action,'cancel');assert.equal(pendingMatch(),false);
});
test('matching wins a cancellation race without discarding the assignment',async()=>{
  const m=new Matchmaking(()=>{},'11'.repeat(32));m.fresh();replies.push(matched);await m.cancel();
  assert.equal((await m.find()).gameId,matched.gameId);assert.ok(pendingMatch());
});
test('expired unassigned entries requeue with a fresh ticket',async()=>{
  replies.push({status:'expired'},matched);await new Matchmaking(()=>{},'11'.repeat(32)).find();
  assert.notEqual(calls[0].ticket,calls[1].ticket);assert.equal(calls[1].action,'enter');
});
test('a second tab cannot submit another waiting request',async()=>{
  navigator.locks.request=async(_name,_options,run)=>run(null);
  await assert.rejects(new Matchmaking(()=>{},'11'.repeat(32)).find(),/another tab/);assert.equal(calls.length,0);forgetMatch();
});

test('wallet identity is stable across independent browser storage and uses no secret',async()=>{
  const script='5120'+'AB'.repeat(32);
  const first=await walletMatchId({script,secret:'not read'});
  localStorage.clear?.();
  const second=await walletMatchId({script:script.toLowerCase(),secret:'different'});
  assert.equal(first,second);assert.match(first,/^[a-f0-9]{64}$/);
  assert.notEqual(first,await walletMatchId({script:'5120'+'cd'.repeat(32)}));
});
