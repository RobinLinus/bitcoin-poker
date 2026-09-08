import test from 'node:test';
import assert from 'node:assert/strict';
import {continueChannelHand} from './channel-redeal.js';
function table() {
 const calls=[];
 const s={data:{peer:{},terms:{origin:'funding:0',origin_value:45000,button:0},buffer:{}},
   view:{terminal:true,hand:'11'.repeat(32),node:'terminal',nextStacks:[19800,20200]},
   save:async()=>{},notify(){},startPredeal(){calls.push('buffer');},
   send:async(kind,value)=>calls.push([kind,value]),calls};
 return s;
}
function successor(s,complete=false) {
 s.data.peer.nextready={hand:s.view.hand,node:s.view.node};
 const c={data:{gameId:'22'.repeat(32),sender:'alice',entrySelected:true,channelContinuation:true,terms:{origin:'funding:0'}},
  view:{channelReady:true,pendingMove:false},save:async()=>{},wallet:{},chain:{},
  player:{call:async(method)=>method==='authorizePlay'?c.view:new Uint8Array([1,2,3])}};
 s.handBuffer={candidate:async()=>c,adopt(){},table:s};
 s.player={close(){},call:async(method)=>method==='handoff'?{...s.view,handoffComplete:complete}:new Uint8Array([1,2,3])};
 s.wallet={close(){}};s.step=async()=>{};
 return c;
}
test('redeal requests the same settled result immediately',async()=>{
 const s=table();await continueChannelHand.call(s);
 assert.equal(s.data.wantsNext,true);
 assert.deepEqual(s.calls,[['nextready',{hand:s.view.hand,node:'terminal'}]]);
});
test('sit out and insufficient stacks stop automatic readiness',async()=>{
 for(const patch of [{sitOutNext:true},{}]) {
  const s=table();Object.assign(s.data,patch);if(!patch.sitOutNext)s.view.nextStacks=[100,39900];
  await continueChannelHand.call(s);assert.deepEqual(s.calls,[]);
 }
});
test('a different terminal cannot select a buffered tree',async()=>{
 const s=table();s.data.peer.nextready={hand:s.view.hand,node:'wrong'};
 await assert.rejects(()=>continueChannelHand.call(s),/settlement mismatch/);
 assert.ok(!s.calls.includes('buffer'));
});
test('the successor stays hidden until both revocations are acknowledged',async()=>{
 const s=table();successor(s);
 await continueChannelHand.call(s);
 assert.equal(s.data.entrySelection.gameId,'22'.repeat(32));assert.equal(s.data.handoffStarted,true);
 assert.equal(s.data.successor,undefined);assert.equal(s.view.node,'terminal');
});
test('a ready next hand is not blocked by a more distant background preparation error',async()=>{
 const s=table();successor(s);s.handBuffer.error='QuotaExceededError';
 await continueChannelHand.call(s);
 assert.equal(s.data.entrySelection.gameId,'22'.repeat(32));
 assert.equal(s.data.handoffStarted,true);
 assert.equal(s.data.successor,undefined,'retirement barrier remains mandatory');
});
test('a warm handover reuses the prepared worker, funding and buffer',async()=>{
 const s=table(),child=successor(s,true),buffer=s.handBuffer;
 const previous=globalThis.location;globalThis.location={hash:''};
 try {
  await continueChannelHand.call(s);
  assert.equal(s.player,child.player);assert.equal(s.data.terms.origin,'funding:0');
  assert.equal(s.data.parentHandoffDone,true);assert.equal(s.handBuffer,buffer);
 } finally {clearInterval(s.timer);globalThis.location=previous;}
});
test('a peer cashout takes precedence over automatic next-hand readiness',async()=>{
 const s=table();s.data.wantsNext=true;s.data.peer.leave={hand:s.view.hand,node:s.view.node};
 let closed=0;s.cashOut=async()=>closed++;
 await continueChannelHand.call(s);assert.equal(closed,1);assert.deepEqual(s.calls,[]);
});
test('redealing keeps the shared player wallet available for later hands and cashout',async()=>{
 const s=table(),child=successor(s,true);let closed=0;
 const wallet={close(){closed++;}};
 s.wallet=child.wallet=wallet;s.sharedWallet=child.sharedWallet=true;
 const previous=globalThis.location;globalThis.location={hash:''};
 try {
  await continueChannelHand.call(s);
  assert.equal(closed,0);assert.equal(s.wallet,wallet);assert.equal(s.sharedWallet,true);
 } finally {clearInterval(s.timer);globalThis.location=previous;}
});
test('a miss prepares the exact candidate without authorizing entry',async()=>{
 const s=table();s.data.peer.nextready={hand:s.view.hand,node:s.view.node};
 s.handBuffer={candidate:async balances=>{assert.deepEqual(balances,s.view.nextStacks);return null;}};
 await continueChannelHand.call(s);
 assert.equal(s.stage,'Preparing the next hand');assert.equal(s.data.entrySelection,undefined);
});
