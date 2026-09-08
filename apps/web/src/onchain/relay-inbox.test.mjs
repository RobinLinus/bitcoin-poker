import test from 'node:test';
import assert from 'node:assert/strict';
import {PreparationCheckpointStore} from '../storage/preparation-checkpoint-store.js';
import {sendRelayMessage,sendRelayMessages,receiveRelayMessages} from './relay-inbox.js';
import {relayConnection} from './relay-socket.js';

function fixture(t) {
 const saved=new Map(),p=PreparationCheckpointStore.prototype;
 const original={read:p.read,load:p.load,save:p.save,...relayConnection};
 const key=(s,id)=>`${s.name}/${id}`;
 p.read=async function(_,id){return saved.get(key(this,id))};
 p.load=async function(id){return saved.get(key(this,id))};
 p.save=async function(id,_,value){saved.set(key(this,id),value.slice())};
 t.after(()=>{Object.assign(p,{read:original.read,load:original.load,save:original.save});Object.assign(relayConnection,{exchange:original.exchange,status:original.status,take:original.take,discard:original.discard});});
 const state={epoch:1,revision:0,host:null,guest:null,rows:[],cursor:0,ack:[0,0],requests:0,downloads:[0,0],batches:[],loseResponse:false};
 const reset=()=>Object.assign(state,{epoch:state.epoch+1,revision:state.revision+1,host:null,guest:null,rows:[],cursor:0,ack:[0,0]});
 relayConnection.take=async()=>null;relayConnection.discard=async(room,ack)=>{assert.equal(ack.epoch,String(state.epoch));assert.ok(ack.after<=state.cursor);const role=room.sender==='alice'?0:1;state.ack[role]=Math.max(state.ack[role],ack.after);};
 relayConnection.status=async()=>({revision:state.revision,subscribed:true});
 relayConnection.exchange=async(room,body)=>{
  state.requests++;const revision=state.revision,seat=body.sender==='alice'?'host':'guest',role=body.sender==='alice'?0:1;
  if(state[seat] && state[seat]!==body.playerToken)throw new Error('capability conflict');
  if(!state[seat]){state[seat]=body.playerToken;state.revision++;}
  const same=body.epoch===String(state.epoch),after=same?body.after:0,accepted=[];
  assert.ok(after<=state.cursor);state.ack[role]=Math.max(state.ack[role],after);
  const joined=!!(state.host&&state.guest);
  if((same || body.epoch===null) && joined) for(const message of body.messages) {
   const old=state.rows.find(r=>r.messageId===message.messageId);
   if(old)assert.deepEqual(old.payload,message.payload);
   else {state.rows.push({...message,sender:body.sender,cursor:++state.cursor});state.revision++;}
   accepted.push(message.messageId);
  }
  state.batches.push(accepted.length);
  const messages=state.rows.filter(r=>r.cursor>after&&r.cursor>Math.min(...state.ack)&&r.sender!==body.sender).slice(0,64);
  state.downloads[role]+=messages.length;
  if(state.loseResponse){state.loseResponse=false;throw new Error('connection lost');}
  return {revision,page:{epoch:String(state.epoch),joined,accepted,messages,nextCursor:messages.at(-1)?.cursor??state.cursor}};
 };
 const alice={gameId:'game',sender:'alice',playerToken:'host',inviteSecret:'invite'},bob={...alice,sender:'bob',playerToken:'guest'};
 const poll=(room,after)=>receiveRelayMessages(room,after,{force:true});
 const join=async()=>{await poll(alice,0);await poll(bob,0);};
 return {state,reset,alice,bob,saved,poll,join};
}
const message=id=>({messageId:id,kind:'channel.frame',payload:new Uint8Array([1,2,3])});

test('batched uploads do not download the sender’s payloads',async t=>{
 const {state,alice,bob,join,poll}=fixture(t);await join();
 const before=state.requests;
 await sendRelayMessages(alice,Array.from({length:64},(_,i)=>message(String(i))));
 assert.equal(state.requests-before,2);assert.deepEqual(state.batches.slice(-2),[32,32]);
 const requests=state.requests;
 assert.equal((await receiveRelayMessages(alice,0)).messages.length,64);
 assert.equal(state.requests,requests);assert.equal(state.downloads[0],0);
 assert.equal((await poll(bob,0)).messages.length,64);
});
test('idle consumers share push state and make no network requests',async t=>{
 const {state,alice,bob,join,poll}=fixture(t);await join();
 await sendRelayMessage(alice,message('first'));await poll(bob,0);await poll(bob,1);
 const before=state.requests;
 for(let i=0;i<100;i++)await receiveRelayMessages(bob,1);
 assert.equal(state.requests,before);
});
test('restart replays in order without duplicate local delivery',async t=>{
 const {reset,alice,bob,join,poll}=fixture(t);await join();
 await sendRelayMessage(alice,message('first'));await poll(bob,0);await poll(bob,1);
 reset();assert.equal(await sendRelayMessage(alice,message('second')),false);
 await poll(bob,1);await poll(alice,2);
 const next=await poll(bob,1);assert.deepEqual(next.messages.map(m=>m.messageId),['second']);
 assert.equal((await poll(bob,2)).messages.length,0);
 assert.equal((await receiveRelayMessages(bob,0)).messages[0].messageId,'first');
});
test('unsent bytes survive disconnect before the peer joins',async t=>{
 const {reset,alice,bob,poll}=fixture(t);
 assert.equal(await sendRelayMessage(alice,message('pending')),false);
 reset();await poll(bob,0);await poll(alice,1);
 assert.equal((await poll(bob,0)).messages[0].messageId,'pending');
});
test('lost response retries the same message id without duplicating delivery',async t=>{
 const {state,alice,bob,join,poll}=fixture(t);await join();state.loseResponse=true;
 await assert.rejects(sendRelayMessage(alice,message('first')),/lost/);
 await sendRelayMessage(alice,message('first'));assert.equal(state.rows.length,1);
 assert.equal((await poll(bob,0)).messages.length,1);
 assert.equal((await poll(bob,1)).messages.length,0);
});
test('a failed local save never acknowledges incoming bytes',async t=>{
 const {state,alice,bob,join,poll}=fixture(t);await join();await sendRelayMessage(alice,message('first'));
 const save=PreparationCheckpointStore.prototype.save;
 PreparationCheckpointStore.prototype.save=async function(id,...args){if(this.name.endsWith('bob')&&id.includes('/page/'))throw Error('disk full');return save.call(this,id,...args)};
 await assert.rejects(poll(bob,0),/disk full/);assert.equal(state.ack[1],0);
 PreparationCheckpointStore.prototype.save=save;assert.equal((await poll(bob,0)).messages.length,1);
 assert.equal(state.ack[1],1,'durable inbox is acknowledged without another poll');await poll(bob,1);assert.equal(state.ack[1],1);
});
test('a conflicting outgoing id cannot replace previously saved bytes',async t=>{
 const {alice,join}=fixture(t);await join();await sendRelayMessage(alice,message('same'));
 await assert.rejects(sendRelayMessage(alice,{...message('same'),payload:new Uint8Array([4,5,6])}),/identity conflict/);
});

test('waiting for the other seat does not repeatedly upload queued data',async t=>{
 const {state,alice,bob,poll}=fixture(t);
 assert.equal(await sendRelayMessage(alice,message('waiting')),false);
 await poll(alice,1);await poll(alice,1);
 const before=state.requests;
 for(let i=0;i<50;i++){assert.equal(await sendRelayMessage(alice,message('waiting')),false);await receiveRelayMessages(alice,1);}
 assert.equal(state.requests,before);
 await poll(bob,0);await poll(alice,1);
 assert.equal((await poll(bob,0)).messages[0].messageId,'waiting');
});

test('consumers skip unrelated payloads using page metadata and durable cursors',async t=>{
 const {alice,bob,join,poll}=fixture(t);await join();await sendRelayMessages(alice,[message('one'),message('two')]);
 await poll(bob,0);
 const load=PreparationCheckpointStore.prototype.load;let pageReads=0;
 PreparationCheckpointStore.prototype.load=async function(id,...args){if(id.includes('/page/'))pageReads++;return load.call(this,id,...args);};
 const page=await receiveRelayMessages(bob,0,{kindPrefix:'table.'});
 assert.equal(page.nextCursor,2);assert.equal(page.messages.length,1);assert.equal(page.messages[0].kind,'transport.skip');assert.equal(pageReads,0);
});

test('direct push remains queued until its encrypted inbox cursor is durable',async t=>{
 const {alice,bob,join,state}=fixture(t);await join();
 const page={epoch:String(state.epoch),joined:true,socketRevision:state.revision,nextCursor:1,messages:[{...message('push'),sender:'alice',cursor:1}]};
 state.cursor=1;state.rows=page.messages;
 let pending=page,discarded=0;
 relayConnection.take=async()=>pending;
 const acknowledge=relayConnection.discard;
 relayConnection.discard=async(room,ack)=>{discarded++;pending=null;await acknowledge(room,ack)};
 const p=PreparationCheckpointStore.prototype,save=p.save;
 p.save=async function(id,...args){if(id.endsWith('/index'))throw Error('disk full');return save.call(this,id,...args)};
 await assert.rejects(receiveRelayMessages(bob,0),/disk full/);
 assert.equal(discarded,0);assert.deepEqual(state.ack,[0,0]);
 p.save=save;
 const received=await receiveRelayMessages(bob,0);
 assert.equal(received.messages.length,1);assert.equal(received.messages[0].messageId,'push');assert.equal(discarded,1);
 assert.deepEqual(state.ack,[0,1],'only the saved push is acknowledged');
 const requests=state.requests;
 await receiveRelayMessages(bob,1);assert.equal(state.requests,requests,'durable push needs no empty round trip');
 // Duplicate response/push delivery is suppressed by the durable message ID.
 pending=page;const next=await receiveRelayMessages(bob,1);
 assert.equal(next.messages.length,0);assert.equal(discarded,2);
});

test('a delayed upload does not block durable peer delivery or regress its cursor',async t=>{
 const {alice,bob,join,state}=fixture(t);await join();
 const exchange=relayConnection.exchange;let release,started;
 const waiting=new Promise(resolve=>{started=resolve});
 const gate=new Promise(resolve=>{release=resolve});
 relayConnection.exchange=async(room,body)=>{if(room.sender==='bob'&&body.messages.length){started();await gate;}return exchange(room,body)};
 const uploading=sendRelayMessage(bob,message('own'));await waiting;
 const peer={...message('peer'),sender:'alice',cursor:1};state.cursor=1;state.rows=[peer];
 let pending={epoch:String(state.epoch),joined:true,socketRevision:state.revision,nextCursor:1,messages:[peer]};
 relayConnection.take=async()=>pending;
 const discard=relayConnection.discard;relayConnection.discard=async(room,ack)=>{await discard(room,ack);pending=null};
 try {
  const received=await Promise.race([receiveRelayMessages(bob,0,{kindPrefix:'channel.'}),new Promise((_,reject)=>setTimeout(()=>reject(Error('inbox blocked behind upload')),500))]);
  assert.deepEqual(received.messages.filter(m=>m.sender==='alice').map(m=>m.messageId),['peer']);
  assert.equal(state.ack[1],1);
 }finally{release();}
 assert.equal(await uploading,true);
 const all=await receiveRelayMessages(bob,0,{kindPrefix:'channel.'});
 assert.deepEqual(all.messages.filter(m=>m.sender==='alice').map(m=>m.messageId),['peer']);
});

test('an upload response saves earlier pushes before acknowledging its skipped delivery cursor',async t=>{
 const {bob,join,state}=fixture(t);await join();
 const original=relayConnection.exchange;let pending=null;
 relayConnection.take=async()=>pending;
 const discard=relayConnection.discard;
 relayConnection.discard=async(room,ack)=>{await discard(room,ack);pending=null};
 relayConnection.exchange=async(room,body)=>{
   const result=await original(room,body);
   const peer={...message('pushed-before-response'),sender:'alice',cursor:++state.cursor};state.rows.push(peer);
   pending={epoch:String(state.epoch),joined:true,socketRevision:state.revision,nextCursor:state.cursor,messages:[peer]};
   result.page.nextCursor=state.cursor;result.page.messages=[];
   return result;
 };
 await sendRelayMessage(bob,message('upload'));
 const page=await receiveRelayMessages(bob,0);
 assert.deepEqual(page.messages.filter(m=>m.sender==='alice').map(m=>m.messageId),['pushed-before-response']);
 assert.equal(state.ack[1],state.cursor);
});

test('a late subscription response cannot undo an already delivered peer join',async t=>{
 const {alice,join,state}=fixture(t);await join();
 const exchange=relayConnection.exchange,discard=relayConnection.discard;let pending=null;
 relayConnection.take=async()=>pending;
 relayConnection.discard=async(room,ack)=>{await discard(room,ack);pending=null};
 relayConnection.exchange=async(room,body)=>{
   const result=await exchange(room,body);
   pending={...result.page,joined:true,messages:[],socketRevision:result.revision};
   result.page.joined=false;
   // Receiving a join does not replace the live socket subscription.
   state.revision=result.revision;
   return result;
 };
 await sendRelayMessage(alice,message('first'));
 relayConnection.exchange=exchange;
  assert.equal(await sendRelayMessage(alice,message('second')),true,'late response left the peer permanently unjoined');
});

test('bulk uploads fill a bounded window before waiting for the first response',async t=>{
 const {alice,join,poll,state}=fixture(t);await join();await poll(alice,0);
 alice.transportLane=1;
 const original=relayConnection.exchange,releases=[];let inFlight=0,peak=0;
 relayConnection.exchange=async(room,body)=>{
   inFlight++;peak=Math.max(peak,inFlight);
   const result=await original(room,body);
   await new Promise(resolve=>releases.push(resolve));inFlight--;return result;
 };
 const messages=Array.from({length:40},(_,i)=>({...message(String(i)),payload:new Uint8Array(128*1024)}));
 const upload=sendRelayMessages(alice,messages);
 try {
   for(let i=0;i<100&&releases.length<4;i++)await new Promise(r=>setTimeout(r,1));
   assert.equal(releases.length,4,'packets still wait for the previous response');
   assert.equal(state.rows.length,16,'window is capped at 2 MiB');
 } finally {
   relayConnection.exchange=original;for(const release of releases)release();
 }
 assert.equal(await upload,true);assert.equal(peak,4);
 assert.deepEqual(state.rows.map(m=>m.messageId),messages.map(m=>m.messageId));
});

test('a lost response in a bulk window replays identical bytes without duplicate delivery',async t=>{
 const {alice,bob,join,poll,state}=fixture(t);await join();await poll(alice,0);alice.transportLane=3;
 const original=relayConnection.exchange;let calls=0;
 relayConnection.exchange=async(room,body)=>{
   const call=++calls,result=await original(room,body);
   if(call===2)throw Error('window response lost');return result;
 };
 const messages=Array.from({length:20},(_,i)=>({...message(String(i)),payload:new Uint8Array(128*1024).fill(i)}));
 await assert.rejects(sendRelayMessages(alice,messages),/window response lost/);
 relayConnection.exchange=original;
 assert.equal(await sendRelayMessages(alice,messages),true);
 assert.deepEqual(state.rows.map(m=>m.messageId),messages.map(m=>m.messageId));
 const received=await poll(bob,0);assert.equal(received.messages.length,20);
 assert.deepEqual(received.messages.map(m=>m.payload[0]),messages.map(m=>m.payload[0]));
});
