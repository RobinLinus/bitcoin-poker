import test from 'node:test';
import assert from 'node:assert/strict';
import {PreparationCheckpointStore} from '../storage/preparation-checkpoint-store.js';
import {relayConnection} from './relay-socket.js';
import {channelRoom,sendChannelMessages,receiveChannelMessages,compactChannelPreparation,canCompactPreparationJournal} from './channel-inbox.js';
import {encodeBinary,decodeBinary} from './binary-codec.js';

function fixture(t){
  const stored=new Map(),rooms=new Map(),p=PreparationCheckpointStore.prototype;
  const original={read:p.read,load:p.load,save:p.save,saveBatch:p.saveBatch,checkpointIds:p.checkpointIds,...relayConnection};
  p.read=async function(_,id){return stored.get(`${this.name}/${id}`)};
  p.load=async function(id){return stored.get(`${this.name}/${id}`)};
  p.save=async function(id,_,bytes){stored.set(`${this.name}/${id}`,bytes.slice())};
  p.checkpointIds=async function(){return [...stored.keys()].filter(id=>id.startsWith(`${this.name}/`)).map(id=>id.slice(this.name.length+1))};
  p.saveBatch=async function(entries,deleted=[]){for(const id of deleted)stored.delete(`${this.name}/${id}`);for(const {id,plaintext} of entries)stored.set(`${this.name}/${id}`,plaintext.slice());};
  relayConnection.take=async()=>null;relayConnection.discard=async()=>{};
  relayConnection.status=async()=>({subscribed:false,revision:1});
  relayConnection.exchange=async(room,body)=>{
    if(!rooms.has(room.gameId))rooms.set(room.gameId,[]);
    const rows=rooms.get(room.gameId),accepted=[];
    for(const message of body.messages){
      if(!rows.some(r=>r.messageId===message.messageId))rows.push({...message,sender:room.sender,cursor:rows.length+1});
      accepted.push(message.messageId);
    }
    return {revision:1,page:{epoch:'epoch',joined:true,nextCursor:rows.length,accepted,messages:rows.filter(r=>r.cursor>body.after&&r.sender!==room.sender)}};
  };
  t.after(()=>{Object.assign(p,{read:original.read,load:original.load,save:original.save,saveBatch:original.saveBatch,checkpointIds:original.checkpointIds});Object.assign(relayConnection,{exchange:original.exchange,status:original.status,take:original.take,discard:original.discard})});
  const alice={gameId:crypto.randomUUID(),sender:'alice',playerToken:'host',inviteSecret:'invite'},bob={...alice,sender:'bob',playerToken:'guest'};
  return {alice,bob,rooms,stored};
}
const message=(id,kind)=>({messageId:id,kind,payload:new Uint8Array([1,2,3])});

test('completed preparation drops bulk copies while retaining control replay, deduplication and cursors',async t=>{
  const {alice,bob,stored}=fixture(t);
  await sendChannelMessages(alice,[message('move','channel.frame'),message('proof','channel.0.batch'),message('payout','channel.payout.1.batch')]);
  const first=await receiveChannelMessages(bob,0,{bulk:true});
  const second=await receiveChannelMessages(bob,first.nextCursor,{bulk:true,payout:true});
  await compactChannelPreparation(alice);await compactChannelPreparation(bob);
  assert.deepEqual((await receiveChannelMessages(bob,0)).messages.map(m=>m.messageId),['move']);
  const lane=await channelRoom(bob,1),key=`poker-relay-inbox-bob/${lane.gameId}/index`;
  const index=decodeBinary(stored.get(key));
  assert.equal(index.ids.proof,true);assert.equal(index.cursor,1);assert.deepEqual(index.pages,[]);
  assert.ok(![...stored.keys()].some(k=>k.startsWith(`poker-relay-inbox-bob/${lane.gameId}/page/`)));
  // A late replay of already verified bytes must not recreate the payload log.
  await receiveChannelMessages(bob,second.nextCursor,{bulk:true});
  assert.deepEqual(decodeBinary(stored.get(key)).pages,[]);
  await sendChannelMessages(alice,[message('ack','channel.frame')]);
  const next=await receiveChannelMessages(bob,second.nextCursor);
  assert.deepEqual(next.messages.map(m=>m.messageId),['ack']);assert.ok(next.nextCursor>second.nextCursor);
  const main=decodeBinary(stored.get(`poker-relay-inbox-alice/${alice.gameId}/index`));
  assert.equal(main.outgoing.length,2,'control frames remain available after relay restart');
});

test('storage cleanup requires the durable two-peer entry barrier',()=>{
  const journal=value=>{const json=new TextEncoder().encode(JSON.stringify(value)),out=new Uint8Array(12+json.length);out.set(new TextEncoder().encode('CHJOUR01'));new DataView(out.buffer).setUint32(8,json.length,true);out.set(json,12);return out;};
  assert.equal(canCompactPreparationJournal(journal({version:1,entered:true,peer_ready:true})),true);
  for(const meta of [{version:1,entered:true,peer_ready:false},{version:1,entered:false,peer_ready:true},{version:2,entered:true,peer_ready:true},{}])assert.equal(canCompactPreparationJournal(journal(meta)),false);
  assert.equal(canCompactPreparationJournal(new Uint8Array(3)),false);
});

test('owner streams have independent rooms and merge into a stable rewindable cursor',async t=>{
  const {alice,bob,rooms}=fixture(t);
  await sendChannelMessages(alice,[message('score','channel.score'),message('a','channel.0.inventory'),message('b','channel.0.batch'),message('c','channel.1.inventory')]);
  assert.equal(rooms.size,3);
  const page=await receiveChannelMessages(bob,0,{bulk:true});
  assert.deepEqual(page.messages.map(m=>m.messageId),['score','a','b','c']);
  assert.deepEqual(page.messages.map(m=>m.cursor),[1,2,3,4]);
  assert.equal((await receiveChannelMessages(bob,4,{bulk:true})).messages.length,0);
  assert.deepEqual((await receiveChannelMessages(bob,1,{bulk:true})).messages.map(m=>m.messageId),['a','b','c']);
  assert.deepEqual((await receiveChannelMessages(alice,0,{bulk:true})).messages,[]);
  assert.equal((await channelRoom(alice,1)).gameId,(await channelRoom(bob,1)).gameId);
  assert.notEqual((await channelRoom(alice,1)).gameId,(await channelRoom(alice,2)).gameId);
});

test('a failed merged index save replays already durable source data',async t=>{
  const {alice,bob}=fixture(t);
  await sendChannelMessages(alice,[message('a','channel.0.batch'),message('b','channel.1.done')]);
  const save=PreparationCheckpointStore.prototype.save;let failed=false;
  PreparationCheckpointStore.prototype.save=async function(id,...args){
    if(!failed&&this.name==='poker-channel-inbox-bob'&&id.endsWith('/index')){failed=true;throw Error('disk full')}
    return save.call(this,id,...args);
  };
  await assert.rejects(receiveChannelMessages(bob,0,{bulk:true}),/disk full/);
  const page=await receiveChannelMessages(bob,0,{bulk:true});
  assert.deepEqual(page.messages.map(m=>m.messageId),['a','b']);
  assert.equal((await receiveChannelMessages(bob,2,{bulk:true})).messages.length,0);
});

test('dealer-only receive does not open bulk connections',async t=>{
  const {bob,rooms}=fixture(t);await receiveChannelMessages(bob,0);
  assert.equal(rooms.size,1);
});

test('payout delivery has separate streams from future-hand preparation',async t=>{
 const {alice,bob,rooms}=fixture(t);
 await sendChannelMessages(alice,[message('future','channel.0.batch'),message('payout','channel.payout.0.batch'),message('other','channel.payout.1.done')]);
 const first=await receiveChannelMessages(bob,0,{bulk:true,payout:true});
 assert.deepEqual(first.messages.map(m=>m.messageId),['payout','other']);
 const rest=await receiveChannelMessages(bob,first.nextCursor,{bulk:true});
 assert.deepEqual(rest.messages.map(m=>m.messageId),['future']);
 assert.equal(rooms.size,5);
 assert.equal((await channelRoom(alice,3)).transportLane,3);
 assert.notEqual((await channelRoom(alice,1)).gameId,(await channelRoom(alice,3)).gameId);
});

 test('bulk routing keeps Wasm modules and private worker options out of socket messages',async()=>{
  const result=await channelRoom({gameId:'room',sender:'alice',playerToken:'token',inviteSecret:'invite',engine:{module:'not transport data'},secret:'private'},1);
  assert.deepEqual(Object.keys(result).sort(),['gameId','inviteSecret','playerToken','sender','transportLane']);
 });
