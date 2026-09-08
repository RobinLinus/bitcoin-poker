import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {encode,decode} from './wasm-client.js';

// Exercise the actual worker dispatch boundary. The native retirement guard
// must remain effective while out-of-order transport is retained durably.
const source=await readFile(new URL('./channel-worker.js',import.meta.url),'utf8');
const advance=source.slice(source.indexOf('async function advance('),source.indexOf('async function command('));
const message=(cursor,kind)=>({sender:'bob',kind:'channel.frame',cursor,payload:encode({[kind]:{}})});
function fixture(incoming=[],saved) {
  const record=structuredClone(saved??{entrySent:true,cursor:0,deferred:[]});
  const view={playAllowed:false,channelReady:false},accepted=[],snapshots=[];
  const engine={call(op,bytes){
    if(op===73)return encode(false);
    assert.equal(op,63);
    const kind=Object.keys(decode(bytes))[0];
    if(['Move','Ack'].includes(kind)&&!view.playAllowed)throw Error('previous hand not retired');
    if(kind==='Invalid')throw Error('invalid frame');
    if(kind==='Ready')view.channelReady=true;
    accepted.push(kind);return encode(null);
  }};
  const build=new Function('record','engine','decode','publicView','messages','persist',`
    const room={sender:'alice',gameId:'candidate'};
    let cachedView,journalDirty;
    const trace=()=>{},flush=async()=>{},send=async()=>{},watch=async()=>{};
    const messageBytes=message=>message.payload,advancedView=async()=>publicView();
    ${advance}
    return advance;
  `);
  const run=build(record,engine,decode,()=>view,async()=>incoming.splice(0),async()=>snapshots.push(structuredClone(record)));
  return {run,record,view,accepted,snapshots};
}

test('early next-hand play waits durably while entry acknowledgements still progress',async()=>{
  const f=fixture([message(1,'Move'),message(2,'Ready'),message(3,'Ack')]);
  await f.run();
  assert.deepEqual(f.accepted,['Ready']);assert.equal(f.view.channelReady,true);
  assert.equal(f.record.cursor,3);assert.deepEqual(f.record.deferred.map(m=>m.cursor),[1,3]);
  assert.deepEqual(f.snapshots.at(-1).deferred,f.record.deferred);
  await f.run();assert.deepEqual(f.accepted,['Ready'],'polling cannot bypass the retirement guard');
  f.view.playAllowed=true;await f.run();
  assert.deepEqual(f.accepted,['Ready','Move','Ack']);assert.deepEqual(f.record.deferred,[]);
  await f.run();assert.deepEqual(f.accepted,['Ready','Move','Ack'],'early frames are accepted once');
});

test('reconnect retains an early play message past the transport cursor',async()=>{
  const f=fixture([message(4,'Move')]);await f.run();
  const restored=fixture([],f.snapshots.at(-1));
  await restored.run();assert.deepEqual(restored.accepted,[]);
  restored.view.playAllowed=true;await restored.run();
  assert.deepEqual(restored.accepted,['Move']);assert.equal(restored.record.cursor,4);
});

test('invalid frames remain errors rather than being treated as handover timing',async()=>{
  const f=fixture([message(1,'Invalid')]);
  await assert.rejects(f.run(),/invalid frame/);assert.deepEqual(f.record.deferred,[]);
});
