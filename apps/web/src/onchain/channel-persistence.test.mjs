import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {encodeBinary,decodeBinary} from './binary-codec.js';

// Exercise the worker's actual persistence boundary with delayed storage. The
// browser regression separately checks the underlying IndexedDB transaction.
const source=await readFile(new URL('./channel-worker.js',import.meta.url),'utf8');
const boundary=source.slice(source.indexOf('let persistence='),source.indexOf('async function restore('));
function fixture(store) {
 const state={sequence:1},record={cursor:1},room={gameId:'ab'.repeat(32)};
 const engine={call:op=>encodeBinary({sequence:op===69?state.sequence:0})};
 const build=new Function('store','engine','record','room','encodeBinary','hash',`
 let terms={},artifactDirty=true,journalDirty=true,halted=false,fatalError,preparationMetrics;
 const traceOperation=()=>()=>{};
 ${boundary}
 return {persist,record,change(){record.cursor=2;journalDirty=true;},get halted(){return halted}};
 `);
 return {state,...build(store,engine,record,room,encodeBinary,async bytes=>createHash('sha256').update(bytes).digest('hex'))};
}
test('overlapping delivery checkpoints retain fresh cursors and export matching journals',async()=>{
 const batches=[],ids=new Set();let release,started;
 const blocked=new Promise(resolve=>{started=resolve});
 const store={checkpointIds:async()=>[...ids],saveBatch:async(entries,deleted)=>{
  batches.push(entries);
  if(batches.length===1){started();await new Promise(resolve=>{release=resolve})}
  for(const id of deleted)ids.delete(id);for(const e of entries)ids.add(e.id);
 }};
 const f=fixture(store),first=f.persist();await blocked;
 f.state.sequence=2;f.change();const second=f.persist();release();await Promise.all([first,second]);
 assert.equal(f.record.cursor,2);
 assert.equal(batches.length,2);
 for(const [index,entries] of batches.entries()) {
  const journal=decodeBinary(entries.find(e=>e.id.includes('/journal/')).plaintext);
  const metadata=decodeBinary(entries.at(-1).plaintext);
  assert.equal(metadata.cursor,index+1);assert.equal(journal.sequence,index+1);
 }
 assert.equal([...ids].filter(id=>id.includes('/journal/')).length,1);
});
test('failed checkpoint replacement halts without publishing new recovery references',async()=>{
 const f=fixture({checkpointIds:async()=>[],saveBatch:async()=>{throw new DOMException('','QuotaExceededError')}});
 await assert.rejects(f.persist(),{name:'QuotaExceededError'});
 assert.equal(f.record.artifact,undefined);assert.equal(f.record.journal,undefined);
 await assert.rejects(f.persist(),/QuotaExceededError/);
});
