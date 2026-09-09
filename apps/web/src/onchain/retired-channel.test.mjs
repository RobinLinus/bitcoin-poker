import test from 'node:test';
import assert from 'node:assert/strict';
import {compactRetiredChannel} from './channel-inbox.js';
import {encodeBinary,decodeBinary} from './binary-codec.js';
const oldId='aa'.repeat(32),nextId='bb'.repeat(32),encode=value=>new TextEncoder().encode(JSON.stringify(value));
const hash=async bytes=>Buffer.from(await crypto.subtle.digest('SHA-256',bytes)).toString('hex');
async function fixture(change=()=>{}) {
  const hand=Array(32).fill(7),body=encode({hand}),certificate=[...body,...Array(32).fill(0)];
  const parent={version:1,entered:true,peer_ready:true,closing:false,pending:null,accepted:[{},{}],handoff:{watched:true,peer_ack:true,next:hand},entry_authorization:[1],play_authorization:certificate};
  const child={version:1,entered:true,peer_ready:true,entry_authorization:[1],play_authorization:certificate};
  const seed=Uint8Array.of(1,2,3),terms={origin:'funding:0',slot:{index:1}};
  const old={seed,terms,outbox:[],cursor:12,artifact:'cc'.repeat(32),commitments:new Uint8Array(2000)};
  const next={seed,terms:{...terms,slot:{index:2}},artifact:'dd'.repeat(32)};
  const defense={version:1,funding:'funding:0',revision:13,paths:[[],[]],penalties:[[1,2,3]]};
  const f={parent,child,old,next,defense};change(f);
  const records=new Map();
  for(const [id,record,header] of [[oldId,old,parent],[nextId,next,child]]) {
    const metadata=encode(header),journal=new Uint8Array(12+metadata.length);
    journal.set(new TextEncoder().encode('CHJOUR01'));new DataView(journal.buffer).setUint32(8,metadata.length,true);journal.set(metadata,12);
    record.journal=await hash(journal);records.set(`${id}/journal/${record.journal}`,journal);
    records.set(`${id}/artifact/${record.artifact}`,new Uint8Array(1000));records.set(id,encodeBinary(record));
  }
  records.set(`defense/${oldId}`,encode(defense));records.set('wallet',Uint8Array.of(99));
  const store={read:async(_,id)=>records.get(id),load:async id=>records.get(id),checkpointIds:async()=>[...records.keys()],
    saveBatch:async(entries,deletions)=>{if(store.fail)throw new DOMException('full','QuotaExceededError');for(const id of deletions)records.delete(id);for(const e of entries)records.set(e.id,e.plaintext);}};
  return {...f,records,store,run:()=>compactRetiredChannel({gameId:oldId,sender:'alice'},nextId,store)};
}
test('retired hand drops bulk artifacts only after a durable playable successor and justice package',async()=>{
  const f=await fixture(),defense=f.records.get(`defense/${oldId}`),next=f.records.get(nextId),wallet=f.records.get('wallet');
  assert.equal(await f.run(),true);
  const compact=decodeBinary(f.records.get(oldId));
  assert.equal(compact.retiredTo,nextId);assert.deepEqual(compact.seed,f.old.seed);
  assert.equal(compact.artifact,undefined);assert.equal(compact.journal,undefined);
  assert.equal([...f.records.keys()].filter(id=>id.startsWith(`${oldId}/`)).length,0);
  assert.equal(f.records.get(`defense/${oldId}`),defense);assert.equal(f.records.get(nextId),next);assert.equal(f.records.get('wallet'),wallet);
  assert.equal(await f.run(),false,'repeating cleanup does not rewrite history');
});
test('incomplete handovers and missing or stale justice evidence retain the full checkpoint',async()=>{
  for(const change of [f=>f.parent.handoff.peer_ack=false,f=>f.parent.handoff.watched=false,f=>f.parent.pending={},
    f=>f.child.play_authorization=null,f=>f.child.entered=false,f=>f.next.terms.origin='different:0',
    f=>f.next.terms.slot.index=3,f=>f.next.seed=Uint8Array.of(9),f=>f.parent.handoff.next=[9],
    f=>f.old.outbox=[{}],f=>f.defense.penalties=[],f=>f.defense.revision=9,f=>f.defense.paths=[[1],[]]]) {
    const f=await fixture(change),before=new Map(f.records);
    assert.equal(await f.run(),false);assert.deepEqual(f.records,before);
  }
});
test('a retired successor retains enough authorization evidence for out-of-order startup cleanup',async()=>{
  const f=await fixture();f.next.retiredTo='ee'.repeat(32);f.next.retiredHeader=f.child;delete f.next.journal;
  f.records.set(nextId,encodeBinary(f.next));assert.equal(await f.run(),true);
});
test('journal corruption and failed storage never delete recovery checkpoints',async()=>{
  const f=await fixture();f.store.fail=true;const before=new Map(f.records);
  await assert.rejects(f.run(),/full/);assert.deepEqual(f.records,before);
  f.store.fail=false;f.records.get(`${oldId}/journal/${f.old.journal}`)[12]^=1;
  assert.equal(await f.run(),false);assert.ok(f.records.has(`${oldId}/artifact/${f.old.artifact}`));
});
