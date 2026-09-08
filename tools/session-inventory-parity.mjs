// Public deterministic fixture only. Compare full channel inventories across builds.
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const encode=value=>new TextEncoder().encode(JSON.stringify(value));
const decode=bytes=>JSON.parse(new TextDecoder().decode(bytes));
async function client(path) {
  const {instance:{exports:e}}=await WebAssembly.instantiate(await readFile(path),{});
  return (op,bytes=new Uint8Array())=>{
    const p=e.session_input(bytes.length);new Uint8Array(e.memory.buffer,p,bytes.length).set(bytes);
    if(!e.session_call(op)) throw new Error(new TextDecoder().decode(new Uint8Array(e.memory.buffer,e.session_error_ptr(),e.session_error_len())));
    return new Uint8Array(e.memory.buffer,e.session_output_ptr(),e.session_output_len()).slice();
  };
}
const old=process.argv[2]??'target/readiness-original.wasm', next=process.argv[3]??'apps/web/public/wasm/session.wasm';
const players=await Promise.all([client(old),client(old)]);
const seeds=[Array(32).fill(3),Array(32).fill(5)];
seeds.sort((a,b)=>Buffer.compare(Buffer.from(decode(players[0](2,Uint8Array.from(a))).identity),Buffer.from(decode(players[0](2,Uint8Array.from(b))).identity)));
const keys=seeds.map(seed=>decode(players[0](2,Uint8Array.from(seed))));
const terms={regtest:true,identities:keys.map(k=>k.identity),reveal_keys:[keys[1].reveal,keys[0].reveal],
  origin:'01'.repeat(32)+':0',origin_value:44600,nonce:Array(32).fill(7),full:true,fee_multiplier:0.1,csv:12,stacks:[20000,20000],button:0};
players.forEach((call,i)=>call(60,encode({seed:seeds[i],terms,contest_blocks:6})));
const setup=(i,owner,op,payload=new Uint8Array())=>players[i](61,Uint8Array.from([owner,op,...payload]));
for(let owner=0;owner<2;owner++) {
  for(let step=0;step<500;step++) {
    const status=players.map((_,i)=>decode(setup(i,owner,7)));
    if(status.every(s=>s.accepted)) break;
    if(status.every(s=>s.retry)) {players.forEach((_,i)=>setup(i,owner,6,encode(status[0].attempt+1)));continue;}
    const outgoing=players.map((_,i)=>setup(i,owner,3));
    outgoing.forEach((bytes,i)=>{if(bytes.length){setup(i,owner,4,bytes);setup(1-i,owner,5,bytes);}});
    if(step===499) throw new Error('Deal did not finish');
  }
  const scores=players.map((_,i)=>setup(i,owner,8));
  players.forEach((_,i)=>setup(i,owner,9,scores[1-i]));
  const commitments=players.map((_,i)=>setup(i,owner,52));
  players.forEach((_,i)=>setup(i,owner,53,commitments[1-i]));
  const snapshot=setup(0,owner,16);
  const inventories=[];
  for(const path of [old,next]) {
    const call=await client(path),start=performance.now();
    call(17,snapshot);const restored=performance.now();call(10);const built=performance.now();const inventory=call(11);inventories.push(inventory);
    console.log(JSON.stringify({owner,path,restoreMs:restored-start,buildMs:built-restored,ms:performance.now()-start,bytes:inventory.length,sha256:createHash('sha256').update(inventory).digest('hex')}));
  }
  assert.deepEqual(inventories[1],inventories[0],`owner ${owner} full inventory changed`);
  for(let role=0;role<2;role++) {
    const metadata=encode({key:Array.from(setup(role,owner,13)),material:decode(setup(role,owner,12)),regtest:true});
    const frame=new Uint8Array(4+metadata.length+inventories[0].length);
    new DataView(frame.buffer).setUint32(0,metadata.length,true);frame.set(metadata,4);frame.set(inventories[0],4+metadata.length);
    const workers=await Promise.all([client(old),client(next)]);
    for(const call of workers) call(34,frame);
    const manifest=workers[0](33),indices=[];let ordinary=0,reveals=0;
    for(let i=0;i<manifest.length/2;i++) if(manifest[2*i]===role) {
      if(manifest[2*i+1] ? reveals++<16 : ordinary++<4) indices.push(i);
    }
    const input=new Uint8Array(indices.length*4),view=new DataView(input.buffer);
    indices.forEach((index,i)=>view.setUint32(i*4,index,true));
    const responses=workers.map(call=>call(31,input));
    assert.deepEqual(responses[1],responses[0],'canonical generated signatures changed');
    assert.deepEqual(workers[1](32,responses[0]),workers[0](32,responses[1]),'cross-backend verification differs');
    responses[0][responses[0].length-1]^=1;
    assert.throws(()=>workers[1](32,responses[0]),/malformed|invalid|mismatched/);
  }
}
console.log('Both complete owner inventories and sampled ordinary/adaptor batches match byte for byte; cross-verification and corruption rejection pass.');
