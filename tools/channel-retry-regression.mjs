// Real authenticated Wasm frames, public deterministic fixture; no relay/funds.
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {advanceDealerRetry} from '../apps/web/src/onchain/dealer-progress.js';
const encode=v=>new TextEncoder().encode(JSON.stringify(v));
const decode=v=>JSON.parse(new TextDecoder().decode(v));
const module=await WebAssembly.compile(await readFile('apps/web/public/wasm/session.wasm'));
async function client() {
 const {exports:e}=await WebAssembly.instantiate(module,{});
 return (op,bytes=new Uint8Array())=>{
  const p=e.session_input(bytes.length);new Uint8Array(e.memory.buffer,p,bytes.length).set(bytes);
  if(!e.session_call(op)) throw new Error(new TextDecoder().decode(new Uint8Array(e.memory.buffer,e.session_error_ptr(),e.session_error_len())));
  return new Uint8Array(e.memory.buffer,e.session_output_ptr(),e.session_output_len()).slice();
 };
}
let exercised=false;
for(let nonce=1;nonce<=12 && !exercised;nonce++) {
 const players=await Promise.all([client(),client()]);
 const seeds=[Array(32).fill(3),Array(32).fill(5)];
 seeds.sort((a,b)=>Buffer.compare(Buffer.from(decode(players[0](2,Uint8Array.from(a))).identity),Buffer.from(decode(players[0](2,Uint8Array.from(b))).identity)));
 const keys=seeds.map(s=>decode(players[0](2,Uint8Array.from(s))));
 const terms={regtest:true,identities:keys.map(k=>k.identity),reveal_keys:[keys[1].reveal,keys[0].reveal],origin:'01'.repeat(32)+':0',origin_value:44600,nonce:Array(32).fill(nonce),full:true,fee_multiplier:0.1,csv:12,stacks:[20000,20000],button:0};
 players.forEach((call,i)=>call(60,encode({seed:seeds[i],terms,contest_blocks:6})));
 const setup=(i,op,bytes=new Uint8Array(),owner=0)=>players[i](61,Uint8Array.from([owner,op,...bytes]));
 const both=(i,op,bytes)=>{for(let owner=0;owner<2;owner++)setup(i,op,bytes,owner);};
 for(let round=0;round<30;round++) {
  if(players.every((_,i)=>decode(setup(i,7)).accepted)) break;
  const outgoing=players.map((_,i)=>{const bytes=setup(i,3);assert.deepEqual(setup(i,3,new Uint8Array(),1),bytes);return bytes;});
  outgoing.forEach((bytes,i)=>{if(bytes.length)both(i,4,bytes);});
  if(outgoing[1].length)both(0,5,outgoing[1]);
  if(decode(setup(0,7)).retry) {
   const previous=decode(setup(0,7)).attempt;
   await advanceDealerRetry((...args)=>setup(0,...args),async()=>{});
   const next=setup(0,3);assert.deepEqual(setup(0,3,new Uint8Array(),1),next);assert.ok(next.length);both(0,4,next);
   // The slower receiver gets these two frames together in one relay page.
   both(1,5,outgoing[0]);assert.equal(decode(setup(1,7)).retry,true);
   assert.throws(()=>setup(1,5,next),/protocol stage/);
   let persisted=false;
   await advanceDealerRetry((...args)=>setup(1,...args),async()=>{persisted=true;});
   assert.equal(persisted,true);both(1,5,next);
   for(let owner=0;owner<2;owner++) assert.equal(decode(setup(1,7,new Uint8Array(),owner)).attempt,previous+1);
   exercised=true;console.log(`PASS: queued retry frame accepted only after durable retry advancement (fixture nonce ${nonce})`);
   break;
  }
  if(outgoing[0].length)both(1,5,outgoing[0]);
 }
}
assert.ok(exercised,'Fixture did not exercise a rejected shuffle');
