import test from 'node:test';
import assert from 'node:assert/strict';
import {Rpc,workerFailure} from './wasm-client.js';
test('an empty browser worker error retains its worker identity and rejects pending work',async t=>{
 const original=globalThis.Worker;let worker;
 globalThis.Worker=class {constructor(){worker=this;}postMessage(){}terminate(){this.terminated=true;}};
 t.after(()=>{globalThis.Worker=original});
 const rpc=new Rpc('construction-worker.js'),pending=rpc.call('construct');
 let prevented=false;worker.onerror({message:'',preventDefault(){prevented=true;}});
 await assert.rejects(pending,/Worker failed: construction-worker.js: Worker could not start/);
 assert.equal(worker.terminated,true);
 assert.equal(prevented,true);
});
test('an unavailable versioned module requires a reload without loading replacement code',async t=>{
 const original=globalThis.fetch,requests=[];t.after(()=>{globalThis.fetch=original});
 globalThis.fetch=async(url,options)=>{requests.push({url:String(url),options});return {status:404};};
 const url=`https://example.test/assets/${'a'.repeat(64)}/src/onchain/construction-worker.js`;
 assert.match((await workerFailure(url,'')).message,/^Worker app file unavailable/);
 assert.equal(requests.length,1);assert.equal(requests[0].url,url);assert.equal(requests[0].options.method,'HEAD');
 globalThis.fetch=async()=>({status:200});
 assert.match((await workerFailure(url,'crashed')).message,/^Worker failed: construction-worker.js: crashed/);
});
