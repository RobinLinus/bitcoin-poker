import test from 'node:test';
import assert from 'node:assert/strict';
import {Rpc} from './wasm-client.js';
test('empty worker errors reject initialization instead of resolving undefined',async()=>{
 const Previous=globalThis.Worker;
 globalThis.Worker=class { postMessage({id}) { queueMicrotask(()=>this.onmessage({data:{id,error:''}})); } terminate(){} };
 try {const rpc=new Rpc('test');await assert.rejects(rpc.call('init'),/Worker request failed/);assert.equal(rpc.jobs.size,0);rpc.close();}finally{globalThis.Worker=Previous;}
});
test('background worker diagnostics reach the main log without becoming progress',async()=>{
 const Previous=globalThis.Worker,info=console.info,lines=[];
 globalThis.Worker=class { postMessage({id}) {queueMicrotask(()=>{this.onmessage({data:{event:'diagnostic',entry:{timestamp:'2026-09-07T12:00:00.000Z',event:'relay.state',joined:true}}});this.onmessage({data:{id,value:true}})})} terminate(){} };
 console.info=line=>lines.push(line);
 try {const rpc=new Rpc('channel-worker.js');rpc.diagnostics.gameId='public-game';rpc.onprogress=()=>assert.fail('diagnostic was interpreted as progress');assert.equal(await rpc.call('view'),true);assert.ok(lines.some(line=>line.includes('relay.state')&&line.includes('public-game')));rpc.close();}finally{globalThis.Worker=Previous;console.info=info;}
});
test('calls on failed preloaded workers reject instead of hanging',async()=>{
 const Previous=globalThis.Worker;
 globalThis.Worker=class {postMessage(){assert.fail('closed worker was used')}terminate(){}};
 try {const rpc=new Rpc('test');rpc.close(new Error('load failed'));await assert.rejects(rpc.call('init'),/load failed/);}finally{globalThis.Worker=Previous;}
});
test('concurrent worker initialization shares one verified compiled module',async()=>{
 const previous=globalThis.fetch;
 const bytes=new Uint8Array([0,97,115,109,1,0,0,0]);
 const sha256=Buffer.from(await crypto.subtle.digest('SHA-256',bytes)).toString('hex');
 let requests=0;
 globalThis.fetch=async url=>{requests++;return url.endsWith('.json')?Response.json({schemaVersion:1,artifacts:[{name:'session',url:'/wasm/session.wasm',sha256,sizeBytes:8,securityBoundary:'fixture'}]}):new Response(bytes);};
 try {
  const {sessionEngine}=await import('./wasm-client.js');
  const [a,b]=await Promise.all([sessionEngine(),sessionEngine()]);
  assert.equal(a,b);assert.ok(a.module instanceof WebAssembly.Module);assert.equal(a.digest,sha256);assert.equal(requests,2);
 }finally{globalThis.fetch=previous;}
});
