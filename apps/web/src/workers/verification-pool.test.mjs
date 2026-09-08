import test from "node:test";
import assert from "node:assert/strict";
import {VerificationPool} from "./verification-pool.js";
class FakeWorker {
  messages = []; terminated = false;
  postMessage(message) { this.messages.push(message); }
  reply(bytes = new Uint8Array([1])) { const message=this.messages.shift(); this.onmessage({data:{id:message.id,bytes,elapsedMs:1,memoryBytes:64}}); }
  terminate() { this.terminated = true; }
}
test("role ownership, verification priority and cancellation", async () => {
  const workers=[];
  const pool=new VerificationPool("test",{count:2,createWorker:()=>{const worker=new FakeWorker();workers.push(worker);return worker;}});
  const initialized=pool.initialize({},new Uint8Array(),new Uint8Array(32));workers.forEach(w=>w.reply());await initialized;
  const first=pool.submit(0,"sign",new Uint8Array([1]));
  const later=pool.submit(0,"sign",new Uint8Array([2]));
  const verification=pool.submit(0,"verify",new Uint8Array([3]));
  assert.equal(workers[1].messages.length,0);
  workers[0].reply();await first;
  assert.equal(workers[0].messages[0].mode,"verify");workers[0].reply();await verification;
  assert.equal(workers[0].messages[0].mode,"sign");workers[0].reply();await later;
  const cancelled=pool.submit(1,"sign",new Uint8Array([4]));
  pool.close();await assert.rejects(cancelled,/closed/);assert.ok(workers.every(w=>w.terminated));
});
test("unexpected worker responses fail all outstanding work", async()=>{
  const workers=[];
  const pool=new VerificationPool("test",{count:2,createWorker:()=>{const worker=new FakeWorker();workers.push(worker);return worker;}});
  const initialized=pool.initialize({},new Uint8Array(),new Uint8Array(32));workers.forEach(w=>w.reply());await initialized;
  const pending=pool.submit(0,"sign",new Uint8Array([1]));
  workers[0].onmessage({data:{id:-1,bytes:new Uint8Array()}});
  await assert.rejects(pending,/Unexpected/);assert.ok(workers.every(w=>w.terminated));
});
