import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFile} from 'node:fs/promises';
import {encodeBinary,decodeBinary} from './binary-codec.js';

test('peer bytes in upload replies remain ordered and recoverable until durable ACK',async t=>{
 const sockets=[],commands=[],replies=new Map();let sequence=0;
 class Socket {
   static OPEN=1;
   constructor(){this.readyState=1;this.bufferedAmount=0;sockets.push(this);queueMicrotask(()=>this.onopen());}
   send(bytes){commands.push(decodeBinary(bytes));}
   close(){this.readyState=3;this.onclose?.();}
   receive(frame){this.onmessage({data:encodeBinary(frame)});}
 }
 const port={start(){},postMessage(data){const p=replies.get(data.id);replies.delete(data.id);data.error?p.reject(Error(data.error.message)):p.resolve(data.value);}};
 const self={location:{href:'https://example.com/src/onchain/relay-socket-worker.js'}};
 const source=(await readFile(new URL('./relay-socket-worker.js',import.meta.url),'utf8')).replace(/^import .*\n/,'');
 vm.runInNewContext(source,{self,WebSocket:Socket,URL,encodeBinary,decodeBinary,performance,setTimeout,clearTimeout});
 self.onconnect({ports:[port]});t.after(()=>sockets.forEach(s=>s.close()));
 const room={gameId:'room',sender:'alice',transportLane:1};
 const rpc=(op,body)=>new Promise((resolve,reject)=>{const id=++sequence;replies.set(id,{resolve,reject});port.onmessage({data:{id,op,room,body}});});
 const until=async n=>{for(let i=0;commands.length<n&&i<100;i++)await new Promise(r=>setImmediate(r));assert.ok(commands.length>=n);};
 const body={sender:'alice',playerToken:'token',inviteSecret:'invite',epoch:null,after:0,messages:[]};
 const page=(cursor,messages=[])=>({epoch:'epoch',joined:true,accepted:[],nextCursor:cursor,messages});
 const subscription=rpc('exchange',body);await until(1);
 const socket=sockets[0],handle=commands[0].handle;
 socket.receive({id:commands[0].id,value:page(0)});await subscription;
 const first=rpc('exchange',{...body,epoch:'epoch'}),second=rpc('exchange',{...body,epoch:'epoch'});
 await until(3);
 const message=n=>({messageId:String(n),sender:'bob',cursor:n,kind:'channel.0.batch',payload:new Uint8Array([n])});
 socket.receive({id:commands[1].id,value:page(1,[message(1)])});
 socket.receive({id:commands[2].id,value:page(2,[message(2)])});
 socket.receive({push:handle,value:page(3,[message(3)])});
 // Even without applying either upload reply, the inbox can recover all peer
 // bytes in order. It cannot acknowledge the later push while skipping replies.
 for(let cursor=1;cursor<=3;cursor++) {
   assert.equal((await rpc('take')).messages[0].cursor,cursor);
   assert.equal((await rpc('take')).messages[0].cursor,cursor,'reading is not an ACK');
   await rpc('discard',{epoch:'epoch',after:cursor});
 }
 assert.equal(await rpc('take'),null);
 assert.equal((await first).page.messages.length,0);
 assert.equal((await second).page.messages.length,0);
 assert.equal(commands.filter(c=>c.ack).length,3);
});
