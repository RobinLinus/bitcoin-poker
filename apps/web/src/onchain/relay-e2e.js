import {binaryEqual} from './binary-codec.js';
import {sendRelayMessages,sendRelayMessage,receiveRelayMessages,relayMetrics} from './relay-inbox.js';
import {relayConnection,releaseRelayRoom} from './relay-socket.js';
const output=document.querySelector('#result'),run=document.querySelector('#run'),resume=document.querySelector('#resume');
const random=()=>Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
const delay=ms=>new Promise(r=>setTimeout(r,ms));
let alice,bob,report,messages;
const show=()=>output.textContent=JSON.stringify(report,null,2);
const check=(value,message)=>{if(!value)throw new Error(message);};
async function drain(room,after,target) {
 const received=[],deadline=Date.now()+15000;
 while(after<target) {
  if(Date.now()>deadline)throw new Error('Delivery timed out');
  const page=await receiveRelayMessages(room,after);received.push(...page.messages);after=page.nextCursor;
  if(!page.messages.length)await delay(10);
 }
 return received;
}
run.onclick=async()=>{
 run.disabled=true;report={status:'Running'};show();
 try {
  alice={gameId:random(),sender:'alice',playerToken:random(),inviteSecret:random()};bob={...alice,sender:'bob',playerToken:random()};
  await receiveRelayMessages(alice,0);await receiveRelayMessages(bob,0);
  messages=Array.from({length:100},()=>({messageId:random(),kind:'channel.batch',payload:new Uint8Array(8192).fill(120)}));
  const before=relayMetrics.requests,start=performance.now();
  await sendRelayMessages(alice,messages);
  report.uploadExchanges=relayMetrics.requests-before;check(report.uploadExchanges===4,'Batch uploads used extra round trips');
  const received=await drain(bob,0,100);
  check(received.length===100 && received.every((m,i)=>m.messageId===messages[i].messageId && binaryEqual(m.payload,messages[i].payload)),'Delivery mismatch');
  await drain(alice,0,100);
  report.deliveryMs=performance.now()-start;
  check(relayMetrics.incomingMessages===100,'Sender downloaded its own payloads');
  for(let i=0;i<3;i++){await receiveRelayMessages(alice,100);await receiveRelayMessages(bob,100);await delay(50);}
  const idle=relayMetrics.requests;
  for(let i=0;i<100;i++){await receiveRelayMessages(alice,100);await receiveRelayMessages(bob,100);}
  report.idleExchanges=relayMetrics.requests-idle;check(report.idleExchanges===0,'Idle polling still uses the network');
  report.socket=await relayConnection.stats();check(report.socket.connections===1,'Rooms did not share a WebSocket');
  report.status='Ready for relay restart';show();resume.disabled=false;
 }catch(error){report.status='FAIL';report.error=error.message;show();run.disabled=false;}
};
resume.onclick=async()=>{
 resume.disabled=true;
 try {
  await receiveRelayMessages(bob,100);
  const next={messageId:random(),kind:'channel.frame',payload:new Uint8Array([1,2,3])};
  await sendRelayMessage(alice,next);
  const received=await drain(bob,100,101);
  check(received.length===1 && received[0].messageId===next.messageId,'Replay duplicated or lost delivery');
  report.socketAfterRestart=await relayConnection.stats();report.status='PASS';show();
 }catch(error){report.status='FAIL';report.error=error.message;show();}
 finally{releaseRelayRoom(alice);releaseRelayRoom(bob);run.disabled=false;}
};
