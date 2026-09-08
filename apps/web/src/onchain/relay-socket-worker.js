import {encodeBinary,decodeBinary} from './binary-codec.js';
// Independent recovery-owner inventories use separate bounded bulk connections.
// Gameplay and dealer messages retain the control connection.
const metrics={connections:0,framesSent:0,framesReceived:0,bytesSent:0,bytesReceived:0,pushedMessages:0,queueMs:0,byPhase:{},receivedByPhase:{}};
const lanes=[],payouts=new Map();
let incomingBytes=0;
const key=room=>`${room.gameId}/${room.sender}`;
function payoutActive(){const now=performance.now();for(const [id,until] of payouts)if(until<=now)payouts.delete(id);return payouts.size>0;}
function connection(lane) { return lanes[lane] ??= createConnection(lane); }
function totals(){return lanes.reduce((n,l)=>({pending:n.pending+l.stats().pending,queued:n.queued+l.stats().queued,bytes:n.bytes+l.stats().bytes,subscriptions:n.subscriptions+l.stats().subscriptions}),{pending:0,queued:0,bytes:0,subscriptions:0});}
function createConnection(lane) {
let socket,opening,sequence=0,revision=0,nextHandle=0,draining=false;
const pending=new Map(),rooms=new Map(),queue=[];
const roomKey=room=>`${room.gameId}/${room.sender}`;
const phase=body=>body?.messages?.some(m=>m.kind==='channel.frame'||m.kind==='channel.cashout')?'play':body?.messages?.some(m=>m.kind.startsWith('channel.payout.'))?'payout':body?.messages?.some(m=>m.kind.startsWith('channel.'))?'preparation':'control';
const priority=body=>({play:0,control:0,payout:1,preparation:2})[phase(body)];
function clearPages(room){for(const item of room.pushes)incomingBytes-=item.bytes;room.pushes=[];}
function enqueuePage(room,page){
  const bytes=page.messages.reduce((n,m)=>n+m.payload.byteLength,0);
  if(room.pushes.length>=16 || incomingBytes+bytes>16*1024*1024)return false;
  room.pushes.push({page,bytes});incomingBytes+=bytes;return true;
}
function info(room){const key=roomKey(room);if(!rooms.has(key))rooms.set(key,{...room,handle:++nextHandle,revision:++revision,subscribed:false,pushes:[]});return rooms.get(key);}
function connect(){
  if(socket?.readyState===WebSocket.OPEN)return Promise.resolve(socket);if(opening)return opening;
  opening=new Promise((resolve,reject)=>{
    const url=new URL('/api/v1/socket',self.location.href);url.protocol=url.protocol==='https:'?'wss:':'ws:';
    const ws=new WebSocket(url);ws.binaryType='arraybuffer';socket=ws;metrics.connections++;
    const timer=setTimeout(()=>ws.close(),15000);
    ws.onopen=()=>{clearTimeout(timer);opening=null;resolve(ws);};
    ws.onmessage=({data})=>{
      let frame;try{frame=decodeBinary(data);}catch{ws.close();return;}
      metrics.framesReceived++;metrics.bytesReceived+=data.byteLength;
      const receivedPhase=phase(frame.value);
      metrics.receivedByPhase[receivedPhase]=(metrics.receivedByPhase[receivedPhase]??0)+data.byteLength;
      if(frame.push!==undefined){
        const room=[...rooms.values()].find(r=>r.handle===frame.push);if(!room)return;
        // A lost caller response must not create an unbounded volatile queue.
        // The inbox drains this queue before checking connection revision.
        // A delivered push is not a resync: bumping revision here forces an
        // empty round trip whenever a response already contained that push.
        if(!enqueuePage(room,frame.value)){ws.close();return;}
        metrics.pushedMessages+=frame.value.messages.length;return;
      }
      if(frame.resync!==undefined){const room=[...rooms.values()].find(r=>r.handle===frame.resync);if(room)room.revision=++revision;return;}
      const job=pending.get(frame.id);if(!job)return;pending.delete(frame.id);clearTimeout(job.timer);
      if(frame.error){const error=new Error(frame.error.message);error.status=frame.error.status;job.reject(error);}
      else {
        // Upload replies can carry peer data too. Keep them in the same ordered
        // durable-delivery queue as pushes, even if the caller disappears or a
        // later reply arrives before it saves this one. A later cursor must
        // never acknowledge an earlier, unpersisted response payload.
        const room=[...rooms.values()].find(r=>r.handle===job.handle);
        if(room && frame.value?.messages?.length){
          if(!enqueuePage(room,frame.value)){job.reject(Error('Relay receive queue full'));ws.close();return;}
          job.resolve({...frame.value,messages:[]});
        }else job.resolve(frame.value);
      }
    };
    ws.onerror=()=>ws.close();
    ws.onclose=()=>{
      clearTimeout(timer);opening=null;if(socket===ws)socket=null;
      const error=new Error('Relay connection interrupted');reject(error);
      for(const job of pending.values()){clearTimeout(job.timer);job.reject(error);}pending.clear();
      for(const job of queue.splice(0))job.reject(error);
      for(const room of rooms.values()){room.subscribed=false;clearPages(room);room.revision=++revision;}
    };
  });return opening;
}
async function drain(){
  if(draining)return;draining=true;
  try{
    while(queue.length){
      const ws=await connect();
      // Keep bounded speculative uploads behind the current hand's payout work.
      // Already sent frames finish normally; no durable messages are cancelled.
      while((lane===1||lane===2)&&payoutActive()&&ws.readyState===WebSocket.OPEN)await new Promise(r=>setTimeout(r,10));
      while(ws.bufferedAmount>64*1024 && ws.readyState===WebSocket.OPEN)await new Promise(r=>setTimeout(r,2));
      if(ws.readyState!==WebSocket.OPEN)throw Error('Relay connection interrupted');
      queue.sort((a,b)=>a.priority-b.priority||a.id-b.id);const job=queue.shift();
      if(!job.notification) {
        const timer=setTimeout(()=>{pending.delete(job.id);job.reject(Error('Relay response timed out'));ws.close();},30000);
        pending.set(job.id,{...job,timer});
      }
      metrics.framesSent++;metrics.bytesSent+=job.bytes.length;
      metrics.queueMs+=performance.now()-job.queuedAt;
      metrics.byPhase[job.phase]=(metrics.byPhase[job.phase]??0)+job.bytes.length;
      ws.send(job.bytes);
      if(job.notification)job.resolve(null);
      await Promise.resolve();
    }
  }catch(error){for(const job of queue.splice(0))job.reject(error);}
  finally{draining=false;if(queue.length)void drain();}
}
async function exchange(room,body,ack){
  await connect();
  const id=++sequence,command={id,handle:room.handle,body};
  if(ack)command.ack=ack;
  if(body){
    if(room.subscribed){command.body={...body};delete command.body.playerToken;delete command.body.inviteSecret;delete command.body.sender;}
    else command.gameId=room.gameId;
  }
  const bytes=encodeBinary(command);
  if(totals().queued+totals().pending>=128 || totals().bytes+bytes.length>24*1024*1024) throw Error('Relay queue full');
  return new Promise((resolve,reject)=>{queue.push({id,handle:room.handle,bytes,resolve,reject,notification:!!ack,priority:priority(body),phase:phase(body),queuedAt:performance.now()});void drain();});
}
async function handle(data) {
      let value;
      if(data.op==='release'){
        const key=roomKey(data.room),room=rooms.get(key);rooms.delete(key);
        if(room)clearPages(room);
        if(room?.subscribed && socket?.readyState===WebSocket.OPEN)await exchange(room,null);
      }else{
        const room=info(data.room);
        if(data.op==='status')value={revision:room.revision,subscribed:room.subscribed && socket?.readyState===WebSocket.OPEN};
        else if(data.op==='take')value=room.pushes.length?{...room.pushes[0].page,socketRevision:room.revision}:null;
        else if(data.op==='discard'){
          if(!room.subscribed)throw Error('Relay subscription interrupted');
          await exchange(room,undefined,data.body);
          room.pushes=room.pushes.filter(item=>{
            const keep=item.page.epoch!==data.body.epoch||item.page.nextCursor>data.body.after;
            if(!keep)incomingBytes-=item.bytes;return keep;
          });
        }
        else if(data.op==='exchange'){
          const observed=room.revision;const page=await exchange(room,data.body);
          room.subscribed=true;value={page,revision:observed};
        }else throw Error('Invalid relay operation');
      }
      return value;
}
return {handle,stats:()=>({subscriptions:rooms.size,pending:pending.size,queued:queue.length,bytes:queue.reduce((n,j)=>n+j.bytes.length,0)})};
}
function attach(port){
  port.onmessage=async({data})=>{
    if(data.op==='attach'){attach(data.port);return;}
    try {
      if(data.op==='priority'){
        if(data.body?.active)payouts.set(key(data.room),performance.now()+180000);else payouts.delete(key(data.room));
        port.postMessage({id:data.id,value:null});return;
      }
      if(data.op==='release')payouts.delete(key(data.room));
      const lane=data.room?.transportLane??0;
      if(!Number.isInteger(lane)||lane<0||lane>4)throw Error('Invalid relay lane');
      const value=data.op==='stats'?{...metrics,...totals()}:await connection(lane).handle(data);
      port.postMessage({id:data.id,value});
    }catch(error){port.postMessage({id:data.id,error:{message:error.message,status:error.status}});}
  };port.start();
}
self.onconnect=event=>attach(event.ports[0]);
