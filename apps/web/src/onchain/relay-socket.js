import {traceState,traceOperation} from './diagnostics.js';
let port,nextId=0;
const pending=new Map();
export function setRelayPort(value) {
  port=value;
  port.onmessage=({data})=>{
    const job=pending.get(data.id);if(!job)return;
    pending.delete(data.id);clearTimeout(job.timer);
    if(data.error) {const error=new Error(data.error.message);error.status=data.error.status;job.reject(error);}
    else job.resolve(data.value);
  };
  port.start();
}
// A shared worker can outlive every individual page reload. Incompatible
// transport changes require a new identity, even when other app tabs stay open.
function connection() {
  if(!port) setRelayPort(new SharedWorker(new URL('./relay-socket-worker.js',import.meta.url),{type:'module',name:'poker-relay-priority-v2'}).port);
  return port;
}
function call(op,room,body) {
  return new Promise((resolve,reject)=>{
    const id=++nextId,timer=setTimeout(()=>{pending.delete(id);reject(new Error('Relay worker timed out'));},45000);pending.set(id,{resolve,reject,timer});
    try {connection().postMessage({id,op,room,body});}catch(error){pending.delete(id);clearTimeout(timer);reject(error);}
  });
}
export function createRelayPort() {
  const channel=new MessageChannel();
  connection().postMessage({op:'attach',port:channel.port1},[channel.port1]);
  return channel.port2;
}
export function releaseRelayRoom(room) {
  if(port && room?.gameId) void call('release',{gameId:room.gameId,sender:room.sender,transportLane:room.transportLane}).catch(()=>{});
}
export const relayConnection={
  stats:()=>call('stats',{}),
  prioritizePayout:(room,active)=>call('priority',{gameId:room.gameId,sender:room.sender},{active}),
  exchange:async(room,body)=>{
    const context={gameId:room.gameId,sender:room.sender,transportLane:room.transportLane};
    const end=traceOperation('relay.exchange',{...context,messages:body.messages.length,bytes:body.messages.reduce((n,m)=>n+m.payload.length,0)},true);
    try {
      const result=await call('exchange',context,body);end();
      traceState(`relay/${room.gameId}/${room.sender}`,'relay.state',{...context,joined:result.page.joined,epoch:result.page.epoch});
      return result;
    } catch(error){end(error);throw error;}
  },
  take:room=>call("take",room),
  discard:(room,body)=>call("discard",room,body),
  status:async room=>{
    const context={gameId:room.gameId,sender:room.sender,transportLane:room.transportLane},status=await call('status',context);
    traceState(`connection/${room.gameId}/${room.sender}`,'relay.connection',{...context,subscribed:status.subscribed});
    return status;
  },
};
