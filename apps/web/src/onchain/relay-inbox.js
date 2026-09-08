import {relayConnection} from './relay-socket.js';
import { PreparationCheckpointStore } from '../storage/preparation-checkpoint-store.js';
import {encodeBinary as encode,decodeBinary as decode,binaryEqual} from './binary-codec.js';
const stores=new Map();
const MAX_BATCH_BYTES=512*1024, MAX_BATCH_MESSAGES=32, BULK_WINDOW=4;
export const relayMetrics={requests:0,outgoingBytes:0,incomingMessages:0,localReads:0,coalescedPolls:0};

// Table and cryptographic workers share durable cursors and a polling deadline.
// Acknowledgements always refer to a page saved before the current request.
async function transport(room,work) {
  return navigator.locks.request(`relay-inbox/${room.gameId}/${room.sender}`,async()=>{
    const name=`poker-relay-inbox-${room.sender}`;
    if(!stores.has(name)) stores.set(name,new PreparationCheckpointStore(name));
    const store=stores.get(name),binding=room.gameId,metaId=`${binding}/index`;
    const index=await store.read('checkpoints',metaId)?decode(await store.load(metaId,binding)):
      {cursor:0,pages:[],ids:{},outgoing:[],remoteCursor:0,epoch:null};
    const save=()=>store.save(metaId,binding,encode(index));
    const pageCache=new Map();
    async function append(messages) {
      const fresh=[];
      for(const message of messages) {
        if(index.ids[message.messageId]) continue;
        index.ids[message.messageId]=true;
        fresh.push({...message,cursor:++index.cursor});
      }
      if(fresh.length) {
        const id=`${binding}/page/${index.cursor}`;
        await store.save(id,binding,encode({messages:fresh}));
        index.pages.push({id,end:index.cursor,peer:fresh.some(m=>m.sender!==room.sender),kinds:[...new Set(fresh.map(m=>m.kind))]});
        pageCache.set(id,{messages:fresh});return id;
      }
    }
    async function outgoing(entry) {
      if(entry.page) {
        if(!pageCache.has(entry.page))pageCache.set(entry.page,decode(await store.load(entry.page,binding)));
        return pageCache.get(entry.page).messages.find(m=>m.messageId===entry.messageId);
      }
      return decode(await store.load(`${binding}/outgoing/${entry.messageId}`,binding));
    }
    // Replaying is needed only after a relay epoch change. It is batched and
    // retains original order, including when a new message was queued offline.
    async function request(excluded=new Set()) {
      if(!room.inviteSecret) throw new Error('The table invitation is missing');
      const batch=[];let bytes=0;
      for(const entry of index.outgoing) {
        if(excluded.has(entry.messageId)) continue;
        if(entry.epoch && entry.epoch===index.epoch) continue;
        const message=await outgoing(entry);
        if(batch.length && (batch.length>=MAX_BATCH_MESSAGES || bytes+message.payload.length>MAX_BATCH_BYTES)) break;
        batch.push({messageId:message.messageId,kind:message.kind,payload:message.payload});bytes+=message.payload.length;
      }
      const body={playerToken:room.playerToken,inviteSecret:room.inviteSecret,sender:room.sender,
        epoch:index.epoch,after:index.remoteCursor,messages:batch};
      relayMetrics.requests++;relayMetrics.outgoingBytes+=encode(body).length;
      return body;
    }
    async function apply(body,{page,revision}) {
      // Ordered socket responses may omit messages already sent as pushes.
      // Persist every earlier push before acknowledging the response cursor.
      while(await pushed()) {}
      // A pushed page may have been saved while the upload was in flight.
      // Do not roll a newer observed relay epoch back to an older response.
      if(index.epoch!==body.epoch && index.epoch!==page.epoch)return false;
      index.socketRevision=revision;
      index.ackSent=body.epoch===page.epoch?body.after:0;
      const changed=index.epoch!==page.epoch;
      index.epoch=page.epoch;index.joined=changed?page.joined:index.joined||page.joined;
      // A known stale epoch accepts no uploads. A first subscription may upload
      // immediately; in either case only explicit accepted IDs advance replay.
      const accepted=new Set(page.accepted);
      for(const entry of index.outgoing) if(accepted.has(entry.messageId)) entry.epoch=page.epoch;
      const before=index.cursor;await append(page.messages);
      relayMetrics.incomingMessages+=index.cursor-before;
      index.remoteCursor=changed?page.nextCursor:Math.max(index.remoteCursor,page.nextCursor);
      await save();
      if(index.remoteCursor>index.ackSent) {
        await relayConnection.discard(room,{epoch:page.epoch,after:index.remoteCursor});
        index.ackSent=index.remoteCursor;await save();
      }
      return changed;
    }
    async function pushed() {
      const page=await relayConnection.take(room);if(!page)return false;
      // A push is only delivery, never a persistence acknowledgement.
      const changed=index.epoch!==page.epoch;
      if(changed){index.epoch=page.epoch;index.remoteCursor=0;index.ackSent=0;index.joined=false;}
      const before=index.cursor;await append(page.messages);relayMetrics.incomingMessages+=index.cursor-before;
      index.remoteCursor=Math.max(index.remoteCursor,page.nextCursor);index.joined=index.joined||page.joined;
      index.socketRevision=page.socketRevision;
      await save();await relayConnection.discard(room,{epoch:page.epoch,after:index.remoteCursor});
      index.ackSent=index.remoteCursor;await save();
      return true;
    }
    async function read(after,kindPrefix) {
      const messages=[];let cursor=after;
      const skip=end=>{
        cursor=end;
        if(messages.at(-1)?.kind==='transport.skip')messages.at(-1).cursor=end;
        else messages.push({cursor:end,sender:room.sender,kind:'transport.skip'});
      };
      for(const entry of index.pages) {
        if(entry.end<=cursor)continue;
        if(kindPrefix && (entry.peer===false || entry.kinds && !entry.kinds.some(kind=>kind.startsWith(kindPrefix))))skip(entry.end);
        else {
          const page=decode(await store.load(entry.id,binding));
          for(const message of page.messages) {
            if(message.cursor<=cursor)continue;
            if(kindPrefix && (message.sender===room.sender || !message.kind.startsWith(kindPrefix)))skip(message.cursor);
            else {messages.push(message);cursor=message.cursor;}
            if(messages.length>=64)break;
          }
        }
        if(messages.length>=64)break;
      }
      return {messages,nextCursor:cursor};
    }
    return work({index,store,binding,save,append,outgoing,request,apply,read,pushed});
  });
}

// Serialize uploads independently of the durable inbox. A slow upload must
// not prevent the dealer or verifier from consuming already-arrived peer data.
async function exchange(room,{wait=true,needed=()=>true}={}) {
  return navigator.locks.request(`relay-exchange/${room.gameId}/${room.sender}`,{ifAvailable:!wait},async lock=>{
    if(!lock)return null;
    const bodies=await transport(room,async context=>{
      if(!await needed(context))return [];
      const status=await relayConnection.status(room);
      // Subscribe/reconnect serially. Once authenticated, keep a small upload
      // window in flight instead of paying a full RTT for each 512 KiB packet.
      // Control messages retain their separate connection and single request.
      const count=room.transportLane && context.index.joined && status.subscribed &&
        status.revision===context.index.socketRevision ? BULK_WINDOW : 1;
      const bodies=[],excluded=new Set();
      for(let i=0;i<count;i++) {
        const body=await context.request(excluded);
        if(i && !body.messages.length)break;
        bodies.push(body);for(const message of body.messages)excluded.add(message.messageId);
        if(!body.messages.length)break;
      }
      return bodies;
    });
    if(!bodies.length)return null;
    // All bytes are already durable. Consume responses in upload order, and
    // acknowledge only after apply() has also saved every preceding push.
    const responses=bodies.map(body=>relayConnection.exchange(room,body)
      .then(response=>({response}),error=>({error})));
    let changed=false;
    for(let i=0;i<bodies.length;i++) {
      const result=await responses[i];if(result.error)throw result.error;
      changed=await transport(room,context=>context.apply(bodies[i],result.response)) || changed;
    }
    return changed;
  });
}
const delivered=(index,messages)=>messages.every(m=>index.outgoing.find(e=>e.messageId===m.messageId)?.epoch===index.epoch && index.epoch);

export async function sendRelayMessages(room,messages) {
  if(!messages.length) return true;
  if(messages.some(m=>!(m.payload instanceof Uint8Array))) throw new Error('Expected binary relay payload');
  await transport(room,async({index,save,append,outgoing})=>{
    const fresh=new Map();
    for(const message of messages) {
      const old=index.outgoing.find(e=>e.messageId===message.messageId);
      if(!old && index.ids[message.messageId])throw new Error('Outgoing message identity conflict');
      const previous=old?await outgoing(old):fresh.get(message.messageId);
      if(previous) {
        if(previous.kind!==message.kind || !binaryEqual(previous.payload,message.payload)) throw new Error('Outgoing message identity conflict');
        continue;
      }
      fresh.set(message.messageId,{...message,sender:room.sender});
    }
    if(fresh.size) {
      const page=await append([...fresh.values()]);
      for(const message of fresh.values())index.outgoing.push({messageId:message.messageId,page});
      await save();
    }
  });
  while(true) {
    let waiting=false;
    await exchange(room,{needed:async({index,pushed})=>{
      while(await pushed()){}
      if(delivered(index,messages))return false;
      const status=await relayConnection.status(room);
      waiting=index.joined===false && status.subscribed && status.revision===index.socketRevision;
      return !waiting;
    }});
    const state=await transport(room,({index})=>({done:delivered(index,messages),joined:index.joined}));
    if(state.done)return true;
    if(waiting || !state.joined)return false;
  }
}
export const sendRelayMessage=(room,message)=>sendRelayMessages(room,[message]);

export async function receiveRelayMessages(room,after,{force=false,kindPrefix}={}) {
  const {local,needed}=await transport(room,async({index,read,pushed})=>{
    while(await pushed()) {}
    const local=await read(after,kindPrefix);
    if(local.messages.length) {relayMetrics.localReads++;return {local,needed:false};}
    const status=await relayConnection.status(room);
    const replay=index.joined && index.outgoing.some(e=>!e.epoch || e.epoch!==index.epoch);
    const needed=force || !status.subscribed || status.revision!==index.socketRevision || index.ackSent!==index.remoteCursor || replay;
    if(!needed)relayMetrics.coalescedPolls++;
    return {local,needed};
  });
  if(!needed)return local;
  const changed=await exchange(room,{wait:force});
  if(changed && await transport(room,({index})=>index.joined && index.outgoing.some(e=>e.epoch!==index.epoch)))await exchange(room,{wait:force});
  return transport(room,async({read,pushed})=>{while(await pushed()){}return read(after,kindPrefix);});
}
