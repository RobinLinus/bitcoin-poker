import {releaseRelayRoom} from './relay-socket.js';
import {sendRelayMessages as send,receiveRelayMessages as receive} from './relay-inbox.js';
import {PreparationCheckpointStore} from '../storage/preparation-checkpoint-store.js';
import {encodeBinary as encode,decodeBinary as decode} from './binary-codec.js';

const stores=new Map(),roomIds=new Map();
const laneFor=kind=>{const match=/^channel\.(payout\.)?([01])\./.exec(kind);return match?Number(match[2])+(match[1]?3:1):0;};

// Both entry acknowledgements prove both peers have saved the complete tree.
// Before this barrier the bulk log is still required to resume verification.
export function canCompactPreparationJournal(bytes) {
  if(bytes.length<12 || new TextDecoder().decode(bytes.subarray(0,8))!=='CHJOUR01') return false;
  const size=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint32(8,true);
  if(size>bytes.length-12)return false;
  try {const j=JSON.parse(new TextDecoder().decode(bytes.subarray(12,12+size)));return j.version===1 && j.entered===true && j.peer_ready===true;}
  catch{return false;}
}

// Caller has checked the authenticated, durable journal under its player lock.
// Retain control/revocation messages and all cursors/deduplication tombstones.
export async function compactChannelPreparation(room) {
  await navigator.locks.request(`channel-inbox/${room.gameId}/${room.sender}`,async()=>{
    const store=new PreparationCheckpointStore(`poker-channel-inbox-${room.sender}`),binding=room.gameId,id=`${binding}/index`;
    if(await store.read('checkpoints',id)) {
      const index=decode(await store.load(id,binding)),entries=[],deleted=[],pages=[];
      for(const page of index.pages) {
        const value=decode(await store.load(page.id,binding)),messages=value.messages.filter(m=>laneFor(m.kind)===0);
        if(messages.length)pages.push(page);else deleted.push(page.id);
        if(messages.length && messages.length!==value.messages.length)entries.push({id:page.id,binding,plaintext:encode({messages})});
      }
      index.pages=pages;
      entries.push({id,binding,plaintext:encode(index)});
      await store.saveBatch(entries,deleted);
    }
    for(const lane of [1,2,3,4]) {
      const source=await channelRoom(room,lane);
      await navigator.locks.request(`relay-inbox/${source.gameId}/${room.sender}`,async()=>{
        const inbox=new PreparationCheckpointStore(`poker-relay-inbox-${room.sender}`),binding=source.gameId,id=`${binding}/index`;
        if(!await inbox.read('checkpoints',id))return;
        const index=decode(await inbox.load(id,binding));
        const deleted=(await inbox.checkpointIds()).filter(key=>typeof key==='string' && key.startsWith(`${binding}/`) && key!==id);
        index.pages=[];index.outgoing=[];
        await inbox.saveBatch([{id,binding,plaintext:encode(index)}],deleted);
      });
    }
  });
}
export async function channelRoom(room,lane) {
  if(!lane)return room;
  if(!Number.isInteger(lane)||lane<1||lane>4)throw Error('Invalid channel transport lane');
  const context=`poker-channel-transport/v1/${room.gameId}/${lane}`;
  if(!roomIds.has(context))roomIds.set(context,crypto.subtle.digest('SHA-256',new TextEncoder().encode(context))
    .then(bytes=>Array.from(new Uint8Array(bytes),b=>b.toString(16).padStart(2,'0')).join('')));
  return {gameId:await roomIds.get(context),sender:room.sender,playerToken:room.playerToken,inviteSecret:room.inviteSecret,transportLane:lane};
}

// Each owner stream retains order and its own durable relay acknowledgement.
// The relay still sees ordinary opaque rooms, with no game-specific routing.
// Only call after the player's unactivated-journal check permits discarding a slot.
export async function discardChannelInbox(room) {
  await navigator.locks.request(`channel-inbox/${room.gameId}/${room.sender}`,async()=>{
    const merged=new PreparationCheckpointStore(`poker-channel-inbox-${room.sender}`);
    await merged.deleteCheckpoints((await merged.checkpointIds()).filter(id=>typeof id==='string'&&id.startsWith(`${room.gameId}/`)));
    await Promise.all([1,2,3,4].map(async lane=>{
      const source=await channelRoom(room,lane);
      await navigator.locks.request(`relay-inbox/${source.gameId}/${room.sender}`,async()=>{
        const inbox=new PreparationCheckpointStore(`poker-relay-inbox-${room.sender}`);
        await inbox.deleteCheckpoints((await inbox.checkpointIds()).filter(id=>typeof id==='string'&&id.startsWith(`${source.gameId}/`)));
      });
    }));
  });
}
export async function warmChannelTransport(room,{payout=false}={}) {
  await Promise.all((payout?[3,4]:[1,2]).map(async lane=>receive(await channelRoom(room,lane),0,{force:true,kindPrefix:'channel.'})));
}
export function releaseChannelRoom(room) {
  if(!room?.gameId)return;
  releaseRelayRoom(room);
  for(const lane of [1,2,3,4])void channelRoom(room,lane).then(releaseRelayRoom).catch(()=>{});
}
export async function sendChannelMessages(room,messages) {
  const groups=[[],[],[],[],[]];for(const message of messages)groups[laneFor(message.kind)].push(message);
  const results=await Promise.all(groups.map(async(group,lane)=>!group.length||await send(await channelRoom(room,lane),group)));
  return results.every(Boolean);
}

// Merge the durable source logs into a stable local cursor. Persisting this
// index lets an interrupted preparation rewind without losing another lane.
// An ACK may precede the merge because the source inbox already saved the bytes.
export async function receiveChannelMessages(room,after,{bulk=false,payout=false}={}) {
  return navigator.locks.request(`channel-inbox/${room.gameId}/${room.sender}`,async()=>{
    if(!stores.has(room.sender))stores.set(room.sender,new PreparationCheckpointStore(`poker-channel-inbox-${room.sender}`));
    const store=stores.get(room.sender),binding=room.gameId,id=`${binding}/index`;
    const index=await store.read('checkpoints',id)?decode(await store.load(id,binding)):{sources:[0,0,0,0,0],cursor:0,pages:[]};
    // Recover unread merged data before requesting another network page.
    async function read(){
      const messages=[];
      for(const page of index.pages){
        if(page.end<=after)continue;
        for(const message of decode(await store.load(page.id,binding)).messages){
          if(message.cursor>after)messages.push(message);
          if(messages.length===64)return {messages,nextCursor:messages.at(-1).cursor};
        }
      }
      return {messages,nextCursor:messages.at(-1)?.cursor??after};
    }
    const local=await read();if(local.messages.length)return local;
    const lanes=bulk?(payout?[0,3,4]:[0,1,2]):[0];
    const pages=await Promise.all(lanes.map(async lane=>({lane,page:await receive(await channelRoom(room,lane),index.sources[lane],{kindPrefix:'channel.'})})));
    const messages=[];let changed=false;
    for(const {lane,page} of pages){
      if(page.nextCursor!==index.sources[lane])changed=true;
      index.sources[lane]=page.nextCursor;
      for(const message of page.messages){
        if(message.sender===room.sender||!message.kind.startsWith('channel.'))continue;
        if(laneFor(message.kind)!==lane)throw Error('Channel message on wrong transport lane');
        messages.push({...message,cursor:++index.cursor});
      }
    }
    if(messages.length){
      const pageId=`${binding}/page/${index.cursor}`;
      await store.save(pageId,binding,encode({messages}));index.pages.push({id:pageId,end:index.cursor});
    }
    if(changed)await store.save(id,binding,encode(index));
    return read();
  });
}
