// Public protocol metadata only. Never pass payloads, keys, witnesses or views here.
const history=[],states=new Map();
const allowed=new Set('gameId sender background worker method stage phase percent node actor pending terminal ready active slots queued kind messages bytes received joined epoch subscribed revision durationMs operation error'.split(' '));
let sequence=0;
const scrub=value=>String(value).split('\n')[0].replace(/[A-Za-z0-9+/_=-]{40,}/g,'[redacted]').replace(/\[(?:\s*\d+\s*,){8,}[^\]]*\]/g,'[redacted]').slice(0,300);
function clean(fields) {
  return Object.fromEntries(Object.entries(fields).filter(([k,v])=>allowed.has(k)&&['string','number','boolean'].includes(typeof v)).map(([k,v])=>[k,k==='error'?scrub(v):typeof v==='string'?v.slice(0,160):v]));
}
export function acceptDiagnostic(entry) {
  const item={timestamp:entry.timestamp,event:entry.event,...clean(entry)};
  if(typeof document==='undefined' && typeof globalThis.self?.postMessage==='function') {
    self.postMessage({event:'diagnostic',entry:item});return;
  }
  const line=`[poker ${item.timestamp}] ${JSON.stringify(item)}`;
  history.push(line);if(history.length>2000)history.shift();
  console.info(line);
}
export function trace(event,fields={}) {
  acceptDiagnostic({timestamp:new Date().toISOString(),event,...clean(fields)});
}
export function traceState(key,event,fields,{heartbeat=0}={}) {
  const value=clean(fields),fingerprint=JSON.stringify(value),now=performance.now(),previous=states.get(key);
  if(previous?.fingerprint===fingerprint && (!heartbeat||now-previous.at<heartbeat))return;
  states.delete(key);states.set(key,{fingerprint,at:now});if(states.size>512)states.delete(states.keys().next().value);
  trace(previous?.fingerprint===fingerprint?`${event}.waiting`:event,value);
}
export function traceOperation(event,fields={},quiet=false) {
  const operation=++sequence,start=performance.now(),data={...clean(fields),operation};let waiting=false,ended=false;
  if(!quiet)trace(`${event}.start`,data);
  const timer=setInterval(()=>{waiting=true;trace(`${event}.waiting`,{...data,durationMs:Math.round(performance.now()-start)});},15000);
  timer.unref?.();
  return error=>{
    if(ended)return;ended=true;clearInterval(timer);
    const durationMs=Math.round(performance.now()-start);
    if(error||!quiet||waiting||durationMs>=1000)trace(`${event}.${error?'error':'done'}`,{...data,durationMs,...(error?{error:error.message??error}:{})});
  };
}
export const pokerLog=()=>history.join('\n');
if(typeof window!=='undefined')window.pokerLog=pokerLog;
