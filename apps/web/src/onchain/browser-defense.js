import { createEsploraChainAdapter } from '../bitcoin/esplora-client.js';
import { inspectTransaction } from '../bitcoin/transaction-inspector.js';
const unhex = value => Uint8Array.from(value.match(/../g), h => parseInt(h,16));
const hex = value => Array.from(value, x => x.toString(16).padStart(2,'0')).join('');
const decode = value => JSON.parse(new TextDecoder().decode(value));
const point = value => { const [txid,vout] = value.split(':'); return {displayTxid:unhex(txid),vout:Number(vout)}; };

// Revision 1 spans both sides of entry: the initial package has no executable
// paths, then receiving Entry adds exactly one launch per owner. This is forward
// progress within the same revision, never permission to replace an entry path.
function completesEntry(previous, next) {
  if(previous.version!==1 || previous.revision!==1 || next.revision!==1 ||
     previous.paths?.length!==2 || next.paths?.length!==2 ||
     !previous.paths.every(path=>Array.isArray(path)&&path.length===0) ||
     !next.paths.every(path=>Array.isArray(path)&&path.length===1&&Array.isArray(path[0])&&path[0].length>0) ||
     previous.penalties?.length!==0 || next.penalties?.length!==0)return false;
  const {paths:oldPaths,...oldIdentity}=previous,{paths:newPaths,...newIdentity}=next;
  return JSON.stringify(oldIdentity)===JSON.stringify(newIdentity);
}

export class BrowserDefense {
  constructor(config, store, chain = createEsploraChainAdapter(config), inspect = inspectTransaction) {
    this.store=store; this.chain=chain; this.inspect=inspect; this.confirmed=new Set();
  }
  async register(gameId, payload, digest) {
    const actual = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', payload)));
    if (actual !== digest) throw new Error('Local recovery digest mismatch');
    const pkg=decode(payload), id=`defense/${gameId}`;
    if (await this.store.read('checkpoints',id)) {
      const old=await this.store.load(id,gameId), previous=decode(old);
      if (previous.revision>pkg.revision || (previous.revision===pkg.revision && hex(new Uint8Array(await crypto.subtle.digest('SHA-256',old)))!==digest && !completesEntry(previous,pkg))) {
        throw new Error('Saved channel state is stale');
      }
    }
    await this.store.save(id,gameId,payload);
    if(await this.store.read('checkpoints',`closing/${pkg.funding}`)) return {closing:true};
    if(this.confirmed.has(pkg.funding)) return {closing:false};
    const status=await this.chain.outpointStatus(point(pkg.funding));
    if(status.state==='spent') return {closing:true};
    if(status.state!=='unspent' || status.creatingStatus.state!=='confirmed') throw new Error('Channel funding is not confirmed');
    this.confirmed.add(pkg.funding);
    return {closing:false};
  }
  async tick() {
    const observed=new Map();
    for (const id of await this.store.checkpointIds()) {
      if (!id.startsWith('defense/')) continue;
      try {
        const pkg=decode(await this.store.load(id,id.slice(8)));
        if(!observed.has(pkg.funding)) observed.set(pkg.funding,await this.chain.outpointStatus(point(pkg.funding)));
        await this.defend(pkg,observed.get(pkg.funding));
      }
      catch(error) { console.warn('Browser recovery:', error); }
    }
  }
  async defend(pkg, observed) {
    const status=observed ?? await this.chain.outpointStatus(point(pkg.funding));
    if(status.state!=='spent') return;
    if(this.store) await this.store.save(`closing/${pkg.funding}`,pkg.funding,new Uint8Array([1]));
    const owner=pkg.roots.indexOf(hex(status.spendingDisplayTxid));
    if(owner<0) return;
    const {block}=await this.chain.tip();
    // Publish justice first. Re-read each output so a competing spend is respected.
    for(const bytes of [...pkg.penalties,...pkg.paths[owner]]) {
      const raw=Uint8Array.from(bytes), tx=await this.inspect(raw), input=tx.inputs[0];
      const current=await this.chain.outpointStatus(input.previousOutpoint);
      if(current.state!=='unspent') continue;
      const sequence=input.sequence;
      if((sequence & 0x80000000)===0) {
        if(sequence & 0x00400000) continue;
        if(current.creatingStatus.state!=='confirmed' || block.height+1<current.creatingStatus.block.height+(sequence & 0xffff)) continue;
      }
      try { await this.chain.publish(raw); } catch(error) { console.warn('Browser recovery broadcast:',error); }
    }
  }
}
