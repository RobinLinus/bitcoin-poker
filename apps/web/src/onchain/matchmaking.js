// Only opaque matchmaking credentials live here. Game history belongs to TableSession.
const KEY = 'poker-matchmaking-v2';
const ACTIVE='poker-public-table-v1';
export function activePublicTable() { return JSON.parse(localStorage.getItem(ACTIVE)||'null'); }
export function rememberPublicTable(a) { localStorage.setItem(ACTIVE,JSON.stringify({gameId:a.gameId,sender:a.sender})); }
export function clearPublicTable() { localStorage.removeItem(ACTIVE); }
// Stable across windows, browser profiles and app origins sharing the same wallet.
// This is public wallet data, never the wallet secret or a spending credential.
export async function walletMatchId(wallet) {
  if (typeof wallet.script !== 'string' || !/^(?:[a-f0-9]{2})+$/i.test(wallet.script)) throw new Error('Wallet is not ready.');
  const bytes = new TextEncoder().encode('BP52/matchmaking/wallet/v1:'+wallet.script.toLowerCase());
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)), b=>b.toString(16).padStart(2,'0')).join('');
}
const random = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2,'0')).join('');
export function pendingMatch() { return !!localStorage.getItem(KEY); }
export function forgetMatch() { localStorage.removeItem(KEY); }
export class Matchmaking {
  constructor(onState, walletId) { this.onState=onState; this.walletId=walletId; }
  save() { localStorage.setItem(KEY,JSON.stringify(this.record)); }
  fresh() {
    if (!/^[a-f0-9]{64}$/.test(this.walletId ?? '')) throw new Error('Wallet is not ready.');
    this.record={ticket:random(),walletId:this.walletId,gameId:random(),playerToken:random(),inviteSecret:random()};
    this.save();
  }
  async request(action) {
    const {ticket,walletId,gameId,playerToken,inviteSecret}=this.record;
    const response=await fetch('/api/v1/matchmaking',{method:'POST',headers:{'content-type':'application/json'},
      body:JSON.stringify({ticket,walletId,gameId,playerToken,inviteSecret,action}),signal:AbortSignal.timeout(22000)});
    const result=await response.json();
    if(!response.ok) throw new Error(result?.error?.message ?? 'Couldn’t find an opponent. Try again.');
    return result;
  }
  async cancel() {
    if(!this.record) {this.cancelled=true;return;}
    const result=await this.request('cancel');
    // The server decides the race; never discard an already assigned seat.
    if(result.status==='matched') {this.record.assignment=result;this.save();this.onState('matched');return;}
    this.cancelled=true;forgetMatch();
  }
  async find() {
    const run=async lock=>{
      if(!lock) throw new Error('Matchmaking is already open in another tab.');
      this.record=JSON.parse(localStorage.getItem(KEY)||'null');
      if(this.record && this.record.walletId!==this.walletId) throw new Error("This search belongs to a different wallet.");
      if(!this.record)this.fresh();
      if(this.cancelled) {await this.cancel();return null;}
      if(this.record.assignment)return {...this.record.assignment,playerToken:this.record.playerToken};
      let action=this.record.entered?'poll':'enter';
      while(!this.cancelled) {
        const result=await this.request(action);
        if(this.cancelled)return null;
        if(result.status==='matched') {
          this.record.assignment=result;this.save();this.onState('matched');
          return {...result,playerToken:this.record.playerToken};
        }
        if(result.status==='cancelled') {forgetMatch();return null;}
        if(result.status==='missing'||result.status==='expired') {this.fresh();action='enter';continue;}
        this.record.entered=true;this.save();this.onState('waiting');action='poll';
      }
      return null;
    };
    return navigator.locks.request('poker-matchmaking',{ifAvailable:true},run);
  }
}
