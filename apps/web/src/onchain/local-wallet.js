import {Rpc, hex, unhex, sessionEngine, preloadChannelWorker} from './wasm-client.js';
import {createBrowserEsploraChainAdapter} from '../bitcoin/esplora-client.js';
const KEY = 'poker-wallet-key-v1';
export function walletSecret(storage = localStorage) {
  let value = storage.getItem(KEY);
  if (value === null) {
    do { value = hex(crypto.getRandomValues(new Uint8Array(32))); }
    while (BigInt(`0x${value}`) === 0n || BigInt(`0x${value}`) >= 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n);
    storage.setItem(KEY,value);
  }
  if (!/^[0-9a-f]{64}$/i.test(value) || BigInt(`0x${value}`) === 0n || BigInt(`0x${value}`) >= 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n)
    throw new Error('Local wallet key is invalid');
  return value;
}
let instance;
export function localWallet(config) {
  return instance ??= (async()=>{
    preloadChannelWorker();
    const secret = await navigator.locks.request('poker-wallet-key',()=>walletSecret());
    const rpc = new Rpc(new URL('./funding-worker.js',import.meta.url));
    await rpc.call('init',await sessionEngine());
    const address = await rpc.call('address',{secret:unhex(secret)});
    const chain = await createBrowserEsploraChainAdapter(config);
    await chain.verifyProfile();
    return {secret,rpc,chain,...address, async refresh(){
      const coins=await chain.addressUtxos(address.address);
      this.balance=coins.filter(c=>c.status.confirmed).reduce((sum,c)=>sum+c.value,0);
      return coins;
    }};
  })().catch(error=>{instance=null;throw error;});
}
