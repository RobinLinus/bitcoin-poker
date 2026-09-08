import test from 'node:test';
import assert from 'node:assert/strict';
import {walletSecret} from './local-wallet.js';
const store = () => { const m=new Map(); return {getItem:k=>m.get(k)??null,setItem:(k,v)=>m.set(k,v)}; };
test('wallet key persists without generating a replacement or backup',()=>{
 const s=store(), key=walletSecret(s);
 assert.match(key,/^[0-9a-f]{64}$/);
 assert.equal(walletSecret(s),key);
 assert.notEqual(walletSecret(store()),key);
});
test('invalid stored wallet key fails without overwriting funds access',()=>{
 const s=store();s.setItem('poker-wallet-key-v1','0'.repeat(64));
 assert.throws(()=>walletSecret(s),/invalid/);
 assert.equal(s.getItem('poker-wallet-key-v1'),'0'.repeat(64));
});
