// Real IndexedDB rollback test; uses an isolated disposable browser profile.
import {createRequire} from 'node:module';
const {chromium}=createRequire(import.meta.url)(process.env.PLAYWRIGHT_MODULE??'playwright');
const origin=process.argv.find(a=>a.startsWith('--origin='))?.slice(9)??'http://127.0.0.1:3102';
(async()=>{const browser=await chromium.launch({channel:'chrome',headless:true});try{const page=await browser.newPage();await page.goto(origin+'/tools/relay-e2e');console.log(JSON.stringify(await page.evaluate(async()=>{
 const {PreparationCheckpointStore}=await import('/src/storage/preparation-checkpoint-store.js');
 const s=new PreparationCheckpointStore('atomic-quota-regression');
 await s.saveBatch([{id:'old-artifact',binding:'hand',plaintext:Uint8Array.of(1,2,3)},{id:'record',binding:'hand',plaintext:Uint8Array.of(1)}]);
 const original=IDBObjectStore.prototype.put;let failed=false;
 IDBObjectStore.prototype.put=function(value,id){if(this.name==='checkpoints'&&id==='new-journal'){failed=true;throw new DOMException('Injected full storage','QuotaExceededError')}return original.call(this,value,id)};
 try {await s.saveBatch([{id:'new-artifact',binding:'hand',plaintext:Uint8Array.of(4,5,6)},{id:'new-journal',binding:'hand',plaintext:Uint8Array.of(4)},{id:'record',binding:'hand',plaintext:Uint8Array.of(2)}],['old-artifact']);throw Error('failure was not injected')}catch(e){if(e.name!=='QuotaExceededError')throw e}finally{IDBObjectStore.prototype.put=original}
 await new Promise(r=>setTimeout(r,20));
 const intact=(await s.load('old-artifact','hand')).join(',')==='1,2,3'&&(await s.load('record','hand'))[0]===1&&!await s.read('checkpoints','new-artifact');
 if(!intact)throw Error('aborted replacement corrupted recovery');
 await s.saveBatch([{id:'new-artifact',binding:'hand',plaintext:Uint8Array.of(4,5,6)},{id:'record',binding:'hand',plaintext:Uint8Array.of(2)}],['old-artifact']);
 if(await s.read('checkpoints','old-artifact')||(await s.load('record','hand'))[0]!==2)throw Error('replacement did not commit');
 return {status:'PASS',quotaFailureInjected:failed,oldRecoveryPreserved:intact,retryCommitted:true};
})));}finally{await browser.close()}})().catch(e=>{console.error(e);process.exitCode=1});
