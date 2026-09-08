// Exercise the shipped worker scheduling in a disposable browser. Stub only
// the cryptographic engine: these checks concern scheduling, not signatures.
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE??'playwright');
const origin=(process.argv.find(arg=>arg.startsWith('--origin='))?.slice(9)??'http://127.0.0.1:3102').replace(/\/$/,'');
const browser=await chromium.launch({channel:'chrome',headless:true});
try {
  const page=await browser.newPage();
  await page.route(`${origin}/`,route=>route.fulfill({contentType:'text/html',body:'<!doctype html><title>Worker scheduling regression</title>'}));
  await page.route('**/src/onchain/wasm-client.js',route=>route.fulfill({contentType:'text/javascript',body:`
    export const encode=value=>new TextEncoder().encode(JSON.stringify(value));
    export const client=async()=>({call(op,args){
      if(args?.[0]===255)throw new Error('Injected engine failure');
      return new Uint8Array([op]);
    }});
  `}));
  await page.goto(origin);
  const result=await page.evaluate(async()=>{
    const workers=[],results=[];
    let next=0;
    const create=file=>{
      const worker=new Worker(`/src/onchain/${file}`,{type:'module'});workers.push(worker);
      return (method,args)=>new Promise((resolve,reject)=>{
        const id=++next;
        const listener=({data})=>{if(data.id!==id)return;worker.removeEventListener('message',listener);data.error?reject(Error(data.error)):resolve(data.value);};
        worker.addEventListener('message',listener);worker.postMessage({id,method,args});
      });
    };
    const deadline=Date.now()+5000;
    const waitFor=async condition=>{while(!await condition()){if(Date.now()>deadline)throw Error('Scheduling check timed out');await new Promise(r=>setTimeout(r,10));}};
    let release,entered;
    const held=new Promise(r=>entered=r);
    const priority=navigator.locks.request('poker-payout-cpu',async()=>{entered();await new Promise(r=>release=r);});
    try {
      await held;
      const background=create('crypto-worker.js'),foreground=create('crypto-worker.js');
      const context={inventory:new Uint8Array(),owner:0};
      const signing=background('init',{speculative:true,priority:'poker-payout-cpu',context}).then(()=>results.push('background'));
      await waitFor(async()=> (await navigator.locks.query()).pending.filter(l=>l.name==='poker-payout-cpu').length===1);
      await foreground('init',{speculative:false,context});
      const otherTable=create('crypto-worker.js');
      await otherTable('init',{speculative:true,priority:'poker-payout-cpu/other-table',context});
      if(results.length)throw Error('Speculative work ran during payout priority');
      release();await priority;await signing;
      try {await background('sign',{bytes:new Uint8Array([255])});throw Error('Expected engine failure');}
      catch(error){if(error.message!=='Injected engine failure')throw error;}
      await navigator.locks.request('poker-payout-cpu',{ifAvailable:true},lock=>{if(!lock)throw Error('Failed worker retained the CPU lock');});
      return {status:'PASS',checks:['foreground bypasses queued background work','background resumes after payout','failure releases CPU reservation','unrelated tables continue signing']};
    } finally {release?.();workers.forEach(worker=>worker.terminate());}
  });
  console.log(JSON.stringify(result));
} finally {await browser.close();}
