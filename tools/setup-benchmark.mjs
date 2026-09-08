// Two isolated browser wallets, real relay/dealer/trees, synthetic unfunded origin.
// Run with PLAYWRIGHT_MODULE pointing to Playwright if it is installed externally.
import {createRequire} from 'node:module';
import {writeFile,mkdir} from 'node:fs/promises';
import {dirname,resolve} from 'node:path';
const {chromium}=createRequire(import.meta.url)(process.env.PLAYWRIGHT_MODULE??'playwright');
const option=(name,fallback)=>process.argv.find(a=>a.startsWith(`--${name}=`))?.slice(name.length+3)??fallback;
const origin=option('origin','http://127.0.0.1:3102');
const trials=Number(option('trials','3')),destination=resolve(option('output','target/setup-benchmark.json'));
const browser=await chromium.launch({channel:'chrome',headless:true});
const results=[];
try {
  for(let trial=0;trial<trials;trial++) {
    const contexts=await Promise.all([browser.newContext(),browser.newContext()]);
    const pages=await Promise.all(contexts.map(c=>c.newPage()));
    const errors=[],diagnostics=[];
    try {
      const coldStarted=performance.now();
      await Promise.all(pages.map(async page=>{
        page.on('pageerror',e=>errors.push(e.message));
        page.on('console',message=>{if(message.text().startsWith('[poker ')&&diagnostics.length<5000)diagnostics.push(message.text());});
        await page.goto(origin);
        await page.evaluate(async()=>{
          const {TableSession}=await import(`${document.documentElement.dataset.assetBase??''}/src/onchain/table-session.js`);
          const {localWallet}=await import(`${document.documentElement.dataset.assetBase??''}/src/onchain/local-wallet.js`);
          const config=await(await fetch('/api/v1/config')).json();
          // The playable lobby already loads the wallet before enabling Create/Join.
          const wallet=await localWallet(config);
          if((await wallet.refresh()).length)throw Error('Benchmark wallet must be empty');
          window.bench=new TableSession(config,()=>{});
        });
      }));
      const lobbyMs=performance.now()-coldStarted;
      const invitation=await pages[0].evaluate(async()=>{
        await bench.create('Benchmark Alice');return {gameId:bench.data.gameId,inviteSecret:bench.data.inviteSecret};
      });
      const started=performance.now();
      await pages[1].evaluate(async invite=>bench.join(invite,'Benchmark Bob'),invitation);
      await Promise.all(pages.map(page=>page.waitForFunction(()=>bench.data.initialDeckReady,{},{timeout:120000})));
      const dealerMs=performance.now()-started;
      const terms=await pages[0].evaluate(()=>{
        const plan=bench.data.buyinplan,keys=bench.keys();
        return {regtest:false,identities:keys.map(k=>k.identity),reveal_keys:[keys[1].reveal,keys[0].reveal],
          origin:'02'.repeat(32)+':0',origin_value:40000+plan.reserve+1000*plan.multiplier,
          predeal_anchor:Array.from(Uint8Array.from(bench.data.gameId.match(/../g),h=>parseInt(h,16))),
          nonce:plan.nonce,full:true,fee_multiplier:plan.multiplier,fee_reserve:plan.reserve,csv:12};
      });
      await Promise.all(pages.map(page=>page.evaluate(async terms=>{
        if(bench.data.proposal||bench.data.peer.proposal||bench.data.funded)throw Error('Unexpected funding');
        bench.initialDealBinding=true;clearInterval(bench.timer);
        if(bench.initialDealTask)await bench.initialDealTask;
        await bench.player.call('configure',terms);
      },terms)));
      const preparations=pages.map(page=>page.evaluate(async()=>{
        const deadline=Date.now()+120000;
        while(true) {
          const state=await bench.player.call('deal');
          if(state.accepted&&state.peerScore)break;
          if(Date.now()>deadline)throw Error('Score exchange timeout');
          await new Promise(r=>setTimeout(r,10));
        }
        return bench.player.call('prepare');
      }));
      for(const task of preparations)task.catch(()=>{});
      if(process.argv.includes('--reload-during-preparation')) {
        await pages[0].waitForFunction(()=>bench.progress?.phase==='signing'&&bench.progress.done>0,null,{timeout:120000});
        const seat=await pages[0].evaluate(()=>{const seat={gameId:bench.data.gameId,sender:bench.data.sender};bench.close();return seat;});
        await pages[0].goto(`${origin}/tools/relay-e2e`);
        preparations[0]=pages[0].evaluate(async seat=>{
          const {TableSession}=await import(`${document.documentElement.dataset.assetBase??''}/src/onchain/table-session.js`);
          const config=await(await fetch('/api/v1/config')).json();
          window.bench=new TableSession(config,()=>{});
          await bench.resume(seat.gameId,seat.sender);clearInterval(bench.timer);
          return bench.player.call('prepare');
        },seat);
      }
      const prepared=await Promise.all(preparations);
      if(prepared[0].binding!==prepared[1].binding)throw Error('Preparation mismatch');
      const totalMs=performance.now()-started;
      const sockets=await Promise.all(pages.map(page=>page.evaluate(async()=>
        (await import(`${document.documentElement.dataset.assetBase??''}/src/onchain/relay-socket.js`)).relayConnection.stats())));
      const result={trial,reloaded:process.argv.includes('--reload-during-preparation'),lobbyMs,dealerMs,preparationMs:totalMs-dealerMs,totalMs,prepared,sockets,errors,diagnostics};
      results.push(result);console.log(JSON.stringify({trial,lobbyMs,dealerMs,preparationMs:result.preparationMs,totalMs,attempt:prepared[0].owners[0].dealAttempt,errors}));
      if(errors.length)throw Error('Browser errors during setup');
    } finally {
      await Promise.all(pages.map(page=>page.evaluate(()=>window.bench?.close()).catch(()=>{})));
      await Promise.all(contexts.map(c=>c.close()));
      await mkdir(dirname(destination),{recursive:true});await writeFile(destination,JSON.stringify(results,null,2));
    }
  }
} finally {await browser.close();}
