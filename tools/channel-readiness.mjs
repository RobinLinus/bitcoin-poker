// No funding or broadcast: real TableSession/relay/crypto/storage with a synthetic origin.
// PLAYWRIGHT_MODULE may name an externally installed Playwright package.
import {createRequire} from 'node:module';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve} from 'node:path';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.PLAYWRIGHT_MODULE ?? 'playwright');
const arg=(key,fallback)=>process.argv.find(a=>a.startsWith(`--${key}=`))?.split('=').slice(1).join('=') ?? fallback;
const origin=arg('origin','http://127.0.0.1:3102');
const trials=Number(arg('trials','3')), hands=Number(arg('hands','2'));
const destination=resolve(arg('output','target/channel-readiness.json'));
const stacks=arg('stacks','20000,20000').split(',').map(Number);
if(stacks.length!==2 || stacks.some(n=>!Number.isSafeInteger(n)||n<200)) throw new Error('Invalid benchmark stacks');
const browser=await chromium.launch({channel:'chrome',headless:!process.argv.includes('--headed')});
const results=[];
try {
  for(let trial=0;trial<trials;trial++) {
    const context=await browser.newContext();
    if(process.argv.includes('--corrupt-batch')) {
      const injected=new Set();
      await context.route(`${origin}/api/v1/games/*/messages?*`,async route=>{
        const response=await route.fetch(),body=await response.json();
        const token=route.request().headers().authorization;
        const batches=(body.messages??[]).filter(m=>/^channel\.[01]\.batch$/.test(m.kind));
        if(!injected.has(token) && new Set(batches.map(m=>m.sender)).size===2) {
          for(const message of batches) {
            const bytes=Buffer.from(message.payload,'base64');bytes[bytes.length-1]^=1;
            message.payload=bytes.toString('base64');
          }
          injected.add(token);
        }
        await route.fulfill({response,json:body});
      });
    }
    // Only the chain adapter is mocked: this unfunded origin is treated as
    // confirmed and unspent. Browser recovery validation and storage remain real.
    await context.route(`${origin}/src/onchain/browser-defense.js`,async route=>{
      const response=await route.fetch();
      const body=await response.text()+`
const registerForBenchmark=BrowserDefense.prototype.register;
BrowserDefense.prototype.register=function(...args) {
  this.chain={outpointStatus:async()=>({state:'unspent',creatingStatus:{state:'confirmed'}}),
    publish:async()=>{throw Error('Benchmark attempted recovery broadcast');}};
  return registerForBenchmark.apply(this,args);
};`;
      await route.fulfill({response,body});
    });
    const page=await context.newPage();
    page.on('pageerror',error=>console.error('Page error:',error));
    page.on('requestfailed',request=>console.error('Request failed:',request.url(),request.failure()));
    page.on('console',m=>{if(m.text().startsWith('Ready hand')) console.log(m.text()); else if(m.type()==='error' && !m.text().includes('409')) console.error(m.text());});
    await page.goto(`${origin}/tools/channel-e2e`);
    await page.evaluate(({hands,fold,stacks,corrupt})=>{
      window.readiness={status:'starting'};
      window.runReadiness=(async()=>{
        const {TableSession}=await import('/src/onchain/table-session.js');
        const wait=ms=>new Promise(r=>setTimeout(r,ms));
        const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
        const random=()=>crypto.getRandomValues(new Uint8Array(32));
        const config=await (await fetch('/api/v1/config')).json();
        const result={status:'running',userAgent:navigator.userAgent,cores:navigator.hardwareConcurrency,syntheticOrigin:true,mockedChainMonitor:true,corruptionRecoveryTest:corrupt,fold,startingStacks:stacks,hands:[],stages:[],stageHistory:[]};
        window.readiness=result;
        // No wallet action can run; every publication fails this qualification.
        TableSession.prototype.prepareBuyIn=async()=>{};
        TableSession.prototype.publish=async()=>{throw new Error('Benchmark attempted a broadcast');};
        let players=[];
        const starts=new Map(),terminals=new Map(),preparing=[null,null];
        const started=performance.now();
        try {
          players=[0,1].map(i=>new TableSession(config,state=>{
            const hand=state.data?.gameId;
            if(state.stage==='Preparing the full game' && !preparing[i]) preparing[i]=performance.now();
            if(state.view?.terminal && !terminals.has(hand)) terminals.set(hand,performance.now());
            if(result.stages[i]?.stage!==state.stage) {
              const item={stage:state.stage,at:performance.now()-started};
              result.stages[i]=item;result.stageHistory.push({player:i,...item});
            }
          }));
          await players[0].create('Benchmark Alice');clearInterval(players[0].timer);
          await players[1].join({gameId:players[0].data.gameId,inviteSecret:players[0].data.inviteSecret},'Benchmark Bob');clearInterval(players[1].timer);
          for(const p of players) {if(p.pollTask) await p.pollTask;p.localWallet=null;p.fundingKey=null;}
          await Promise.all(players.map(p=>p.step()));
          result.createdGameId=players[0].data.gameId;
          const keys=players[0].keys();if(!keys) throw new Error('Player keys missing');
          const terms={regtest:false,identities:keys.map(k=>k.identity),reveal_keys:[keys[1].reveal,keys[0].reveal],
            origin:`${hex(random())}:0`,origin_value:44600,nonce:Array.from(random()),full:true,fee_multiplier:0.1,csv:12,stacks,button:0};
          terms.fee_reserve=await players[0].wallet.call('reserve',terms);
          terms.origin_value=stacks[0]+stacks[1]+terms.fee_reserve+100;
          result.engine=players[0].data.engine;
          for(const p of players) {
            await p.player.call('configure',terms);
            p.data.terms=terms;p.data.proposal={terms};p.data.funded=true;await p.save();
            p.timer=setInterval(()=>void p.step(),100);
          }
          let pending=null;
          const deadline=performance.now()+600000;
          while(result.hands.length<hands || !players.every(p=>p.view?.terminal)) {
            if(performance.now()>deadline) throw new Error('Readiness benchmark timed out');
            const failed=players.find(p=>p.error);
            if(failed) {
              if(!corrupt || result.recovered || !/invalid|malformed|mismatch/i.test(failed.error)) throw new Error(failed.error);
              if(players.some(p=>p.view?.channelReady || p.data.prepared)) throw new Error('Corrupted preparation became playable');
              result.rejectedCorruption=failed.error;
              const seats=players.map(p=>({gameId:p.data.gameId,sender:p.data.sender,render:p.render}));
              for(const p of players) p.close();
              players=seats.map(s=>new TableSession(config,s.render));
              await Promise.all(players.map((p,i)=>p.resume(seats[i].gameId,seats[i].sender)));
              result.recovered=true;
              continue;
            }
            const [a,b]=players, hand=a.data.gameId;
            if(players.every(p=>p.data.prepared && p.view?.recoveryReady) && !result.initialPreparationMs) {
              result.initialPreparationMs=preparing.map(at=>performance.now()-at);
              result.initialWorkerPreparation=players.map(p=>p.data.prepared);
            }
            const betting=hand===b.data.gameId && players.every(p=>p.view?.betting && p.view?.channelReady && !p.view.pendingMove && p.view.holeCards?.length===2);
            if(betting && !starts.has(hand)) {
              const now=performance.now();starts.set(hand,now);
              const previous=result.hands.at(-1);
              result.hands.push({gameId:hand,playableMs:now-started,gapMs:previous?now-terminals.get(previous.gameId):null,
                preparation:players.map(p=>p.data.prepared),stacks:a.data.terms.stacks,button:a.data.terms.button});
              console.log(`Ready hand ${result.hands.length}: ${JSON.stringify({gapMs:result.hands.at(-1).gapMs,preparationMs:players.map(p=>p.data.prepared.elapsedMs)})}`);
              if(result.hands.length===hands) for(const p of players) await p.setSitOutNext(true);
            }
            if(pending && a.view?.node===b.view?.node && a.view?.node!==pending && players.every(p=>!p.view?.pendingMove)) pending=null;
            if(betting && !pending && a.view.node===b.view.node) {
              const actor=players.find(p=>p.view.actor===p.view.role);
              if(actor && !actor.busy) {
                const edge=actor.view.actions.find(e=>fold?/Fold/.test(e.kind):/Check|Call/.test(e.kind));
                if(!edge) throw new Error('Benchmark action missing');
                pending=actor.view.node;await actor.act(edge.index);
              }
            }
            await wait(10);
          }
          if(corrupt && !result.recovered) throw new Error('Corruption was not exercised');
          result.timingTargetMet=corrupt?null:Math.max(...result.initialPreparationMs,...result.hands.slice(1).map(h=>h.gapMs))<10000;
          result.status='PASS';result.finalBalances=players.map(p=>p.view.nextStacks);
        } catch(error) {result.status='FAIL';result.error=error.stack ?? String(error);}
        finally {for(const p of players) p.close();}
      })();
    },{hands,fold:process.argv.includes('--fold'),stacks,corrupt:process.argv.includes('--corrupt-batch')});
    await page.waitForFunction(()=>['PASS','FAIL'].includes(window.readiness?.status),null,{timeout:660000});
    const result=await page.evaluate(()=>window.readiness);
    results.push(result);
    await mkdir(resolve(destination,'..'),{recursive:true});
    await writeFile(destination,JSON.stringify({served:true,latencyTargetMs:10000,scope:'Two synthetic seats in one Chrome context, local relay, mocked chain monitor; status is protocol completion, timingTargetMet is separate.',trials:results},null,2)+'\n');
    console.log(JSON.stringify({trial:trial+1,status:result.status,timingTargetMet:result.timingTargetMet,error:result.error,initial:result.initialPreparationMs,
      hands:result.hands.map(h=>({gap:h.gapMs,preparation:h.preparation.map(p=>p.elapsedMs)}))}));
    await context.close();
    if(result.status!=='PASS') {process.exitCode=1;break;}
  }
} finally {await browser.close();}
