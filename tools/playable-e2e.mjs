// Explicitly funded UI qualification: independent wallets, auto redeal, cashout.
import {createRequire} from 'node:module';
import * as fs from 'node:fs/promises';
const {chromium}=createRequire(import.meta.url)(process.env.PLAYWRIGHT_MODULE??'playwright');
const option=(name,fallback)=>process.argv.find(a=>a.startsWith(`--${name}=`))?.slice(name.length+3)??fallback;
if(!process.argv.includes('--funded'))throw Error('Pass --funded to authorize this wallet-funded integration test');
const origin=option('origin','https://poker.bitvm.org'),dir=option('output','/private/tmp/poker-playable-e2e');
const handCount=Number(option('hands','3'));
const resume=process.argv.includes('--resume');
const delayHandoff=process.argv.includes('--delay-handoff');
if(!Number.isInteger(handCount)||handCount<1||handCount>5)throw Error('Expected 1–5 hands');
const delay=ms=>new Promise(r=>setTimeout(r,ms));
(async()=>{
 await fs.mkdir(dir,{recursive:true,mode:0o700});
 const keys=(await fs.readFile(option('keys-file','test-accounts.keys'),'utf8')).trim().split(/\s+/);if(keys.length!==2||keys[0]===keys[1])throw Error('Need two independent test wallets');
 // Real profiles preserve non-extractable IndexedDB CryptoKeys after failure.
 // Playwright storageState cannot serialize those keys and is not a recovery backup.
 const contexts=[];
 for(const [i,key] of keys.entries()) {
   const profile=dir+'/profile-'+i;
   if(resume)await fs.access(profile);else await fs.mkdir(profile,{mode:0o700});
   const c=await chromium.launchPersistentContext(profile,{channel:'chrome',headless:false});contexts.push(c);
   await c.addInitScript(({key,i,origin})=>{if(location.origin!==origin)return;localStorage.setItem('poker-wallet-key-v1',key);localStorage.setItem('poker-player-name','Browser '+(i?'Bob':'Alice'));},{key,i,origin:new URL(origin).origin});
 }
 const pages=contexts.map(c=>c.pages()[0]);
 const report=resume?JSON.parse(await fs.readFile(dir+'/report.json','utf8')):{status:'wallets',hands:[],moves:[],terminals:{},stages:[],errors:[],broadcasts:[],diagnostics:[]};
 const resumeUrls=report.hands.at(-1)?['alice','bob'].map(sender=>`${origin}/#/table/${report.hands.at(-1).gameId}/${sender}`):report.urls;
 if(resume){report.resumed=true;report.previousError=report.error;delete report.error;}
 const save=()=>{report.urls=pages.map(p=>p.url());return fs.writeFile(dir+'/report.json',JSON.stringify(report,null,2));};
 try{
  await Promise.all(pages.map(async(p,i)=>{
   p.on('pageerror',e=>report.errors.push({i,error:e.message}));
   p.on('console',m=>{if(m.text().startsWith('[poker ')&&report.diagnostics.length<12000)report.diagnostics.push({i,line:m.text()});});
   await p.goto(origin);await p.evaluate(async({delayHandoff})=>{
    const {TableSession}=await import(`${document.documentElement.dataset.assetBase??''}/src/onchain/table-session.js`);
    const notify=TableSession.prototype.notify,publish=TableSession.prototype.publish;
    window.publications=[];
    TableSession.prototype.notify=function(){if(!this.background&&!this.stopped)window.table=this;return notify.call(this);};
    TableSession.prototype.publish=async function(raw){window.publications.push({at:Date.now(),afterFunding:!!this.data.funded,cashout:!!this.data.cashout});if(this.data.funded&&!this.data.cashout)throw Error('Unexpected gameplay broadcast');return publish.call(this,raw);};
    if(delayHandoff) {
      const {Rpc}=await import(`${document.documentElement.dataset.assetBase??''}/src/onchain/wasm-client.js`),call=Rpc.prototype.call;
      Rpc.prototype.call=async function(method,...args){
        if(method==='playCertificate'&&!window.handoffDelayInjected) {
          const child=[...(window.table?.handBuffer?.sessions.values()??[])].find(c=>c.data.entrySelected&&!c.data.parentHandoffDone&&c.view?.channelReady);
          // Delay the receiver of the first hole-card move after both players
          // retired the parent. The peer can play while this browser catches up.
          if(child&&child.view.actor!==child.view.role) {
            window.handoffDelayInjected=true;
            await new Promise(resolve=>setTimeout(resolve,5000));
          }
        }
        return call.call(this,method,...args);
      };
    }
    const {localWallet}=await import(`${document.documentElement.dataset.assetBase??''}/src/onchain/local-wallet.js`);window.testWallet=await localWallet(await(await fetch('/api/v1/config')).json());
   },{delayHandoff});
  }));
  report.wallets=await Promise.all(pages.map(p=>p.evaluate(async()=>({address:testWallet.address,balance:(await testWallet.refresh()).filter(c=>c.status.confirmed).reduce((n,c)=>n+c.value,0)}))));
  console.log(JSON.stringify({wallets:report.wallets}));await save();
  if(!resume&&report.wallets.some(w=>w.balance<25000)){report.status='NEEDS_FUNDS';await save();throw Error('Wallet funding needed');}
  let started=report.startedAt??Date.now();
  if(resume) {
   await Promise.all(pages.map((p,i)=>p.evaluate(url=>{location.hash=new URL(url).hash;document.querySelector('#resume-connection').click();},resumeUrls[i])));
   await Promise.all(pages.map(p=>p.waitForFunction(()=>window.table?.view,null,{timeout:120000})));
  }else {
  await pages[0].locator('#create-game').click();
  await pages[0].waitForFunction(()=>document.querySelector('#share-link').value.includes('#/join/'));
  const invite=await pages[0].locator('#share-link').inputValue();started=Date.now();report.startedAt=started;
  await pages[1].evaluate(url=>location.hash=new URL(url).hash,invite);
  }
  report.status='setup';let last='',pending=null,sittingOut=false;
  const deadline=Date.now()+600000;
  while(Date.now()<deadline){
    const states=await Promise.all(pages.map(p=>p.evaluate(()=>window.table?{stage:table.stage,error:table.error,gameId:table.data.gameId,startingStacks:table.data.terms?.stacks??[20000,20000],prepared:!!table.data.prepared,funded:table.data.funded,view:table.view?{ready:table.view.channelReady,terminal:table.view.terminal,node:table.view.node,actor:table.view.actor,stacks:table.view.stacks,nextStacks:table.view.nextStacks,role:table.view.role,betting:table.view.betting,pending:table.view.pendingMove}:null}:null)));
    const text=JSON.stringify(states.map(s=>[s?.stage,s?.error]));if(text!==last){console.log(JSON.stringify({elapsed:Date.now()-started,states}));report.stages.push({elapsed:Date.now()-started,states});last=text;await save();}
    if(states.some(s=>s?.error&&s.stage!=='Connection paused — retrying'))throw Error('Table error: '+states.find(s=>s?.error).error);
    if(states.some(s=>s?.error)){await delay(100);continue;}
    for(let i=0;i<2;i++)if(states[i]?.view?.terminal){const seen=report.terminals[states[i].gameId]??=[null,null];seen[i]??=Date.now()-started;const hand=report.hands.find(h=>h.gameId===states[i].gameId);if(hand)hand.settledStacks=states[i].view.nextStacks;}
    if(states.every(s=>s?.view?.ready)&&states[0].gameId===states[1].gameId&&!report.hands.some(h=>h.gameId===states[0].gameId)){
      const previous=report.hands.at(-1),ended=previous&&report.terminals[previous.gameId];
      const hand={gameId:states[0].gameId,startedMs:Date.now()-started,stacks:states[0].startingStacks};
      if(JSON.stringify(states[0].startingStacks)!==JSON.stringify(states[1].startingStacks))throw Error('Peers disagree on next-hand stacks');
      if(previous?.settledStacks&&JSON.stringify(hand.stacks)!==JSON.stringify(previous.settledStacks))throw Error('Next hand did not retain settled stacks');
      if(ended?.every(t=>t!==null))hand.handoverMs=hand.startedMs-Math.max(...ended);
      hand.preparation=await pages[0].evaluate(()=>table.data.prepared);
      report.hands.push(hand);report.setupMs??=hand.startedMs;report.status='playing';pending=null;
      console.log(JSON.stringify({hand:report.hands.length,...hand}));await pages[0].screenshot({path:dir+'/hand-'+report.hands.length+'.png'});await save();
    }
    if(!sittingOut&&report.hands.length>=handCount&&states.every(s=>s?.view?.ready)){
      await Promise.all(pages.map(p=>p.locator('#sit-out-next-hand').check()));sittingOut=true;
    }
    if(states.every(s=>s?.view?.betting&&!s.view.pending)&&states[0].gameId===states[1].gameId&&states[0].view.node===states[1].view.node){
      const hand=report.hands.find(h=>h.gameId===states[0].gameId);
      if(hand&&hand.actionableMs===undefined){hand.actionableMs=Date.now()-started;const previous=report.hands.at(-2),ended=previous&&report.terminals[previous.gameId];if(ended?.every(t=>t!==null))hand.redealToActionMs=hand.actionableMs-Math.max(...ended);}
    }
    if(report.hands.length===handCount&&states.every(s=>s?.view?.terminal))break;
    if(states.every(s=>s?.view?.ready&&!s.view.pending)&&states[0].view.node===states[1].view.node){
      if(pending&&states[0].view.node!==pending){const move=report.moves.at(-1);if(move)move.settledMs=Date.now()-started-move.clickedMs;pending=null;}
      if(!pending){const i=states.findIndex(s=>s.view.betting&&s.view.actor===s.view.role);if(i>=0){const bet=pages[i].locator('#action-aggressive'),check=pages[i].locator('#action-check'),call=pages[i].locator('#action-call');if(report.hands.length===1&&await bet.isVisible()){pending=states[i].view.node;report.moves.push({hand:report.hands.length,action:'bet/raise',clickedMs:Date.now()-started});await bet.click();}else if(await check.isVisible()){pending=states[i].view.node;report.moves.push({hand:report.hands.length,action:'check',clickedMs:Date.now()-started});await check.click();}else if(await call.isVisible()){pending=states[i].view.node;report.moves.push({hand:report.hands.length,action:'call',clickedMs:Date.now()-started});await call.click();}}}
    }
    await delay(100);
  }
  if(!await pages[0].evaluate(()=>table.view?.terminal))throw Error('Timed out before hand completion');
  report.status='cashout';await save();
  if(process.argv.includes('--cashout-reconnect')) {
    await pages[0].exposeFunction('disconnectCashoutTest',()=>contexts[0].setOffline(true));
    await pages[0].evaluate(()=>{
      const prototype=Object.getPrototypeOf(table),publish=prototype.publish;
      let interrupt=true;
      prototype.publish=async function(raw){
        if(interrupt&&this.data.cashout){
          interrupt=false;window.interruptedCashout=this.data.cashout;
          await window.disconnectCashoutTest();throw Error('Failed to fetch');
        }
        return publish.call(this,raw);
      };
    });
  }
  await pages[0].locator('#leave-table').click();
  if(process.argv.includes('--cashout-reconnect')) {
    await pages[0].waitForFunction(()=>window.interruptedCashout&&table.error,null,{timeout:60000});
    await contexts[0].setOffline(false);
    const reconnectStarted=Date.now();
    await pages[0].locator('#resume-connection').click();
    await pages[0].waitForFunction(()=>table.data.left,null,{timeout:120000});
    report.cashoutReconnect={durationMs:Date.now()-reconnectStarted,sameTransaction:await pages[0].evaluate(()=>table.data.cashout===window.interruptedCashout)};
    if(!report.cashoutReconnect.sameTransaction)throw Error('Reconnect replaced the saved cashout');
  }
  await Promise.all(pages.map(p=>p.waitForFunction(()=>table.data.left,null,{timeout:180000})));
  report.broadcasts=await Promise.all(pages.map(p=>p.evaluate(()=>publications)));
  if(report.hands.length!==handCount)throw Error('Missing automatic hands');
  if(report.errors.length)throw Error('Browser errors during playable test');
  if(delayHandoff) {
    report.delayedHandoff={injected:await Promise.all(pages.map(p=>p.evaluate(()=>!!window.handoffDelayInjected))),
      deferredFrames:report.diagnostics.filter(d=>d.line.includes('"event":"channel.frame.deferred"')).length};
    if(!report.delayedHandoff.injected.some(Boolean)||!report.delayedHandoff.deferredFrames)throw Error('Did not exercise early next-hand delivery');
  }
  report.status='PASS';report.totalMs=Date.now()-started;await save();console.log(JSON.stringify({status:report.status,setupMs:report.setupMs,hands:report.hands,totalMs:report.totalMs,errors:report.errors}));
 }catch(e){report.status='FAIL';report.error=e.stack;await save();console.error(e);process.exitCode=1;}
 finally{await Promise.all(contexts.map(c=>c.close()));}
})();
