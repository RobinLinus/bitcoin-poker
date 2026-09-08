// Browser qualification: payout priority, durable delivery, replay after relay restart.
import {createRequire} from 'node:module';
import {spawn} from 'node:child_process';
const {chromium}=createRequire(import.meta.url)(process.env.PLAYWRIGHT_MODULE??'playwright');
let relay,browser;
const start=()=>new Promise((resolve,reject)=>{
 relay=spawn('target/release/poker-relay',['127.0.0.1:3115','deployments/mutinynet/onchain-test.json'],{stdio:['ignore','pipe','pipe']});
 const timer=setTimeout(()=>reject(Error('Local relay startup timed out')),10000);
 const ready=d=>{if(d.toString().includes('listening')){clearTimeout(timer);resolve();}};
 relay.once('error',error=>{clearTimeout(timer);reject(error)});
 relay.once('exit',code=>{clearTimeout(timer);reject(Error('Local relay exited: '+code))});
 relay.stdout.on('data',ready);relay.stderr.on('data',ready);
});
const stop=()=>new Promise(resolve=>{relay.once('exit',resolve);relay.kill('SIGTERM')});
(async()=>{try{
 await start();browser=await chromium.launch({channel:'chrome',headless:true});const page=await browser.newPage();await page.goto('http://127.0.0.1:3115/tools/relay-e2e');
 console.log(await page.evaluate(async()=>{
 const {sendChannelMessages:send,receiveChannelMessages:receive,warmChannelTransport:warm}=await import(`${document.documentElement.dataset.assetBase??''}/src/onchain/channel-inbox.js`);
 const {relayConnection}=await import(`${document.documentElement.dataset.assetBase??''}/src/onchain/relay-socket.js`);
 const rand=()=>Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
 const a={gameId:rand(),sender:'alice',playerToken:rand(),inviteSecret:rand()},b={...a,sender:'bob',playerToken:rand()};
 await Promise.all([warm(a,{payout:true}),warm(b,{payout:true})]);await receive(a,0,{bulk:true,payout:true});await receive(b,0,{bulk:true,payout:true});
 const fa={...a,gameId:rand()},fb={...b,gameId:fa.gameId};
 await Promise.all([warm(fa),warm(fb)]);await receive(fa,0,{bulk:true});await receive(fb,0,{bulk:true});
 await relayConnection.prioritizePayout(a,true);let completed=false;
 const future=send(fa,[{messageId:rand(),kind:'channel.0.batch',payload:new Uint8Array([1,2,3])}]).then(()=>{completed=true});
 await new Promise(r=>setTimeout(r,100));if(completed)throw Error('background upload bypassed payout priority');
 // Each payout lane exceeds a packet, exercising the bounded upload window.
 const messages=Array.from({length:90},(_,i)=>({messageId:rand(),kind:['channel.frame','channel.payout.0.batch','channel.payout.1.batch'][i%3],payload:crypto.getRandomValues(new Uint8Array(65536))}));
 const drain=async(after,count)=>{const list=[],deadline=Date.now()+20000;while(list.length<count){const page=await receive(b,after,{bulk:true,payout:true});list.push(...page.messages);after=page.nextCursor;if(Date.now()>deadline)throw Error('delivery timed out '+JSON.stringify({after,count,got:list.length,stats:await relayConnection.stats()}));await new Promise(r=>setTimeout(r,10));}return list};
 for(let n=0;!await send(a,messages);n++){if(n>100)throw Error('upload remained unjoined');await new Promise(r=>setTimeout(r,10));}const got=await drain(0,90);
 for(const kind of ['channel.frame','channel.payout.0.batch','channel.payout.1.batch'])if(JSON.stringify(got.filter(m=>m.kind===kind).map(m=>m.messageId))!==JSON.stringify(messages.filter(m=>m.kind===kind).map(m=>m.messageId)))throw Error('lane order mismatch');
 for(const m of got){const old=messages.find(n=>n.messageId===m.messageId);if(!old||m.payload.some((v,i)=>v!==old.payload[i]))throw Error('bytes differ');}
 await relayConnection.prioritizePayout(a,false);await future;
 const nextFuture=await receive(fb,0,{bulk:true});if(nextFuture.messages.length!==1)throw Error('background upload did not resume');
 window.test={a,b,send,receive,warm,rand,drain,relayConnection};return {delivered:got.length,stats:await relayConnection.stats()};
 }));
 await stop();await start();
 console.log(await page.evaluate(async()=>{const {a,b,send,receive,warm,rand,drain,relayConnection}=test;
 await Promise.all([warm(a,{payout:true}),warm(b,{payout:true})]);await receive(a,0,{bulk:true,payout:true});await receive(b,90,{bulk:true,payout:true});
 const next=['channel.frame','channel.payout.0.done','channel.payout.1.done'].map(kind=>({messageId:rand(),kind,payload:new Uint8Array([1,2,3])}));
 for(let n=0;!await send(a,next);n++){if(n>100)throw Error('replay remained unjoined');await new Promise(r=>setTimeout(r,10));}const got=await drain(90,3);if(got.length!==3||got.some(m=>!next.some(n=>n.messageId===m.messageId)))throw Error('restart duplicated or lost messages');
 const rewind=await receive(b,0,{bulk:true,payout:true});if(rewind.messages.length!==64)throw Error('rewind failed');return {status:'PASS',afterRestart:got.length,stats:await relayConnection.stats()};
 }));
 }finally{await browser?.close();if(relay?.exitCode===null)await stop();}})().catch(e=>{console.error(e);process.exitCode=1});
