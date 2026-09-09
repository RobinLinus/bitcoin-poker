// Exercises payout-driven navigation with an isolated session; no funds are spent.
import {createRequire} from 'node:module';
import assert from 'node:assert/strict';
const {chromium}=createRequire(import.meta.url)(process.env.PLAYWRIGHT_MODULE??'playwright');
const origin=process.env.POKER_ORIGIN??'http://127.0.0.1:3102';
const browser=await chromium.launch({channel:'chrome',headless:true});
try {
 const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.addInitScript(()=>localStorage.setItem('poker-player-name','Alice'));
 await page.route('**/src/onchain/local-wallet.js',r=>r.fulfill({contentType:'text/javascript',body:`export const localWallet=async()=>({balance:100000,address:'wallet',script:'5120'+'ab'.repeat(32),refresh:async()=>{window.walletRefreshes=(window.walletRefreshes||0)+1;return []}})`}));
 await page.route('**/src/onchain/table-session.js',r=>r.fulfill({contentType:'text/javascript',body:`export const publicBuyInRequirement=async()=>21000;export const inviteUrl=()=>'';export const parseInvite=()=>({});export class TableSession {
 constructor(c,render){this.render=render;window.testSession=this}close(){window.closedCount=(window.closedCount||0)+1}
 async create(name){this.state={activeSession:this,data:{gameId:'a'.repeat(64),sender:'alice',playerName:name,peer:{profile:{name:'Bob'}},log:[],sitOutNext:true},view:{terminal:true,role:0,hand:1,node:'n',payouts:[20000,20000],holeCards:[1,2],board:[3,4,5,6,7]},stage:'Hand complete'};this.render(this.state);}
 leaveTable(){this.state.data.leaveRequested=true;this.state.stage='Cashing out…';this.render(this.state);}
 }`}));
 await page.goto(origin);await page.waitForFunction(()=>!document.querySelector('#create-game').disabled);await page.locator('#create-game').click();
 await page.evaluate(()=>{localStorage.setItem('poker-public-table-v1',JSON.stringify({gameId:'a'.repeat(64),sender:'alice'}));localStorage.setItem('poker-matchmaking-v2','{}');});
 await page.locator('#leave-table').click();assert.equal(await page.locator('#game').isVisible(),true);assert.match(await page.locator('#table-phase').textContent(),/Cashing out/);assert.equal(await page.locator('#leave-table').isVisible(),false);
 await page.evaluate(()=>{testSession.state.error='Waiting for payout confirmation';testSession.render(testSession.state);});assert.equal(await page.locator('#game').isVisible(),true);
 const before=await page.evaluate(()=>walletRefreshes);
 await page.evaluate(()=>{testSession.state.error=null;testSession.state.data.left=true;testSession.render(testSession.state);});
 await page.waitForFunction(()=>location.hash===''&&document.querySelector('#game').classList.contains('hidden'));
 assert.equal(await page.locator('#lobby').isVisible(),true);assert.equal(await page.evaluate(()=>closedCount),1);
 assert.equal(await page.evaluate(()=>localStorage.getItem('poker-public-table-v1')),null);assert.equal(await page.evaluate(()=>localStorage.getItem('poker-matchmaking-v2')),null);
 await page.waitForFunction(n=>walletRefreshes>n,before);
 await page.evaluate(()=>{testSession.render({...testSession.state,data:{...testSession.state.data,left:false}});testSession.render(testSession.state);});
 assert.equal(await page.locator('#lobby').isVisible(),true);assert.equal(await page.locator('#game').isVisible(),false);assert.equal(await page.evaluate(()=>closedCount),1);assert.deepEqual(errors,[]);
 console.log('Cashout: waits for payout, automatically returns to lobby, clears matching state, refreshes wallet, ignores late callbacks.');
} finally {await browser.close();}
