// Isolated wallet/session fixtures exercise the real relay and browser matchmaking. No funds are spent.
import {createRequire} from 'node:module';
import assert from 'node:assert/strict';
const {chromium}=createRequire(import.meta.url)(process.env.PLAYWRIGHT_MODULE??'playwright');
const origin=process.env.POKER_ORIGIN??'http://127.0.0.1:3102';
(async()=>{const browser=await chromium.launch({channel:'chrome',headless:true});
try {
 const errors=[];
 async function player(name,balance=100000,walletName=name) {
  const context=await browser.newContext();await context.addInitScript(n=>localStorage.setItem('poker-player-name',n),name);
  await context.route('**/src/onchain/local-wallet.js',r=>r.fulfill({contentType:'text/javascript',body:`export const localWallet=async()=>({balance:${balance},address:'wallet',script:'${Buffer.from(walletName).toString('hex')}',refresh:async()=>[{value:${balance},status:{confirmed:true}}]})`}));
  await context.route('**/src/onchain/table-session.js',r=>r.fulfill({contentType:'text/javascript',body:`export const publicBuyInRequirement=async()=>21000;export const inviteUrl=(id,secret)=>location.origin+'/#/join/'+id+'/'+secret;export const parseInvite=()=>({});export class TableSession{constructor(c,render){this.render=render}close(){}async joinMatched(a,name){window.assignment=a;location.hash='/table/'+a.gameId+'/'+a.sender;this.render({data:{...a,publicMatch:true,protocol:'channel-v1',playerName:name,peer:{profile:{name:'Other player'}},log:[]},stage:'Starting'});}async create(name){window.privateCreated=true;this.render({data:{gameId:'a'.repeat(64),inviteSecret:'b'.repeat(64),sender:'alice',playerName:name,peer:{},log:[]},stage:'Waiting'})}}`}));
  const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto(origin);await page.locator('#play-now').waitFor();await page.waitForFunction(()=>!document.querySelector('#play-now').disabled);return page;
 }
 const a=await player('Alice');await a.locator('#play-now').click();await a.waitForFunction(()=>JSON.parse(localStorage.getItem('poker-matchmaking-v2')||'null')?.entered);
 assert.equal(await a.locator('#preparation-title').textContent(),'Finding an opponent…');assert.equal(await a.locator('#invite-card').isVisible(),false);assert.equal(await a.locator('#local-hole-cards').isVisible(),false);
 const ticket=await a.evaluate(()=>JSON.parse(localStorage.getItem('poker-matchmaking-v2')).ticket);
 await a.reload();await a.waitForFunction(()=>document.querySelector('#cancel-match').offsetParent!==null);
 assert.equal(await a.evaluate(()=>JSON.parse(localStorage.getItem('poker-matchmaking-v2')).ticket),ticket);
 const duplicate=await player('Alice second window',100000,'Alice');await duplicate.locator('#play-now').click();await duplicate.locator('#lobby-error').waitFor({state:'visible'});assert.match(await duplicate.locator('#lobby-error').textContent(),/already finding an opponent/);assert.equal(await duplicate.evaluate(()=>!!window.assignment),false);await duplicate.context().close();
 const b=await player('Bob');const started=Date.now();await b.locator('#play-now').click();await Promise.all([a.waitForFunction(()=>!!window.assignment),b.waitForFunction(()=>!!window.assignment)]);
 assert.ok(Date.now()-started<4000);assert.equal(await a.evaluate(()=>assignment.gameId),await b.evaluate(()=>assignment.gameId));assert.notEqual(await a.evaluate(()=>assignment.sender),await b.evaluate(()=>assignment.sender));
 const c=await player('Carol');await c.locator('#play-now').click();await c.waitForFunction(()=>JSON.parse(localStorage.getItem('poker-matchmaking-v2')||'null')?.entered);await c.locator('#cancel-match').click();await c.waitForFunction(()=>location.hash==='');assert.equal(await c.locator('#lobby').isVisible(),true);assert.equal(await c.evaluate(()=>localStorage.getItem('poker-matchmaking-v2')),null);
 await c.locator('#create-game').click();assert.equal(await c.locator('#invite-card').isVisible(),true);
 const poor=await player('Poor',20500);await poor.locator('#play-now').click();await poor.locator('#lobby-error').waitFor({state:'visible'});assert.match(await poor.locator('#lobby-error').textContent(),/₿21,000/);assert.equal(await poor.evaluate(()=>localStorage.getItem('poker-matchmaking-v2')),null);
 assert.deepEqual(errors,[]);console.log('Browser: public pairing, immediate notification, refreshed ticket, cancel, private invite, insufficient funds passed.');
}finally{await browser.close()}})().catch(e=>{console.error(e);process.exit(1)});
