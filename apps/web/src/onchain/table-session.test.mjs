import {encodeBinary,decodeProtocol} from './binary-codec.js';
import test from "node:test";
import assert from "node:assert/strict";
import { TableSession, parseInvite } from "./table-session.js";

test("invites require an exact game and invite capability", () => {
  const a = "a".repeat(64),
    b = "b".repeat(64);
  assert.deepEqual(parseInvite(`https://example.test/#/join/${a}/${b}`), {
    gameId: a,
    inviteSecret: b,
  });
  assert.throws(() => parseInvite(`#/table/${a}/alice`));
  assert.throws(() => parseInvite(`#/join/${a}/${b}/extra`));
});
test("a host retains its exact outgoing message until the guest joins", async () => {
  const s = new TableSession({}, () => {}), frame = {messageId:"fixed",kind:"table.keys",payload:"opaque"};
  s.data={outbox:[frame]}; s.save=async()=>{};
  s.postMessage=async()=>{throw new Error("both player capabilities must be fixed before messages are accepted")};
  await s.flush(); assert.deepEqual(s.data.outbox,[frame]);
  s.postMessage=async message=>assert.deepEqual(message,frame);
  await s.flush(); assert.deepEqual(s.data.outbox,[]);
});
test("different pinned engines cannot agree a table", () => {
  const s = new TableSession({}, () => {});
  s.data = { engine: "a", keys: {}, peer: { keys: { engine: "b", keys: {} } } };
  assert.throws(() => s.keys(), /same game version/);
});
test("guest rejects funding that pays a different script", async () => {
  const s = new TableSession({}, () => {});
  const keys = [
    { identity: Array(32).fill(1), reveal: [] },
    { identity: Array(32).fill(2), reveal: [] },
  ];
  s.keys = () => keys;
  s.save = async () => {};
  s.data = {
    sender: "bob",
    peer: {
      proposal: {
        funding: "00",
        returnScript: "5120",
        terms: {
          regtest: false,
          full: true,
          csv: 12,
          fee_multiplier: 1,
          origin_value: 86000,
          origin: "tx:0",
          identities: keys.map((k) => k.identity),
          reveal_keys: [[], []],
        },
      },
    },
  };
  s.wallet = {
    call: async () => ({
      txid: "tx",
      outputs: [{ value: 86000, script: "wrong" }],
    }),
  };
  s.player = {
    call: async (method) =>
      method === "view" ? { originScript: "correct" } : undefined,
  };
  await assert.rejects(s.configure(), /wrong escrow script/);
  assert.equal(s.data.refund, undefined);
});

test("a saved return still releases a missing queued signature after recovery", async () => {
  const s = new TableSession({}, () => {});
  s.data = { refund: "00", proposal: { returnScript: "5120" }, sent: {} };
  s.player = {
    call: async (method) => {
      assert.equal(method, "refundSig");
      return new Uint8Array(64);
    },
  };
  let sent;
  s.send = async (kind, value) => {
    sent = { kind, value };
  };
  assert.equal(await s.configure(), true);
  assert.equal(sent.kind, "refund");
  assert.equal(sent.value.length, 128);
});

test("continuation preserves ownership and switches the button when canonical roles change", () => {
  const keys = [{ identity: [1] }, { identity: [2] }];
  const s = new TableSession({}, () => {});
  s.data = {
    keys: keys[1],
    continuation: { role: 0, button: 0, stacks: [19400, 20600] },
  };
  assert.deepEqual(s.nextTerms(keys), { stacks: [20600, 19400], button: 0 });
  s.data.keys = keys[0];
  assert.deepEqual(s.nextTerms(keys), { stacks: [19400, 20600], button: 1 });
});

test("a settled hand never advances without both players consenting to the same payout", async () => {
  const s = new TableSession({}, () => {});
  s.data = { peer: { nextready: { tip: "peer:0" } } };
  s.view = { terminal: true, tip: "local:0" };
  s.send = async () => {};
  await s.continueHand();
  assert.equal(s.stage, "Hand settled");
  s.data.wantsNext = true;
  await assert.rejects(s.continueHand(), /same confirmed payout/);
  s.data.peer = {};
  await s.continueHand();
  assert.match(s.stage, /Waiting for your opponent/);
});

test("next hand rejects an unsettled game and a busted stack without sending consent", async () => {
  const s = new TableSession({}, () => {});
  s.data = { peer: {} };
  let sent = false;
  s.send = async () => {
    sent = true;
  };
  s.step = async () => {};
  await s.nextHand();
  assert.equal(sent, false);
  s.view = { terminal: true };
  s.player = { call: async () => ({ nextStacks: [0, 40000] }) };
  await s.nextHand();
  assert.equal(sent, false);
  assert.match(s.error, /minimum/);
});

test("next-hand consent uses the relay's lowercase message alphabet and survives waiting", async () => {
  const s = new TableSession({}, () => {});
  s.data = { peer: {} };
  s.view = { terminal: true, tip: "settled:0" };
  s.player = { call: async () => ({ nextStacks: [19400, 20600] }) };
  s.save = async () => {};
  s.step = async () => {};
  let frame;
  s.send = async (kind, payload) => {
    assert.match(kind, /^[a-z0-9._-]+$/);
    frame = { kind, payload };
  };
  await s.nextHand();
  assert.deepEqual(frame, { kind: "nextready", payload: { tip: "settled:0" } });
  assert.equal(s.data.wantsNext, true);
});

test("funding errors remain visible across background table polling", async () => {
  let rendered;
  const s = new TableSession({}, (value) => {
    rendered = value;
  });
  s.data = { sender: "alice" };
  s.keys = () => null;
  await s.fund("01".repeat(32));
  s.tick = async () => {};
  await s.step();
  assert.match(rendered.error, /opponent to join/);
});

test("large payout witnesses are durably queued without exceeding argument limits", async () => {
  const s = new TableSession({}, () => {});
  s.data = { sent: {}, outbox: [] };
  s.save = async () => {};
  s.flush = async () => {};
  const value = { previous: "ab".repeat(100000) };
  await s.send("proposal", value);
  assert.deepEqual(
    decodeProtocol(s.data.outbox[0].payload),
    value,
  );
  await s.send("proposal", value);
  assert.equal(s.data.outbox.length, 1);
});

test("background polls do not toggle the button busy state or overlap", async () => {
  const rendered = [];
  const s = new TableSession({}, (state) => rendered.push(state.busy));
  s.data = { gameId: "table" };
  let finish,
    calls = 0;
  s.tick = () => {
    calls++;
    return new Promise((resolve) => {
      finish = resolve;
    });
  };
  const poll = s.step();
  await Promise.resolve();
  await s.step();
  s.notify();
  assert.equal(s.busy, false);
  assert.equal(calls, 1);
  finish();
  await poll;
  assert.deepEqual(rendered, [false, false]);
});

test("a click during polling executes once after the poll", async () => {
  const s = new TableSession({}, () => {});
  s.data = { gameId: "table" };
  s.view = { channelReady:true, node: "node" };
  let finish,
    submitted = [];
  s.tick = () =>
    new Promise((resolve) => {
      finish = resolve;
    });
  s.submit = async (edge) => {
    submitted.push(edge);
  };
  const poll = s.step();
  await Promise.resolve();
  const click = s.act(3);
  await s.act(3);
  assert.equal(s.busy, true);
  assert.deepEqual(submitted, []);
  finish();
  await poll;
  await click;
  assert.deepEqual(submitted, [3]);
  assert.equal(s.busy, false);
});

test("a queued click cannot act on a different confirmed node", async () => {
  const s = new TableSession({}, () => {});
  s.data = { gameId: "table" };
  s.view = { channelReady:true, node: "old" };
  let finish,
    submitted = false;
  s.tick = () =>
    new Promise((resolve) => {
      finish = () => {
        s.view = { channelReady:true, node: "new" };
        resolve();
      };
    });
  s.submit = async () => {
    submitted = true;
  };
  const poll = s.step();
  await Promise.resolve();
  const click = s.act(2);
  finish();
  await poll;
  await click;
  assert.equal(submitted, false);
  assert.equal(s.busy, false);
});

test("next hand acknowledges a click before checking the saved hand", async () => {
  const frames = [];
  const s = new TableSession({}, state => frames.push({busy:state.busy,action:state.busyAction}));
  s.data = {peer:{}};
  s.view = {terminal:true,tip:'settled:0'};
  let finish;
  s.player = {call:() => new Promise(resolve => { finish = resolve; })};
  s.save = s.send = s.step = async () => {};
  const click = s.nextHand();
  assert.deepEqual(frames[0],{busy:true,action:'next-hand'});
  assert.equal(s.data.wantsNext,undefined);
  await s.nextHand();
  finish({nextStacks:[20000,20000]});
  await click;
  assert.equal(s.data.wantsNext,true);
  assert.deepEqual(frames.at(-1),{busy:false,action:null});
});
test("next hand acknowledges a queued click before the poll completes", async () => {
  const frames = [];
  const s = new TableSession({}, state => frames.push(state.busyAction));
  s.data = {gameId:'table',peer:{}};
  s.view = {node:'end',terminal:true,tip:'settled:0'};
  let finish;
  s.pollTask = new Promise(resolve => { finish = () => {s.pollTask=null;resolve();}; });
  s.player = {call:async()=>({nextStacks:[20000,20000]})};
  s.save = s.send = s.step = async()=>{};
  const click = s.nextHand();
  assert.equal(frames[0],'next-hand');
  finish();
  await click;
  assert.equal(s.data.wantsNext,true);
  assert.equal(s.busy,false);
});
test("invalid funding text releases busy state and allows a retry", async () => {
  const frames = [];
  const s = new TableSession({}, state => frames.push(state.busyAction));
  s.data = {sender:'alice'};
  await s.fund('not hex');
  assert.equal(frames[0],'fund');
  assert.equal(s.busy,false);
  assert.equal(s.busyAction,null);
  assert.equal(s.error,'Invalid hex');
});

function channelSession(view) {
  const s=new TableSession({},()=>{});
  s.data={protocol:'channel-v1',proposal:{terms:{}},prepared:{binding:'same'},peer:{ready:{binding:'same'}},funded:true};
  s.send=s.save=async()=>{};
  s.player={call:async method=>{assert.equal(method,'advance');return view;}};
  s.chain=new Proxy({}, {get(){throw new Error('Cooperative move touched chain adapter');}});
  s.publish=async()=>assert.fail('Cooperative move broadcast a transaction');
  return s;
}
test('healthy channel play never polls a block or broadcasts a move',async()=>{
  const s=channelSession({channelReady:true,recoveryReady:true,betting:true,role:0,actor:1,pendingMove:false});
  await s.advanceChannel();
  assert.equal(s.stage,'Opponent’s turn');
});
test('pending authorizations wait for the peer without broadcasting',async()=>{
  const s=channelSession({channelReady:true,recoveryReady:true,betting:true,role:0,actor:0,pendingMove:true});
  s.submit=async()=>assert.fail('duplicate move');
  await s.advanceChannel();
  assert.equal(s.stage,'Waiting for your opponent');
});
test('card revelation uses cooperative delivery without a chain height',async()=>{
  const s=channelSession({channelReady:true,recoveryReady:true,betting:false,role:0,actor:0,pendingMove:false});
  let called=false;s.submit=async edge=>{assert.equal(edge,null);called=true;};
  await s.advanceChannel();assert.equal(called,true);
});

function automaticNextSession() {
 const frames=[];
 const s=new TableSession({},state=>frames.push({sitOut:state.data.sitOutNext,wantsNext:state.data.wantsNext}));
 s.data={peer:{},sent:{},outbox:[]};
 s.view={terminal:true,tip:'settled:0'};
 s.player={call:async()=>({nextStacks:[20000,20000]})};
 s.save=s.step=async()=>{};
 const sent=[];
 s.send=async(kind,value)=>sent.push({kind,value});
 s.cashOut=async()=>{s.cashedOut=true;};
 return {s,frames,sent};
}
test('next hand readies automatically after the result pause',async()=>{
 const {s,sent}=automaticNextSession();
 await s.continueHand();
 assert.equal(sent.length,0);
 s.handEndedAt=Date.now()-3001;
 await s.continueHand();
 assert.equal(s.data.wantsNext,true);
 assert.deepEqual(sent,[{kind:'nextready',value:{tip:'settled:0'}}]);
 assert.equal(s.data.successor,undefined,'wait for the other seat');
});
test('sit out is immediate, persists, blocks redeal, and can be unchecked',async()=>{
 const {s,frames,sent}=automaticNextSession();
 s.handEndedAt=Date.now()-3001;
 let finish;
 s.save=()=>new Promise(resolve=>{finish=resolve;});
 const check=s.setSitOutNext(true);
 assert.equal(frames.at(-1).sitOut,true);
 await s.continueHand();
 assert.equal(sent.length,0);
 finish();await check;
 s.save=async()=>{};
 await s.setSitOutNext(false);
 await s.continueHand();
 assert.equal(sent[0].kind,'nextready');
 await s.setSitOutNext(true);
 assert.equal(s.data.sitOutNext,true,'can sit out while waiting for the other seat');
});
test('sit out during rollover validation prevents automatic readiness',async()=>{
 const {s,sent}=automaticNextSession();
 s.handEndedAt=Date.now()-3001;
 let finish;
 s.player.call=()=>new Promise(resolve=>{finish=resolve;});
 const next=s.continueHand();
 await s.setSitOutNext(true);
 finish({nextStacks:[20000,20000]});await next;
 assert.equal(sent.length,0);
});
test('automatic redeal stops when a stack cannot cover the minimum',async()=>{
 const {s,sent}=automaticNextSession();
 s.handEndedAt=Date.now()-3001;
 s.player.call=async()=>({nextStacks:[100,39900]});
 await s.continueHand();
 assert.equal(sent.length,0);
 assert.equal(s.data.wantsNext,undefined);
});
test('continuation funding can run inside the poll without waiting on itself',async()=>{
 const s=new TableSession({},()=>{});
 s.data={sender:'alice',peer:{},continuation:{}};
 s.fundingKey='01'.repeat(32);
 s.flush=async()=>{};s.receive=async()=>false;s.keys=()=>[{},{}];
 s.pollTask=Promise.resolve();
 let call;
 s.fund=async(key,options)=>{call={key,options};};
 await s.tick();
 assert.deepEqual(call,{key:s.fundingKey,options:{fromPoll:true}});
 s.close();assert.equal(s.fundingKey,null);
});

test('background deck stops at accepted 2PC without preparing or revealing cards',async()=>{
 const s=new TableSession({},()=>{});
 const keys=[{identity:[1],reveal:[3]},{identity:[2],reveal:[4]}];
 s.data={gameId:'ab'.repeat(32),sender:'alice',keys:keys[1],predealContext:{nonce:Array(32).fill(7),buttonSender:'bob'}};
 s.flush=s.save=async()=>{};s.receive=async()=>false;s.keys=()=>keys;
 const calls=[];
 s.player={call:async(method,args)=>{calls.push({method,args});return {accepted:true};}};
 await s.tickPredeal();await s.tickPredeal();
 assert.deepEqual(calls.map(c=>c.method),['configurePredeal','deal']);
 assert.equal(calls[0].args.button,0,'dealer follows the seat when sorted roles change');
 assert.deepEqual(calls[0].args.predeal_anchor,Array(32).fill(171));
 assert.equal(s.data.deckReady,true);
 assert.equal(s.data.terms,undefined,'funding terms are still unknown');
 assert.equal(s.data.dealt,undefined,'final score exchange must still happen after binding');
});
test('continuation promotes the prepared worker and transfers the in-memory funding key',async()=>{
 const originalFetch=globalThis.fetch,originalLocation=globalThis.location;
 const frames=[],s=new TableSession({},state=>frames.push(state.activeSession));
 const warm=new TableSession({},()=>{});
 const next={gameId:'ab'.repeat(32),inviteSecret:'cd'.repeat(32),tip:'payout:0'};
 s.data={gameId:'ef'.repeat(32),sender:'bob',playerToken:'old-token',engine:'engine',terms:{fee_multiplier:1},wantsNext:true,peer:{nextready:{tip:next.tip},next},nextToken:'next-token'};
 s.view={terminal:true,tip:next.tip};s.fundingKey='private-memory-only';
 s.save=s.send=warm.save=async()=>{};
 const info={previous:'payout',nextStacks:[19400,20600],role:1,button:0};
 s.player={call:async()=>info,close:()=>{}};
 const preparedWorker={close:()=>{throw Error('prepared worker must stay alive');}};
 warm.player=preparedWorker;warm.background=true;warm.data={gameId:next.gameId,sender:'bob',deckReady:true};
 let stepped=0;warm.step=async()=>{stepped++;};s.nextSession=warm;
 globalThis.fetch=async()=>({ok:true,json:async()=>({})});globalThis.location={hash:''};
 try {
  await s.continueHand();
  assert.equal(warm.player,preparedWorker);
  assert.equal(warm.background,false);
  assert.equal(warm.data.deckReady,true);
  assert.equal(warm.data.predealOnly,false);
  assert.equal(warm.data.continuation.previous,'payout');
  assert.equal(warm.fundingKey,'private-memory-only');
  assert.equal(s.fundingKey,null);
  assert.equal(s.stopped,true);
  assert.equal(frames.at(-1),warm);
  assert.equal(stepped,1);
 }finally{
  clearInterval(warm.timer);globalThis.fetch=originalFetch;globalThis.location=originalLocation;
 }
});

test('test wallet survives reload and follows consecutive hands without entering it again',async()=>{
 const records=new Map();
 const store={read:async(_table,id)=>records.get(id),load:async(id,binding)=>{assert.equal(records.get(id).binding,binding);return records.get(id).bytes;},save:async(id,binding,bytes)=>records.set(id,{binding,bytes})};
 const original=new TableSession({},()=>{});
 original.data={gameId:'first',sender:'alice'};
 await original.rememberFundingKey('01'.repeat(32),store);
 await store.save('first-alice','table-v1',encodeBinary(original.data));
 original.close();
 const next=new TableSession({},()=>{});
 next.data={gameId:'second',sender:'alice',previous:{gameId:'first',sender:'alice'}};
 await next.restoreFundingKey(store);
 assert.equal(next.fundingKey,'01'.repeat(32));
 assert.equal(next.data.fundingWalletId,'first');
 assert.equal(JSON.stringify(next.data).includes('01'.repeat(32)),false,'secret stays outside controller snapshots and render data');
 const unrelated=new TableSession({},()=>{});
 unrelated.data={gameId:'unrelated',sender:'alice'};
 await unrelated.restoreFundingKey(store);
 assert.equal(unrelated.fundingKey,undefined,'new tables cannot inherit another table wallet');
 const guest=new TableSession({},()=>{});
 guest.data={gameId:'second',sender:'bob',fundingWalletId:'first'};
 await guest.restoreFundingKey(store);
 assert.equal(guest.fundingKey,undefined,'guest does not load host wallet');
});
test('wallet availability reaches the UI without exposing the secret',()=>{
 let rendered;
 const s=new TableSession({},state=>{rendered=state;});
 s.data={sender:'alice'};s.fundingKey='02'.repeat(32);
 s.notify();
 assert.equal(rendered.hasFundingWallet,true);
 assert.equal(Object.hasOwn(rendered,'fundingKey'),false);
});


test("poll retries retain an error until successful recovery, without flashing shuffling", async () => {
  const s = new TableSession({}, () => {});
  const states = [];
  s.notify = () => states.push(s.error);
  s.error = "Connection failed";
  s.tick = async () => {
    s.stage = "Shuffling together";
    s.notify();
    throw new Error("Connection failed");
  };
  await s.step();
  await s.step();
  assert.ok(states.every(error => error === "Connection failed"));
  s.tick = async () => { s.stage = "Shuffling together"; s.notify(); };
  s.pollRetryAt=0;
  await s.step();
  assert.equal(states.at(-2), "Connection failed");
  assert.equal(states.at(-1), null);
});

test('leave is available only while settled and sitting out, and responds before storage', async()=>{
  const s=new TableSession({},()=>{}); s.data={sitOutNext:true};s.view={terminal:false};
  let saves=0,steps=0; s.save=async()=>{saves++;assert.equal(s.data.leaveRequested,true);assert.equal(s.stage,'Cashing out…');};s.step=async()=>steps++;
  await s.leaveTable();assert.equal(saves,0);
  s.view.terminal=true;await s.leaveTable();await s.leaveTable();assert.equal(saves,1);assert.equal(steps,1);
});
test('cooperative cashout pays canonical wallets and resumes the same transaction',async()=>{
  const s=new TableSession({},()=>{});s.data={peer:{leave:{hand:'hand',node:'end'},wallet:{script:'bb'}},sent:{}};
  s.view={terminal:true,hand:'hand',node:'end',role:1};
  let refreshed=0,signed=0,published=0;
  s.localWallet={script:'aa',refresh:async()=>refreshed++};s.save=async()=>{};s.send=async()=>{};
  s.player={call:async(method,args)=>{signed++;assert.equal(method,'cashout');assert.deepEqual(args.scripts,[[187],[170]]);return {...s.view,cashout:'0102'};}};
  s.publish=async raw=>{published++;assert.deepEqual([...raw],[1,2]);return {txid:'11'.repeat(32),outputs:[1,2]};};
  s.chain={transactionStatus:async()=>({state:published===1?'mempool':'confirmed'})};
  await s.cashOut();assert.equal(s.data.left,undefined);
  await s.cashOut();assert.equal(published,1);s.cashoutCheckAt=0;
  await s.cashOut();assert.equal(signed,1);assert.equal(published,2);assert.equal(refreshed,1);assert.equal(s.data.left,true);
});
test('cashout refuses a different terminal and a committed handoff',async()=>{
  const s=new TableSession({},()=>{});s.view={terminal:true,hand:'hand',node:'end'};
  s.data={peer:{leave:{hand:'wrong',node:'end'}}};await assert.rejects(()=>s.cashOut(),/settlement mismatch/);
  s.data.handoffStarted=true;await assert.rejects(()=>s.cashOut(),/hand transition/);
});
test('a saved signed cashout completes with the relay and opponent offline',async()=>{
  const s=new TableSession({},()=>{});
  s.data={cashout:'0102',peer:{},leaveRequested:true};
  s.view={terminal:true,hand:'hand',node:'end'};
  s.save=async()=>{};
  s.flush=s.receive=s.send=async()=>assert.fail('signed cashout must not require the relay');
  s.player={call:async()=>assert.fail('must not sign a replacement cashout')};
  s.localWallet={refresh:async()=>{}};
  s.publish=async raw=>{assert.deepEqual([...raw],[1,2]);return {txid:'11'.repeat(32),outputs:[]};};
  s.chain={transactionStatus:async()=>({state:'confirmed'})};
  await s.tick();
  assert.equal(s.data.left,true);
  assert.equal(s.stage,'Funds returned');
});
test('missing cashout code pauses with the signed transaction intact instead of reconnecting forever',async()=>{
  const s=new TableSession({},()=>{});
  s.data={cashout:'0102',leaveRequested:true};
  let attempts=0;
  s.tick=async()=>{attempts++;throw Error('call: Wasm artifact request failed (404): transaction')};
  await s.step();
  assert.equal(s.stage,'Cashout paused');
  assert.equal(s.pollPaused,true);
  s.pollRetryAt=0;await s.step();
  assert.equal(attempts,1);
  assert.equal(s.data.cashout,'0102');
});
test('protocol polling accelerates transitions, stops on failure, and stays idle for poker decisions', async () => {
  for (const [view, data, fails, scheduled] of [
    [{betting: true}, {}, false, false],
    [{betting: true, pendingMove: true}, {}, false, true],
    [{betting: false, terminal: false}, {}, false, true],
    [{terminal: true}, {wantsNext: true}, false, true],
    [{terminal: true}, {wantsNext: true, sitOutNext: true}, false, false],
    [{betting: false}, {}, true, false],
  ]) {
    const s = new TableSession({}, () => {});
    s.data = {peer: {}, ...data}; s.view = view;
    s.tick = async () => { if (fails) throw new Error('failed'); };
    await s.step();
    assert.equal(s.protocolTimer !== undefined, scheduled);
    s.close();
  }
});
test('background candidates consume peer readiness before advancing preparation',async()=>{
 const s=new TableSession({},()=>{});s.data={bufferCandidate:true,peer:{}};
 s.flush=async()=>{};s.receive=async()=>{s.data.peer.ready={binding:'verified'};return false;};
 s.advanceChannel=async()=>assert.equal(s.data.peer.ready.binding,'verified');
 await s.tickPredeal();
});
test('completed background sessions do not restart fast protocol polling',async()=>{
 const s=new TableSession({},()=>{});s.background=true;s.data={peer:{}};s.view={betting:false,terminal:false};s.tick=async()=>{};
 await s.step();assert.equal(s.protocolTimer,undefined);s.close();
});


test('funding submission is durable and rate limited across polls and uncertain responses',async()=>{
 const s=new TableSession({},()=>{});s.data={};let submissions=0,saves=0;
 s.save=async()=>{saves++};s.publish=async()=>{assert.ok(s.data.fundingRetryAt);submissions++};
 await s.publishFunding(new Uint8Array(),1000);
 for(let i=0;i<100;i++)await s.publishFunding(new Uint8Array(),2000+i);
 assert.equal(submissions,1);assert.equal(saves,2);
 s.publish=async()=>{submissions++;throw Error('response lost')};
 await assert.rejects(s.publishFunding(new Uint8Array(),31000),/response lost/);
 await s.publishFunding(new Uint8Array(),31001);assert.equal(submissions,2);
});

test('rate-limited table polls back off instead of retrying at the UI tick rate',async()=>{
 const s=new TableSession({},()=>{});s.data={};let calls=0;
 s.notify=()=>{};s.tick=async()=>{calls++;throw Error('Esplora returned HTTP 429')};
 await s.step();for(let i=0;i<100;i++)await s.step();assert.equal(calls,1);assert.ok(s.pollRetryAt>Date.now());
 s.pollRetryAt=0;s.tick=async()=>{calls++};await s.step();assert.equal(calls,2);assert.equal(s.pollFailures,0);assert.equal(s.error,null);
});

test('initial dealer runs before wallet funding and stops before final binding',async()=>{
 const s=new TableSession({},()=>{});s.data={gameId:'01'.repeat(32),peer:{}};s.keys=()=>[{identity:[],reveal:[]},{identity:[],reveal:[]}];s.save=async()=>{};
 const calls=[];let finish;
 s.player={call:async(method,args)=>{calls.push(method);if(method==='configurePredeal'){assert.equal(args.origin_value,45000);assert.equal(args.predeal_anchor.length,32);return;}return new Promise(resolve=>finish=resolve)}};
 const plan={nonce:Array(32).fill(2),multiplier:0.1,reserve:4900};
 await s.startInitialDeal(plan,45000);assert.deepEqual(calls,['configurePredeal','deal']);assert.equal(s.data.funded,undefined);
 await s.startInitialDeal(plan,45000);assert.equal(calls.length,2,'only one dealer loop');
 s.initialDealBinding=true;finish({accepted:false});await s.initialDealTask;assert.equal(calls.length,2);
});

test('mempool buy-ins permit preparation but cannot pass the funding-release confirmation gate',async()=>{
 const s=new TableSession({},()=>{}),coin={previous:'01',vout:0,script:'aa'};
 s.wallet={call:async()=>({txid:'01'.repeat(32),outputs:[{script:'aa',value:25000}]})};
 let state='mempool';s.chain={outpointStatus:async()=>({state:'unspent',creatingStatus:{state}})};
 assert.equal(await s.checkBuyInCoins({coins:[coin,coin]},false),true);
 assert.equal(await s.checkBuyInCoins({coins:[coin,coin]},true),false);
 state='confirmed';assert.equal(await s.checkBuyInCoins({coins:[coin,coin]},true),true);
 s.chain.outpointStatus=async()=>({state:'spent'});await assert.rejects(s.checkBuyInCoins({coins:[coin]},false),/unavailable/);
});

test('prepared tables with pending buy-in parents do not release funding signatures',async()=>{
 const s=new TableSession({},()=>{});s.data={sender:'alice',proposal:{buyin:{coins:[]}},prepared:{binding:'b'},peer:{ready:{binding:'b'}}};
 s.send=async()=>{};s.save=async()=>{};s.player={call:async()=>({recoveryReady:true})};
 let confirmed=false,checks=0,signatures=0;s.checkBuyInCoins=async()=>{checks++;return confirmed};
 s.wallet={call:async method=>{assert.equal(method,'buyinSign');signatures++;return new Uint8Array(64)}};s.localWallet={secret:'01'.repeat(32)};
 for(let i=0;i<20;i++)await s.advanceChannel();assert.equal(checks,1);assert.equal(signatures,0);
 confirmed=true;s.fundingParentsCheckAt=0;await s.advanceChannel();assert.equal(signatures,1);assert.equal(s.data.fundingInputsConfirmed,true);
});

test('both seats derive the same opening plan without a negotiation round trip',async()=>{
 const plans=[];
 for(const sender of ['alice','bob']) {
  const s=new TableSession({},()=>{});s.data={gameId:'12'.repeat(32),sender,peer:{}};
  let quotes=0;s.requiredReserve=async rate=>{assert.equal(rate,0.1);quotes++;return 4500};s.save=async()=>{};
  s.send=async()=>assert.fail('opening plan should not need a relay message');
  plans.push(await s.openingPlan());assert.equal(await s.openingPlan(),plans.at(-1));assert.equal(quotes,1);
 }
 assert.deepEqual(plans[0],plans[1]);assert.deepEqual(plans[0].nonce,Array(32).fill(0x12));
});


test('closing a seat preserves the lobby funding worker',()=>{
  const session=new TableSession({},()=>{});let walletClosed=0,playerClosed=0;
  session.data={gameId:'closing-seat',sender:'alice'};
  session.wallet={close:()=>walletClosed++};session.sharedWallet=true;
  session.player={close:()=>playerClosed++};session.close();
  assert.equal(walletClosed,0);assert.equal(playerClosed,1);
});

function sharedBuyInFixture() {
  const coins=[0,1].map(vout=>({txid:'11'.repeat(32),vout,value:30000,status:{confirmed:true}}));
  let previews=0,refreshes=0;
  const seats=['alice','bob'].map(sender=>{
    const s=new TableSession({},()=>{});
    s.data={gameId:'22'.repeat(32),sender,peer:{wallet:{script:'aa'}},sent:{}};
    s.localWallet={script:'aa',refresh:async()=>{refreshes++;return coins;}};
    s.openingPlan=async()=>({multiplier:0.1,reserve:4500,nonce:Array(32).fill(2)});
    s.startInitialDeal=async()=>{};s.save=async()=>{};
    s.keys=()=>[{identity:[],reveal:[]},{identity:[],reveal:[]}];
    s.chain={rawTransaction:async()=>({raw:new Uint8Array([1])})};
    s.wallet={call:async(method,args)=>{
      if(method==='inspect')return {txid:'11'.repeat(32)};
      assert.equal(method,'buyinPreview');previews++;
      assert.notEqual(args.coins[0].vout,args.coins[1].vout,'funding must never repeat an outpoint');
      return new Uint8Array([2]);
    }};
    return s;
  });
  seats.forEach((s,i)=>s.send=async(kind,value)=>{seats[1-i].data.peer[kind]=structuredClone(value);});
  return {seats,coins,previews:()=>previews,refreshes:()=>refreshes};
}

test('shared-wallet seats choose distinct outputs even when the guest polls first',async()=>{
  const {seats:[host,guest],previews,refreshes}=sharedBuyInFixture();
  await guest.prepareBuyIn();assert.equal(refreshes(),0);assert.equal(guest.data.buyincoin,undefined);
  await host.prepareBuyIn();assert.equal(host.data.buyincoin.vout,0);assert.equal(previews(),0);
  await guest.prepareBuyIn();assert.equal(guest.data.buyincoin.vout,1);
  await host.prepareBuyIn();assert.equal(previews(),1);assert.ok(host.data.proposal);
});

test('one shared output waits for another payment without submitting duplicate funding',async()=>{
  const {seats:[host,guest],coins,previews,refreshes}=sharedBuyInFixture();coins.pop();
  await host.prepareBuyIn();await guest.prepareBuyIn();
  assert.equal(guest.data.buyincoin,undefined);assert.ok(guest.data.walletNeeded);
  assert.equal(guest.stage,'Send another payment to this wallet');
  const reads=refreshes();for(let i=0;i<20;i++){await guest.prepareBuyIn();await host.prepareBuyIn();}
  assert.equal(refreshes(),reads);assert.equal(previews(),0);
  coins.push({...coins[0],vout:1});guest.walletCheckAt=0;
  await guest.prepareBuyIn();await host.prepareBuyIn();
  assert.equal(guest.data.walletNeeded,undefined);assert.equal(previews(),1);
});

test('separate wallets still select their buy-ins in parallel',async()=>{
  const {seats:[,guest]}=sharedBuyInFixture();guest.data.peer.wallet.script='bb';
  await guest.prepareBuyIn();assert.equal(guest.data.buyincoin.vout,0);
});

test('interrupted preparation reopens its durable worker before retrying',async t=>{
 for(const reason of ['Relay connection interrupted','Preparation exchange timed out']) {
  const s=new TableSession({},()=>{});s.data={gameId:'test',sender:'alice'};
  let polls=0,closed=0,opened=0;
  s.player={close(){closed++}};
  s.tick=async()=>{if(++polls===1)throw Error(reason);assert.equal(opened,1);};
  s.openPlayer=async()=>{opened++;};
  t.after(()=>{clearInterval(s.timer);clearTimeout(s.protocolTimer)});
  await s.step();assert.equal(s.reconnectRequired,true);assert.equal(opened,0);
  s.pollRetryAt=0;await s.step();
  assert.equal(closed,1);assert.equal(opened,1);assert.equal(polls,2);
  assert.equal(s.error,null);assert.equal(s.reconnectRequired,false);
 }
});

test('a verification failure is not retried by replacing its worker',async()=>{
 const s=new TableSession({},()=>{});s.data={gameId:'test',sender:'alice'};
 s.tick=async()=>{throw Error('Inventory disagreement')};
 s.openPlayer=async()=>assert.fail('must retain a protocol failure');
 await s.step();s.pollRetryAt=0;await s.step();
 assert.equal(s.error,'Inventory disagreement');assert.ok(!s.reconnectRequired);
});


test('selected future hand progresses entry promptly without activating unused candidates',async()=>{
 const s=new TableSession({},()=>{});s.background=true;s.data={entrySelected:true,peer:{}};
 s.view={betting:false,terminal:false};s.tick=async()=>{};
 try {await s.step();assert.ok(s.protocolTimer);} finally {s.close();}
});
