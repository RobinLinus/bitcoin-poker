import test from "node:test";
import assert from "node:assert/strict";
import { TableSession } from "./table-session.js";
import { tableFeedback, tableActivity, idleFeedback, playerError } from "./table-feedback.js";

function setup() {
  const frames = [];
  const session = new TableSession({}, (state) => frames.push(tableFeedback(state)));
  session.data = {};
  session.view = { channelReady:true, tip: "tip", node: "node", betting: true, role: 1, roundBets: [200, 100], actions: [{ index: 0, kind: "Action(Call)", betAmount: 100 }] };
  session.save = async () => {};
  session.publish = async () => {};
  return { session, frames };
}
test("click feedback and projected chips precede signing; confirmation retains the wager", async () => {
  const { session, frames } = setup();
  let finish;
  session.player = { call: (method) => method === "action" ? new Promise((resolve) => { finish = resolve; }) : Promise.resolve() };
  const action = session.act(0);
  assert.equal(frames[0].title, "Sending your move…");
  assert.deepEqual(frames.at(-1).roundBets, [200, 200]);
  assert.equal(session.data.pending, undefined);
  finish({...session.view,pendingMove:true});
  await action;
  assert.equal(frames.at(-1).title, "Playing your move…");
  assert.deepEqual(frames.at(-1).roundBets, [200, 200]);
});
test("failed signing restores confirmed chips and releases the action", async () => {
  const { session, frames } = setup();
  session.player = { call: async () => { throw new Error("Signing failed"); } };
  await session.act(0);
  assert.equal(session.busy, false);
  assert.equal(session.submission, null);
  assert.deepEqual(frames.at(-1).roundBets, [200, 100]);
  assert.equal(session.error, "Signing failed");
});
test("automatic reveals have distinct progress and confirmation text", async () => {
  const { session, frames } = setup();
  session.view = { tip: "tip", revealing: true, role: 0 };
  session.player = { call: async () => ({...session.view,pendingMove:true}) };
  await session.submit(null);
  assert.equal(frames[0].title, "Dealing cards…");
  assert.equal(frames.at(-1).title, "Dealing cards…");
});
test("a new street or settled hand clears the displayed wager", () => {
  assert.deepEqual(tableFeedback({ data: {}, view: { roundBets: [0, 0] } }).roundBets, [0, 0]);
  assert.deepEqual(tableFeedback({ data: { pending: true, pendingInfo: { roundBets: [200, 200] } }, view: { terminal: true } }).roundBets, [0, 0]);
});
test("dealing copy names the street while preparing, waiting, or resuming", () => {
  const data = { peer: {} };
  for (const [phase, title] of [
    ["Some(DealAlice)", "Dealing hole cards…"],
    ["Some(DealBob)", "Dealing hole cards…"],
    ["Some(FlopRevealFirst)", "Dealing flop…"],
    ["Some(FlopRevealSecond)", "Dealing flop…"],
    ["Some(TurnRevealFirst)", "Dealing turn card…"],
    ["Some(TurnRevealSecond)", "Dealing turn card…"],
    ["Some(RiverRevealFirst)", "Dealing river card…"],
    ["Some(RiverRevealSecond)", "Dealing river card…"],
  ]) {
    const view = { node: "node", tip: "tip", betting: false, phase };
    assert.equal(idleFeedback({ data, view }).title, title);
    assert.equal(tableFeedback({ data, view, submission: { node: "node", kind: "reveal" } }).title, title);
    assert.equal(tableFeedback({ data, view: { ...view, pending: "tx" } }).title, title);
    assert.equal(tableFeedback({ data: { ...data, pending: "tx", pendingInfo: { kind: "reveal" } }, view }).title, title);
  }
});

test("idle copy explains the next step without internal stage names", () => {
  const data = { peer: { keys: {} } };
  assert.deepEqual(idleFeedback({ data, stage: "Preparing the full game", progress: { done: 3, total: 4 } }), { title: "Getting the table ready…", detail: "" });
  assert.equal(idleFeedback({ data, view: { tip: "tip", revealing: true } }).title, "Dealing cards…");
  assert.equal(idleFeedback({ data: { ...data, wantsNext: true }, view: { terminal: true } }).detail, "Waiting for your opponent…");
  assert.equal(idleFeedback({ data, stage: "unknown internal stage" }).title, "Getting the table ready…");
});
test("errors preserve useful next steps and keep diagnostics out of the main UI", () => {
  assert.match(playerError("Funding pays the wrong escrow script."), /could not be verified/);
  assert.match(playerError("Invalid wallet key."), /wallet’s private key/);
  assert.match(playerError("Paste a valid table invitation."), /invite link/);
  assert.match(playerError("Unexpected setup frame onchain.score"), /Try reconnecting/);
  const funding = "This wallet needs a single payment of at least ₿50,000 in funds. Send it to tb1test, wait for it to arrive, then try again.";
  assert.equal(playerError(funding), funding);
});
test("bet chips appear during an in-flight poll and disappear if the turn changes", async () => {
  const { session, frames } = setup();
  session.data.gameId = 'table';
  let finish;
  session.tick = () => new Promise(resolve => { finish = () => { session.view = { ...session.view, node:'next', roundBets:[0,0] }; resolve(); }; });
  const poll = session.step();
  await Promise.resolve();
  const click = session.act(0);
  assert.deepEqual(frames.at(-1).roundBets,[200,200]);
  finish();
  await poll;
  await click;
  assert.deepEqual(frames.at(-1).roundBets,[0,0]);
});


test('opening blinds stay in front of their owners throughout hole-card delivery',()=>{
 for (const phase of ['Some(DealAlice)','Some(DealBob)']) {
  for (const blinds of [[100,200],[200,100]]) {
   const data={terms:{stacks:[19000,21000]},pending:'tx',pendingInfo:{roundBets:[0,0]}};
   const view={phase,tip:'active',pot:300,stacks:[19000-blinds[0],21000-blinds[1]],roundBets:[0,0]};
   assert.deepEqual(tableFeedback({data,view}).roundBets,blinds);
   assert.deepEqual(tableFeedback({data,view:{...view,terminal:true}}).roundBets,[0,0]);
   assert.deepEqual(tableFeedback({data:{terms:data.terms},view:{...view,phase:'Some(FlopRevealFirst)'}}).roundBets,[0,0]);
  }
 }
});


test('a shared-wallet input shortage asks for another payment',()=>{
  assert.equal(idleFeedback({data:{walletNeeded:23000,walletSeparatePayment:true}}).title,'Send another payment to this wallet');
  assert.equal(idleFeedback({data:{walletNeeded:23000}}).title,'Waiting for wallet funds');
});


test("pending moves animate only their actor from either seat", () => {
  for (const actor of [0, 1]) for (const role of [0, 1]) {
    const view = {betting:true, actor, role, pendingMove:true};
    for (const submission of [null, ...(actor === role ? [{kind:"action"}] : [])]) {
      const activity = tableActivity({data:{}, view, submission});
      assert.equal(activity.local, actor === role);
      assert.equal(activity.opponent, actor !== role);
    }
    const idle = tableActivity({data:{},view:{...view,pendingMove:false}});
    assert.equal(idle.local || idle.opponent, false);
  }
});
test("dealing, cashout and errors never animate player seats", () => {
  for (const state of [
    {view:{betting:false,phase:"FlopRevealFirst",pendingMove:true}},
    {view:{terminal:true,pendingMove:true}},
    {data:{leaveRequested:true},view:{betting:true,pendingMove:true,actor:0,role:0}},
    {error:"Disconnected",view:{betting:true,pendingMove:true,actor:0,role:0}},
  ]) {
    const activity=tableActivity({data:{peer:{}},...state});
    assert.equal(activity.local || activity.opponent, false);
  }
});
