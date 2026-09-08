import test from 'node:test';
import assert from 'node:assert/strict';
import { enrichDisplayView } from './display-view.js';
const view = { tip:'tx:0', node:'node', role:1, terminal:false, betting:true, pot:300, stacks:[19800,19900], actions:[{index:2,kind:'Action(Call)'},{index:3,kind:'Action(Raise)'}] };
const checked = { ...view, roundBets:[200,100], revealing:false, actions:[{index:2,kind:'Action(Call)',betAmount:100},{index:3,kind:'Action(Raise)',betAmount:300}] };
test('saved games gain per-seat wagers and immediate bet amounts without replacing legal actions',()=>{
 const enriched = enrichDisplayView(view, checked);
 assert.deepEqual(enriched.roundBets,[200,100]);
 assert.equal(enriched.actions[0].betAmount,100);
 assert.equal(enriched.actions[1].betAmount,300);
 assert.equal(view.roundBets,undefined);
 assert.equal(view.actions[0].betAmount,undefined);
});
test('a mismatched replay cannot change the table display',()=>{
 for(const patch of [{tip:'other'},{node:'other'},{role:0},{stacks:[19700,19800]},{pot:500},{betting:false},{terminal:true}]) {
  assert.equal(enrichDisplayView(view,{...checked,...patch}),view);
 }
 const enriched = enrichDisplayView(view,{...checked,actions:[{index:2,kind:'Action(Fold)',betAmount:200}]});
 assert.equal(enriched.actions[0].betAmount,undefined);
});
