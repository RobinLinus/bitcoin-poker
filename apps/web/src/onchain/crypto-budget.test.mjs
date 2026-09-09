import test from 'node:test';
import assert from 'node:assert/strict';
import {cryptoWorkersPerOwner as count} from './crypto-pool.js';
test('crypto workers share a core budget across both owners and leave room for play',()=>{
  for(const [cores,foreground,background] of [[2,1,1],[4,1,1],[8,3,1],[15,6,3],[32,8,4]]) {
    assert.equal(count({cores,memory:8}),foreground);
    assert.equal(count({cores,memory:8,background:true}),background);
  }
  assert.equal(count({cores:32,memory:2}),1);
  assert.equal(count({cores:32,memory:4}),3);
  assert.equal(count({cores:NaN}),1);
  assert.equal(count({cores:32,full:false}),1);
});
