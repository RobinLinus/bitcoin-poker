import test from 'node:test';
import assert from 'node:assert/strict';
import {trace,traceState,traceOperation,pokerLog,acceptDiagnostic} from './diagnostics.js';
test('timestamped copyable logs omit unknown fields, redact error secrets and suppress repeated state',()=>{
 const original=console.info,lines=[];console.info=line=>lines.push(line);
 try {
  trace('test',{stage:'Preparing',seed:'secret',payload:[1,2,3],error:'invalid '+ 'ab'.repeat(32)});
  assert.match(lines[0],/\[poker \d{4}-\d{2}-\d{2}T/);
  assert.ok(!lines[0].includes('secret'));assert.ok(!lines[0].includes('abab'));assert.ok(!lines[0].includes('payload'));
  traceState('test','state',{stage:'Waiting'});traceState('test','state',{stage:'Waiting'});assert.equal(lines.length,2);
  traceState('test','state',{stage:'Ready'});assert.equal(lines.length,3);
  const end=traceOperation('work',{method:'prepare'});end();end();assert.equal(lines.length,5);assert.match(lines.at(-1),/durationMs/);
  acceptDiagnostic({timestamp:'2026-09-07T00:00:00.000Z',event:'worker.waiting',method:'prepare',seed:'secret'});
  assert.match(pokerLog(),/worker.waiting/);assert.ok(!lines.at(-1).includes('secret'));
  for(let i=0;i<2001;i++)trace('bounded',{messages:i});assert.equal(pokerLog().split('\n').length,2000);
 } finally {console.info=original;}
});
test('pending operations report waits and stop their timer on failure',()=>{
 const interval=globalThis.setInterval,clear=globalThis.clearInterval,info=console.info;
 let tick,cleared=false;const lines=[];
 globalThis.setInterval=callback=>{tick=callback;return 1};globalThis.clearInterval=()=>{cleared=true};console.info=line=>lines.push(line);
 try {const end=traceOperation('network',{},true);assert.equal(lines.length,0);tick();assert.match(lines[0],/network.waiting/);end(Error('offline'));assert.equal(cleared,true);assert.match(lines[1],/network.error/);}finally{globalThis.setInterval=interval;globalThis.clearInterval=clear;console.info=info;}
});
