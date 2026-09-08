import test from 'node:test';
import assert from 'node:assert/strict';
import {encodeBinary,decodeBinary,encodeProtocol,decodeProtocol} from './binary-codec.js';
import {preparationBatches,packPreparation,unpackPreparation} from './preparation-wire.js';

test('binary envelopes preserve raw bytes through nested durable records',()=>{
 const value={seed:new Uint8Array([0,128,255]),outbox:[{payload:new Uint8Array(65536).fill(254)}],empty:new Uint8Array()};
 const frame=encodeBinary(value);
 assert.deepEqual(decodeBinary(frame),value);
 assert.ok(frame.length<66000,'raw bytes have no base64 expansion');
 assert.deepEqual(decodeBinary(frame.subarray(0)),value);
});
test('protocol byte arrays roundtrip without changing ordinary numeric arrays',()=>{
 const value={signature:Array.from({length:64},(_,i)=>i),amounts:[1000,2000],empty:[],nested:[[1,2,3]]};
 assert.deepEqual(decodeProtocol(encodeProtocol(value)),value);
});
test('binary decoder rejects malformed headers, missing attachments and extra data',()=>{
 const frame=encodeBinary({data:new Uint8Array([1,2,3])});
 for(let n=0;n<frame.length;n++)assert.throws(()=>decodeBinary(frame.slice(0,n)));
 assert.throws(()=>decodeBinary(new Uint8Array([...frame,0])));
 const bad=frame.slice();bad[0]=0;assert.throws(()=>decodeBinary(bad));
 assert.throws(()=>decodeBinary(encodeBinary({data:{$b:1,n:0}})),/attachment/);
 assert.throws(()=>decodeBinary(encodeBinary({data:{$b:0,n:-1}})),/attachment/);
});
test('packed signing batches reconstruct exact indices and sizes by role and phase',()=>{
 const manifest=new Uint8Array([0,0,1,0,0,1,1,1,0,0]);
 const jobs=preparationBatches(manifest,0,[0,1,2,3,4]);
 assert.deepEqual(jobs,[[0,2,4]]);
 const sizes=[64,3412,64], original=new Uint8Array(sizes.reduce((a,b)=>a+b+8,0)),view=new DataView(original.buffer);
 let offset=0;for(let j=0;j<3;j++){view.setUint32(offset,jobs[0][j],true);view.setUint32(offset+4,sizes[j],true);original.fill(j+1,offset+8,offset+8+sizes[j]);offset+=8+sizes[j];}
 const packed=packPreparation(original,jobs[0],manifest,0);
 assert.deepEqual(unpackPreparation(packed,jobs,manifest),original);
 assert.equal(original.length-packed.length,20);
 assert.throws(()=>unpackPreparation(packed.slice(1),jobs,manifest));
 assert.throws(()=>unpackPreparation(packed,preparationBatches(manifest,1,[1,3]),manifest));
 const bad=packed.slice();new DataView(bad.buffer).setUint32(0,9,true);assert.throws(()=>unpackPreparation(bad,jobs,manifest));
 assert.throws(()=>packPreparation(original,[4,2,0],manifest,0));
});
