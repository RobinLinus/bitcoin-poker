const size=(manifest,i)=>manifest[i*2+1]?3412:64;
export function preparationBatches(manifest,role,work) {
  const allowed=new Set(work),jobs=[];let list=[],bytes=4;
  for(let i=0;i<manifest.length/2;i++) {
    if(manifest[i*2]!==role||!allowed.has(i))continue;
    const n=size(manifest,i);
    if((bytes+n>128*1024 || list.length>=1800) && list.length){jobs.push(list);list=[];bytes=4;}
    list.push(i);bytes+=n;
  }
  if(list.length)jobs.push(list);return jobs;
}
export function packPreparation(bytes,indices,manifest,batchId) {
  const view=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
  const out=new Uint8Array(4+indices.reduce((n,i)=>n+size(manifest,i),0));new DataView(out.buffer).setUint32(0,batchId,true);
  let read=0,write=4;
  for(const i of indices){const n=size(manifest,i);if(read+8+n>bytes.length||view.getUint32(read,true)!==i||view.getUint32(read+4,true)!==n)throw Error('Unexpected signing batch');out.set(bytes.subarray(read+8,read+8+n),write);read+=8+n;write+=n;}
  if(read!==bytes.length)throw Error('Trailing signing bytes');return out;
}
export function unpackPreparation(bytes,jobs,manifest) {
  if(bytes.length<4)throw Error('Truncated signing batch');
  const indices=jobs[new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint32(0,true)];
  if(!indices||bytes.length!==4+indices.reduce((n,i)=>n+size(manifest,i),0))throw Error('Invalid signing batch');
  const out=new Uint8Array(bytes.length-4+indices.length*8),view=new DataView(out.buffer);let read=4,write=0;
  for(const i of indices){const n=size(manifest,i);view.setUint32(write,i,true);view.setUint32(write+4,n,true);out.set(bytes.subarray(read,read+n),write+8);read+=n;write+=8+n;}
  return out;
}
