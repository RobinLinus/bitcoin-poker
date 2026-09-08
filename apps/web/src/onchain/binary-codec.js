// A bounded JSON header with raw byte attachments. No base64 or decimal byte arrays.
const encoder=new TextEncoder(),decoder=new TextDecoder('utf-8',{fatal:true});
const MAGIC=0x31424b50,MAX=24*1024*1024;
export function encodeBinary(value) {
  const blobs=[];
  const json=encoder.encode(JSON.stringify(value,(_,v)=>{
    if(v instanceof Uint8Array){const index=blobs.length;blobs.push(v);return {$b:index,n:v.length};}
    return v;
  }));
  const size=8+json.length+blobs.reduce((n,b)=>n+b.length,0);
  if(size>MAX)throw Error('Binary frame too large');
  const out=new Uint8Array(size),view=new DataView(out.buffer);
  view.setUint32(0,MAGIC,true);view.setUint32(4,json.length,true);out.set(json,8);
  let offset=8+json.length;for(const blob of blobs){out.set(blob,offset);offset+=blob.length;}
  return out;
}
export function decodeBinary(input) {
  const bytes=input instanceof Uint8Array?input:new Uint8Array(input);
  if(bytes.length<8||bytes.length>MAX)throw Error('Invalid binary frame');
  const view=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),length=view.getUint32(4,true);
  if(view.getUint32(0,true)!==MAGIC||length>bytes.length-8)throw Error('Invalid binary header');
  let offset=8+length,index=0;
  const value=JSON.parse(decoder.decode(bytes.subarray(8,offset)),(_,v)=>{
    if(v && typeof v==='object' && Object.hasOwn(v,'$b')) {
      if(Object.keys(v).length!==2||v.$b!==index++||!Number.isSafeInteger(v.n)||v.n<0||v.n>bytes.length-offset)throw Error('Invalid binary attachment');
      const data=bytes.slice(offset,offset+v.n);offset+=v.n;return data;
    }
    return v;
  });
  if(offset!==bytes.length)throw Error('Trailing binary data');
  return value;
}
export const binaryEqual=(a,b)=>a instanceof Uint8Array && b instanceof Uint8Array && a.length===b.length && a.every((n,i)=>n===b[i]);
const mapBytes=(value,pack)=>{
  if(value instanceof Uint8Array)return pack?value:Array.from(value);
  if(Array.isArray(value))return pack && value.length && value.every(n=>Number.isInteger(n)&&n>=0&&n<=255)?Uint8Array.from(value):value.map(v=>mapBytes(v,pack));
  if(value && typeof value==='object')return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,mapBytes(v,pack)]));
  return value;
};
export const encodeProtocol=value=>encodeBinary(mapBytes(value,true));
export const decodeProtocol=value=>mapBytes(decodeBinary(value),false);
export const isBinary=value=>value instanceof Uint8Array && value.length>=8 && new DataView(value.buffer,value.byteOffset,value.byteLength).getUint32(0,true)===MAGIC;
