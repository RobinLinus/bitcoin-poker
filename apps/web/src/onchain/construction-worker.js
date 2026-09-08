import {client} from './wasm-client.js';
// A private snapshot is delegated locally, never sent through the relay.
self.onmessage=async({data:{id,args}})=>{
  try {
    const started=performance.now(), wasm=await client(args.module);
    const instantiated=performance.now();
    const receipt=wasm.call(54,args.job);
    postMessage({id,value:{receipt,constructionMs:performance.now()-started,
      phases:{instantiateMs:instantiated-started,inventoryMs:performance.now()-instantiated}}},[receipt.buffer]);
  } catch(error) {postMessage({id,error:error.message});}
};
