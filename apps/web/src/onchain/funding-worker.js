import { client, moduleBytes, encode, decode } from "./wasm-client.js";
let wasm;
self.onmessage = async ({ data: { id, method, args } }) => {
  try {
    if(method==='init') {wasm=await client(args.module);postMessage({id,value:null});return;}
    wasm ??= await client(await WebAssembly.compile(await moduleBytes()));
    let value;
    if (method === "address") value = decode(wasm.call(40, args.secret));
    else if (method === "fund") value = wasm.call(41, encode(args));
    else if (method === "reserve") value = decode(wasm.call(86, encode(args)));
    else if (method === "buyinPreview") value = wasm.call(83, encode(args));
    else if (method === "buyinSign") value = wasm.call(84, encode(args));
    else if (method === "buyinFinish") value = wasm.call(85, encode(args));
    else if (method === "inspect") value = decode(wasm.call(42, args.bytes));
    else if (method === "rollover") value = decode(wasm.call(43, encode(args)));
    else if (method === "rolloverFinish") value = wasm.call(44, encode(args));
    else if (method === "rolloverPreview") value = wasm.call(45, encode(args));
    else throw new Error("Unknown funding command");
    postMessage({ id, value });
  } catch (e) {
    postMessage({ id, error: e.message });
  } finally {
    if (args.secret?.fill) args.secret.fill(0);
  }
};
