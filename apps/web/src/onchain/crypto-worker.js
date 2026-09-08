import { client, encode } from "./wasm-client.js";
let wasm, speculative=false, priority;
self.onmessage = async ({ data: { id, method, args } }) => {
  try {
    if(method === "init") {speculative=!!args.speculative;priority=args.priority;}
    const execute=async()=>{
      let value;
      if (method === "init") {
        wasm = await client(args.module);
        const { inventory, ...metadata } = args.context;
        const header = encode(metadata);
        const frame = new Uint8Array(4 + header.length + inventory.length);
        new DataView(frame.buffer).setUint32(0, header.length, true);
        frame.set(header, 4);
        frame.set(inventory, 4 + header.length);
        wasm.call(34, frame);
        value = wasm.call(33);
      } else if (method === "sign") {
        value = wasm.call(31, args.bytes);
      } else if (method === "signReceipt") {
        value = wasm.call(35, args.bytes);
      } else if (method === "verify") {
        value = wasm.call(32, args.bytes);
      } else throw new Error("Unknown crypto command");
      postMessage({ id, value }, [value.buffer]);
    };
    if(speculative) await navigator.locks.request(priority,{mode:"shared"},execute);
    else await execute();
  } catch (e) {
    postMessage({ id, error: e.message });
  }
};
