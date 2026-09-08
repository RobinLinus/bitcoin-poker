import {createServer} from "node:http";
import {readFile,writeFile,mkdir} from "node:fs/promises";
import {fileURLToPath} from "node:url";
const root=new URL("../../",import.meta.url);
const directory=new URL("target/settlement-benchmark/",root);
await mkdir(directory,{recursive:true});
const files=new Map([
  ["/",[new URL("web/index.html",import.meta.url),"text/html"]],
  ["/main.js",[new URL("web/main.js",import.meta.url),"text/javascript"]],
  ["/worker.js",[new URL("web/worker.js",import.meta.url),"text/javascript"]],
  ["/benchmark.wasm",[new URL("target/browser-wasm/wasm32-unknown-unknown/release/settlement_benchmark.wasm",root),"application/wasm"]],
]);
for (const name of ["wasm-client.js", "crypto-worker.js", "parallel-worker.js"]) files.set(`/${name}`, [new URL(`web/${name}`, import.meta.url), "text/javascript"]);
files.set("/verification-pool.js", [new URL("apps/web/src/workers/verification-pool.js", root), "text/javascript"]);
files.set("/preparation-checkpoint-store.js", [new URL("apps/web/src/storage/preparation-checkpoint-store.js", root), "text/javascript"]);
const server=createServer(async(req,res)=>{
  try {
    if(req.method==="POST"&&req.url==="/results") {
      let body="";for await(const chunk of req){body+=chunk;if(body.length>100000){res.writeHead(413).end();return;}}
      const data=JSON.parse(body);
      await writeFile(new URL(data.type==="result"?(data.full?"full.json":"smoke.json"):"progress.json",directory),JSON.stringify(data,null,2)+"\n");
      if(data.type==="result") await writeFile(new URL(`${data.mode === "parallel" ? "parallel" : data.full?"full":"smoke"}-${Date.now()}.json`,directory),JSON.stringify(data,null,2)+"\n");
      res.writeHead(204).end();return;
    }
    const file=files.get(req.url);
    if(req.method!=="GET"||!file){res.writeHead(404).end();return;}
    res.writeHead(200,{"Content-Type":file[1],"Cache-Control":"no-store"});res.end(await readFile(file[0]));
  } catch(error){res.writeHead(500).end(String(error));}
});
server.listen(3101,"127.0.0.1",()=>console.log(`Benchmark: http://127.0.0.1:3101 — reports: ${fileURLToPath(directory)}`));
