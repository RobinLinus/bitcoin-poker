// Test-only proxy: nested Chromium worker loads bypass Playwright routing.
import {createServer,request} from 'node:http';
import {connect} from 'node:net';
export async function startWorkerFailureProxy(origin,injection,port=0) {
  const backend=new URL(origin);
  if(backend.protocol!=='http:'||!['127.0.0.1','localhost'].includes(backend.hostname))throw Error('Crash injection requires a local HTTP relay');
  const sockets=new Set();
  const server=createServer((req,res)=>{
    const upstream=request(new URL(req.url,backend),{method:req.method,headers:{...req.headers,'accept-encoding':'identity'}},reply=>{
      if(req.method!=='GET'||!req.url.endsWith('/src/onchain/construction-worker.js')||reply.statusCode!==200){res.writeHead(reply.statusCode,reply.headers);reply.pipe(res);return;}
      const chunks=[];reply.on('data',chunk=>chunks.push(chunk));reply.on('end',()=>{
        const body=Buffer.concat([...chunks,Buffer.from(injection)]),headers={...reply.headers,'content-length':body.length};delete headers['transfer-encoding'];
        res.writeHead(reply.statusCode,headers);res.end(body);
      });
    });
    upstream.on('error',()=>{res.writeHead(502);res.end();});req.pipe(upstream);
  });
  server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});
  server.on('upgrade',(req,socket,head)=>{
    const upstream=connect(Number(backend.port)||80,backend.hostname,()=>{
      upstream.write(`${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`+req.rawHeaders.reduce((s,v,i)=>s+v+(i%2?'\r\n':': '),'')+'\r\n');
      if(head.length)upstream.write(head);socket.pipe(upstream);upstream.pipe(socket);
    });
    upstream.on('error',()=>socket.destroy());socket.on('error',()=>upstream.destroy());socket.on('close',()=>upstream.destroy());
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});
  return {origin:`http://127.0.0.1:${server.address().port}`,close(){for(const socket of sockets)socket.destroy();server.close();}};
}
