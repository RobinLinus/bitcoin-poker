import { WorkerRpcClient } from "/browser/worker/rpc-client.js";

const button=document.querySelector("#run"),status=document.querySelector("#status"),output=document.querySelector("#result");
const fill=(value)=>new Uint8Array(32).fill(value);
const same=(a,b)=>{a=new Uint8Array(a);b=new Uint8Array(b);return a.length===b.length&&a.every((v,i)=>v===b[i]);};
const hex=(value)=>[...new Uint8Array(value)].map((v)=>v.toString(16).padStart(2,"0")).join("");

async function identity(byte){
  const secret=fill(byte);
  // DLOG52 requires secp256k1 identities. The two fixed public keys below are
  // the canonical x-only keys for scalars 3 and 5; Wasm validates the pairing.
  const xonly=byte===3
    ? Uint8Array.from([83,31,230,6,129,52,80,61,39,35,19,50,39,200,103,172,143,166,200,60,83,126,154,68,195,197,189,189,203,31,227,55])
    : Uint8Array.from([98,192,160,70,218,204,232,109,221,3,67,198,211,199,199,156,34,8,186,13,156,156,242,74,109,4,109,33,210,31,144,247]);
  return {secret,xonly};
}

async function run(){
  button.disabled=true;output.textContent="";status.textContent="Loading DLOG52 Wasm…";
  const started=performance.now();
  const wasm=await (await fetch("/wasm/dlog52.wasm",{cache:"no-store"})).arrayBuffer();
  const [first,second]=await Promise.all([identity(3),identity(5)]);
  const identities=[first,second].sort((a,b)=>hex(a.xonly).localeCompare(hex(b.xonly)));
  const config={networkGenesis:fill(1),sessionAnchor:fill(2),identityA:identities[0].xonly,identityB:identities[1].xonly,sessionNonce:fill(3),rulesHash:fill(4)};
  const clients=[0,1].map(()=>new WorkerRpcClient(new Worker("/browser/deal/dlog52-worker.js",{type:"module"})));
  try {
    await Promise.all(clients.map((client,role)=>{
      const entropy=fill(role?0x62:0x51),identitySecret=identities[role].secret;
      return client.request("init",{wasm:wasm.slice(0),request:{config,role,identitySecret,entropy}},{transfer:[identitySecret.buffer,entropy.buffer]});
    }));
    let snapshots=await Promise.all(clients.map((client)=>client.request("snapshot").then((r)=>r.snapshot)));
    for(let round=0;round<100&&!snapshots[0].accepted;round+=1){
      status.textContent=`Authenticated deal · attempt ${snapshots[0].attempt} · stage ${snapshots[0].stage}/10`;
      if(snapshots.some((s)=>s.retryRequired)){
        if(!snapshots.every((s)=>s.retryRequired&&s.attempt===snapshots[0].attempt))throw new Error("retry outcome disagreement");
        snapshots=await Promise.all(clients.map((client)=>client.request("start-retry",{nextAttempt:snapshots[0].attempt+1}).then((r)=>r.snapshot)));continue;
      }
      const prepared=await Promise.all(clients.map((client)=>client.request("prepare-outgoing")));
      await Promise.all(prepared.map((p,i)=>p.envelope?clients[i].request("confirm-outgoing",{envelope:p.envelope.slice(0)}):null));
      await Promise.all(prepared.map((p,i)=>p.envelope?clients[1-i].request("accept-peer",{envelope:p.envelope}):null));
      snapshots=await Promise.all(clients.map((client)=>client.request("snapshot").then((r)=>r.snapshot)));
    }
    if(!snapshots.every((s)=>s.accepted))throw new Error("deal did not reach acceptance");
    const certs=await Promise.all(clients.map((client)=>client.request("export-certificate").then((r)=>r.certificate)));
    if(!same(certs[0],certs[1]))throw new Error("certificate mismatch");
    await Promise.all(clients.map((client,i)=>client.request("verify-certificate",{certificate:certs[1-i].slice(0)})));
    const cards=new Array(9),gateScripts=new Array(9),actions=[],stacks=[10000,10000],committed=[0,0];
    const pay=(role,amount,street,action)=>{stacks[role]-=amount;committed[role]+=amount;actions.push({role,amount,street,action});};
    const gate=async(slot,rawSum)=>{
      const gates=await Promise.all(clients.map((client)=>client.request("gate-leaf",{slot,rawSum}).then((r)=>r.gate)));
      if(!same(gates[0].outputScript,gates[1].outputScript)||!same(gates[0].controlBlock,gates[1].controlBlock))throw new Error(`gate ${slot} disagreement`);
      gateScripts[slot]=new Uint8Array(gates[0].script).byteLength;
    };
    const derivePrivate=async(slot,receiver,sender)=>{
      const reveal=await clients[sender].request("export-share",{slot,recipient:receiver,stage:0,auxiliaryRandomness:fill(0x40+slot)}).then((r)=>r.opening);
      const signed=await clients[receiver].request("sign-card",{slot,peerOpening:reveal,sighash:fill(0x80+slot),auxiliaryRandomness:fill(0x20+slot)});
      cards[slot]=signed.cardId;await gate(slot,signed.rawSum);
    };
    const derivePublic=async(slot,stage)=>{
      const reveals=await Promise.all(clients.map((client)=>client.request("export-share",{slot,recipient:255,stage,auxiliaryRandomness:fill(0x40+slot)}).then((r)=>r.opening)));
      const signed=await Promise.all(clients.map((client,i)=>client.request("sign-card",{slot,peerOpening:reveals[1-i].slice(0),sighash:fill(0x80+slot),auxiliaryRandomness:fill(0x20+slot)})));
      if(signed[0].cardId!==signed[1].cardId||!same(signed[0].signature,signed[1].signature))throw new Error(`slot ${slot} disagreement`);
      if(cards[slot]!==undefined&&cards[slot]!==signed[0].cardId)throw new Error(`showdown changed slot ${slot}`);
      cards[slot]=signed[0].cardId;await gate(slot,signed[0].rawSum);
    };
    pay(0,50,"preflop","small-blind");pay(1,100,"preflop","big-blind");
    await derivePrivate(0,0,1);await derivePrivate(1,1,0);await derivePrivate(2,0,1);await derivePrivate(3,1,0);
    pay(0,50,"preflop","call");actions.push({role:1,amount:0,street:"preflop",action:"check"});
    await derivePublic(4,1);await derivePublic(5,1);await derivePublic(6,1);
    actions.push({role:1,amount:0,street:"flop",action:"check"});pay(0,100,"flop","bet");pay(1,100,"flop","call");
    await derivePublic(7,2);pay(1,200,"turn","bet");pay(0,200,"turn","call");
    await derivePublic(8,3);actions.push({role:1,amount:0,street:"river",action:"check"});actions.push({role:0,amount:0,street:"river",action:"check"});
    await derivePublic(0,4);await derivePublic(1,4);await derivePublic(2,4);await derivePublic(3,4);
    const board=cards.slice(4),seven=[[cards[0],cards[2],...board],[cards[1],cards[3],...board]];
    const hands=await Promise.all(clients.map((client,i)=>client.request("evaluate-seven",{cards:Uint8Array.from(seven[i])}).then((r)=>r.evaluation)));
    const winner=hands[0].score===hands[1].score?"tie":hands[0].score>hands[1].score?"alice":"bob";
    const pot=committed[0]+committed[1];
    if(winner==="alice")stacks[0]+=pot;else if(winner==="bob")stacks[1]+=pot;else {stacks[0]+=committed[0];stacks[1]+=committed[1];}
    const result={ok:true,elapsedMs:Math.round(performance.now()-started),certificateBytes:new Uint8Array(certs[0]).byteLength,attempt:snapshots[0].attempt,cards,winner,scores:hands.map((h)=>h.score),pot,stacks,actions:actions.length,gateScriptBytes:gateScripts};
    status.textContent=`Complete · ${winner} wins · ${result.elapsedMs} ms`;
    output.textContent=JSON.stringify(result,null,2);button.dataset.complete="true";
  } finally { await Promise.all(clients.map((client)=>client.close()));button.disabled=false; }
}

button.addEventListener("click",()=>run().catch((error)=>{status.textContent="Failed";output.textContent=error instanceof Error?error.stack:String(error);button.disabled=false;}));
