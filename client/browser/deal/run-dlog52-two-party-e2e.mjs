import { readFile } from "node:fs/promises";
import { createECDH } from "node:crypto";
import { performance } from "node:perf_hooks";
import { Dlog52Participant } from "./dlog52-runtime.js";
import { playDlog52HeadsUpGame } from "../game/dlog52-heads-up.js";

const wasmPath = process.argv[2] ?? "../../../dealing-dlog/target/wasm32-unknown-unknown/release/dlog52_wasm.wasm";
const wasm = await WebAssembly.compile(await readFile(new URL(wasmPath, import.meta.url)));
function key(byte) { const secret = new Uint8Array(32).fill(byte); const ecdh=createECDH("secp256k1");ecdh.setPrivateKey(secret);return {secret,xonly:Uint8Array.from(ecdh.getPublicKey(undefined,"compressed").subarray(1))}; }
const keys=[key(3),key(5)].sort((a,b)=>Buffer.compare(a.xonly,b.xonly));
const fill=(value)=>new Uint8Array(32).fill(value);
const config={networkGenesis:fill(1),sessionAnchor:fill(2),identityA:keys[0].xonly,identityB:keys[1].xonly,sessionNonce:fill(3),rulesHash:fill(4)};
const [alice,bob]=await Promise.all([Dlog52Participant.create(wasm),Dlog52Participant.create(wasm)]);
const entropyA=Number(process.argv[3]??0x51),entropyB=Number(process.argv[4]??0x62);
alice.initialize({config,role:0,identitySecret:keys[0].secret,entropy:fill(entropyA)});
bob.initialize({config,role:1,identitySecret:keys[1].secret,entropy:fill(entropyB)});
const started=performance.now();
for(let round=0;round<100&&!alice.snapshot().accepted;round+=1){
  const stateA=alice.snapshot(),stateB=bob.snapshot();
  if(stateA.retryRequired||stateB.retryRequired){
    if(!stateA.retryRequired||!stateB.retryRequired||stateA.attempt!==stateB.attempt)throw new Error("retry outcome disagrees");
    alice.startRetry(stateA.attempt+1);bob.startRetry(stateB.attempt+1);continue;
  }
  const a=alice.prepareOutgoing(),b=bob.prepareOutgoing();
  if(a){const replay=alice.prepareOutgoing();if(!Buffer.from(a).equals(Buffer.from(replay)))throw new Error("outgoing replay changed");alice.confirmPersistedOutgoing(a);}
  if(b)bob.confirmPersistedOutgoing(b);
  if(a)bob.acceptPeer(a); if(b)alice.acceptPeer(b);
}
if(!alice.snapshot().accepted||!bob.snapshot().accepted)throw new Error("DLOG52 E2E did not accept");
const certA=alice.exportCertificate(),certB=bob.exportCertificate();
if(certA.byteLength!==102070||!Buffer.from(certA).equals(Buffer.from(certB)))throw new Error("certificate mismatch");
alice.verifyCertificate(certB);bob.verifyCertificate(certA);
const game=playDlog52HeadsUpGame(alice,bob);
if(!game.complete||new Set(game.cards).size!==9||game.actions.length!==11||game.stacks[0]+game.stacks[1]!==20_000)throw new Error("complete game invariant failed");
console.log(JSON.stringify({ok:true,elapsedMs:Math.round(performance.now()-started),certificateBytes:certA.byteLength,attempt:alice.snapshot().attempt,stage:alice.snapshot().stage,cards:game.cards,pot:game.pot,winner:game.winner,scores:[game.alice.score,game.bob.score],stacks:game.stacks,actions:game.actions.length}));
alice.clear();bob.clear();
