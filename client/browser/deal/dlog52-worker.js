import { Dlog52Participant } from "./dlog52-runtime.js";
import { serializeAsync } from "../worker/serial-dispatch.js";

let participant;
function transfer(value) { const copy=Uint8Array.from(value);return copy.buffer; }
function reply(id,payload={},transfers=[]) { self.postMessage({id,ok:true,...payload},transfers); }
function reject(id,error) { self.postMessage({id,ok:false,error:error instanceof Error?error.message:String(error)}); }

async function handle(event) {
  const {id,type}=event.data??{};
  try {
    if(type==="init") {
      if(participant)throw new Error("DLOG52 Worker already initialized");
      const source=event.data.wasm instanceof WebAssembly.Module?event.data.wasm:await WebAssembly.compile(event.data.wasm);
      participant=await Dlog52Participant.create(source);
      try { participant.initialize(event.data.request); }
      finally { event.data.request?.identitySecret?.fill?.(0);event.data.request?.entropy?.fill?.(0); }
      reply(id,{snapshot:participant.snapshot()});return;
    }
    if(!participant)throw new Error("DLOG52 Worker is not initialized");
    if(type==="prepare-outgoing") {
      const value=participant.prepareOutgoing();if(value===null)reply(id,{envelope:null,snapshot:participant.snapshot()});
      else {const envelope=transfer(value);reply(id,{envelope,snapshot:participant.snapshot()},[envelope]);}
    } else if(type==="confirm-outgoing") {participant.confirmPersistedOutgoing(event.data.envelope);reply(id,{snapshot:participant.snapshot()});
    } else if(type==="accept-peer") {participant.acceptPeer(event.data.envelope);reply(id,{snapshot:participant.snapshot()});
    } else if(type==="snapshot") reply(id,{snapshot:participant.snapshot()});
    else if(type==="start-retry") {participant.startRetry(event.data.nextAttempt);reply(id,{snapshot:participant.snapshot()});}
    else if(type==="export-certificate") {const certificate=transfer(participant.exportCertificate());reply(id,{certificate},[certificate]);}
    else if(type==="verify-certificate") {participant.verifyCertificate(event.data.certificate);reply(id,{});}
    else if(type==="export-share") {const opening=transfer(participant.exportShare(event.data.slot,{recipient:event.data.recipient,stage:event.data.stage,auxiliaryRandomness:event.data.auxiliaryRandomness}));reply(id,{opening},[opening]);}
    else if(type==="sign-card") {const result=participant.signCard(event.data.slot,event.data.peerOpening,event.data.sighash,event.data.auxiliaryRandomness);for(const key of ["publicKey","signature"])result[key]=transfer(result[key]);reply(id,result,[result.publicKey,result.signature]);}
    else if(type==="sign-offchain") {const signature=transfer(participant.signOffchainCommitment(event.data.commitmentHash,event.data.auxiliaryRandomness));reply(id,{signature},[signature]);}
    else if(type==="verify-offchain") {participant.verifyOffchainCommitment(event.data.signer,event.data.commitmentHash,event.data.signature);reply(id,{});}
    else if(type==="evaluate-seven") reply(id,{evaluation:participant.evaluateSeven(event.data.cards)});
    else if(type==="gate-leaf") {
      const gate=participant.gateLeaf(event.data.slot,event.data.rawSum);
      const transfers=[];
      for(const key of ["dealId","authorizer","internalKey","merkleRoot","outputScript","script","controlBlock"]){gate[key]=transfer(gate[key]);transfers.push(gate[key]);}
      reply(id,{gate},transfers);
    }
    else if(type==="clear") {participant.clear();participant=undefined;reply(id,{});self.close();}
    else throw new Error(`unknown DLOG52 Worker request: ${String(type)}`);
  } catch(error) { reject(id,error); }
}
self.addEventListener("message",serializeAsync(handle));
