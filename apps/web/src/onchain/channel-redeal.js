import {releaseChannelRoom as releaseRelayRoom} from './channel-inbox.js';
import {trace} from './diagnostics.js';

// Runs on the completed table. The successor remains hidden and cannot play
// until both old hand revocations have been persisted and acknowledged.
export async function continueChannelHand() {
  if(!this.view?.terminal) return;
  if(this.data.leaveRequested || this.data.peer.leave || this.view.cashoutStarted) return this.cashOut();
  if(!this.data.wantsNext) {
    this.stage='Hand settled';
    if(this.data.sitOutNext || this.view.nextStacks.some(n=>n<200)) return;
    this.data.wantsNext=true;this.notify();await this.save();
  }
  await this.send('nextready',{hand:this.view.hand,node:this.view.node});
  const ready=this.data.peer.nextready;
  if(!ready) {this.stage='Waiting for your opponent';return;}
  if(ready.hand!==this.view.hand || ready.node!==this.view.node) throw new Error('Next hand settlement mismatch');
  this.startPredeal();
  this.stage='Preparing the next hand';this.notify();
  const child=await this.handBuffer.candidate(this.view.nextStacks);
  if(!child && this.handBuffer.error) throw new Error(this.handBuffer.error);
  if(!child) {this.stage='Preparing the next hand';return;}
  if(child.pollTask) await child.pollTask;
  if(!this.data.entrySelection) {
    const prepared=await child.player.call('preparedCertificate');
    const capability=await this.player.call('selectCandidate',{certificate:prepared});
    this.data.entrySelection={gameId:child.data.gameId,certificate:Array.from(capability)};
    await this.save();
  }
  if(this.data.entrySelection.gameId!==child.data.gameId) throw new Error('Conflicting hand selection');
  if(!child.data.entrySelected) {
    child.view=await child.player.call('authorizeEntry',{certificate:Uint8Array.from(this.data.entrySelection.certificate)});
    child.data.entrySelected=true;await child.save();
    child.timer=setInterval(()=>void child.step(),100);void child.step();
  }
  this.stage='Preparing the next hand';
  this.progress=child.progress;
  if(!child.view?.channelReady || child.view.pendingMove) return;
  if(!this.data.handoffStarted) {
    const certificate=await child.player.call('successorCertificate');
    // Keep the local attestation with the old record for crash recovery. It has
    // no signing key and is never sent to the other player.
    this.data.successorCertificate=Array.from(certificate);
    this.data.handoffStarted=true;await this.save();
  }
  this.view=await this.player.call('handoff',{certificate:Uint8Array.from(this.data.successorCertificate)});
  if(!this.view.handoffComplete) return;
  const old=this.data;
  child.view=await child.player.call("authorizePlay",{certificate:await this.player.call("playCertificate")});
  child.data.parentHandoffDone=true;
  child.data.fundingWalletId=old.fundingWalletId;
  child.data.buffer=old.buffer;
  this.handBuffer.adopt(child);
  await child.save();
  old.successor=child.data.gameId;await this.save();
  // Adopt in place so UI callbacks and the E2E driver keep the same TableSession.
  clearInterval(child.timer);clearInterval(this.timer);
  if(child.pollTask) await child.pollTask;
  // Both the playable successor and redirect are durable. Let it play while
  // the old worker compacts its own checkpoint under its existing player lock.
  // Closing this page simply leaves cleanup for the next startup.
  const retiredPlayer=this.player,cleanupStarted=performance.now();
  retiredPlayer.onprogress=null;
  void retiredPlayer.call('compactRetired',{successor:child.data.gameId})
    .then(compacted=>trace('channel.retired.cleanup.done',{gameId:old.gameId,sender:old.sender,compacted,durationMs:Math.round(performance.now()-cleanupStarted)}))
    .catch(error=>trace('channel.retired.cleanup.error',{gameId:old.gameId,sender:old.sender,error:error.message||error.name}))
    .finally(()=>retiredPlayer.close());
  if(!this.sharedWallet)this.wallet?.close();releaseRelayRoom(old);
  this.data=child.data;this.player=child.player;this.wallet=child.wallet;this.sharedWallet=child.sharedWallet;this.chain=child.chain;
  this.view=child.view;this.nextSession=null;this.predealTask=null;
  this.progress=null;this.handEndedAt=null;this.submission=null;this.actionError=null;
  this.player.onprogress=progress=>{this.progress=progress;this.notify();};
  this.stage='Starting the funded hand';
  this.handBuffer.table=this;
  child.stopped=true;
  location.hash=`/table/${this.data.gameId}/${this.data.sender}`;
  this.timer=setInterval(()=>void this.step(),100);
  this.notify();
}
