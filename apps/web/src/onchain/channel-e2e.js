import {relayConnection} from './relay-socket.js';
import {TableSession} from './table-session.js';
const output=document.getElementById('result');
const handCount=Math.max(1,Math.min(3,Number(new URLSearchParams(location.search).get('hands'))||3));
document.getElementById('run').textContent=`Run ${handCount} hands and cash out`;
const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));
let players=[],report={};
function show() {output.textContent=JSON.stringify(report,null,2);}
document.getElementById('run').onclick=async()=>{
  document.getElementById('run').disabled=true;
  const secret=document.getElementById('key').value;document.getElementById('key').value='';
  const resumeGame=document.getElementById("resume-game").value.trim();
  const warmBuffer=document.getElementById("warm-buffer").checked;
  let defenseWorker;
  const originalPublish=TableSession.prototype.publish;
  try {
    const config=await (await fetch('/api/v1/config')).json();
    defenseWorker=new Worker(new URL('./defense-worker.js',import.meta.url),{type:'module'});defenseWorker.postMessage(config);
    report={status:'Creating table',broadcasts:[],moves:[],players:[],hands:[],redeals:[]};show();
    players=[0,1].map(i=>new TableSession(config,state=>{
      if(state.error) {report.failures??=[];if(!report.failures.includes(state.error)) report.failures.push(state.error);}
      report.players[i]={stage:state.stage,error:state.error,gameId:state.data?.gameId,handNumber:state.data?.handNumber??1,node:state.view?.node,actor:state.view?.actor,role:state.view?.role,
        buffer:state.data?.buffer?{slots:state.data.buffer.slots.map(s=>s.index),ready:state.data.buffer.done.length,active:state.data.buffer.active,error:state.activeSession.handBuffer?.error,children:[...(state.activeSession.handBuffer?.sessions.values()??[])].map(c=>({id:c.data.gameId,slot:c.data.terms?.slot?.index,deck:!!c.data.deckReady,prepared:!!c.data.prepared,stage:c.stage,error:c.error,progress:c.progress}))}:null,
        pending:state.view?.pendingMove,terminal:state.view?.terminal,progress:state.progress};show();
    }));
    TableSession.prototype.publish=async function(raw) {
      const info=await this.wallet.call('inspect',{bytes:raw});
      const afterFunding=!!(this.data.funded || this.data.channelContinuation);
      report.broadcasts.push({txid:info.txid,afterFunding});show();
      const cashout=this.data.cashout && this.data.cashout===Array.from(raw,b=>b.toString(16).padStart(2,"0")).join("");
      report.broadcasts.at(-1).cashout=!!cashout;
      if(afterFunding && !cashout) throw new Error('Gameplay or redealing attempted a transaction broadcast');
      return originalPublish.call(this,raw);
    };
    let wallets;
    if(resumeGame) {
      await Promise.all(players.map((p,i)=>p.resume(resumeGame,i===0?'alice':'bob')));
      for(const p of players) clearInterval(p.timer);
      wallets=players.map(p=>p.localWallet);
      report.resumed=true;
    } else {
      await players[0].create('Channel Alice');clearInterval(players[0].timer);
      await players[1].join({gameId:players[0].data.gameId,inviteSecret:players[0].data.inviteSecret},'Channel Bob');clearInterval(players[1].timer);
      wallets=players.map(p=>p.localWallet);
      for(const p of players) {if(p.pollTask) await p.pollTask;p.localWallet=null;p.fundingKey=null;}
      await Promise.all(players.map(p=>p.step()));
      await players[0].fund(secret);
      if(players[0].error) throw new Error(players[0].error);
    }
    report.gameId=players[0].data.gameId;show();
    report.fundingOrigin=players[0].data.proposal.terms.origin;
    const started=performance.now();
    for(const p of players) p.timer=setInterval(()=>void p.step(),100);
    report.status='Preparing channel';show();
    const deadline=Date.now()+900000;
    let pendingNode=null,moveStart=0;
    while(!players.every(p=>p.view?.terminal && (p.data.handNumber??1)>=handCount)) {
      if(Date.now()>deadline) throw new Error('Browser channel test timed out');
      for(const p of players) if(p.error && !/not confirmed|fetch|network/i.test(p.error)) throw new Error(p.error);
      const [a,b]=players;
      for(const p of players) {
        if(p.data.terms && p.data.terms.origin!==report.fundingOrigin) throw new Error('Redeal changed channel funding');
        if((p.data.handNumber??1)>=handCount && !p.data.sitOutNext) await p.setSitOutNext(true);
      }
      if(a.data.gameId===b.data.gameId && a.view?.terminal && b.view?.terminal && !report.hands.some(h=>h.gameId===a.data.gameId)) {
        report.hands.push({gameId:a.data.gameId,balances:a.view.nextStacks,button:a.data.terms.button??0,settledAt:performance.now()});
        show();
      }
      if(a.data.gameId===b.data.gameId && players.every(p=>(p.data.handNumber??1)>1 && p.view?.channelReady && p.data.parentHandoffDone) && !report.redeals.some(h=>h.gameId===a.data.gameId)) {
        const parent=report.hands.at(-1);
        if(parent) {
          if(JSON.stringify(a.data.terms.stacks)!==JSON.stringify(parent.balances) || a.data.terms.button!==1-parent.button) throw new Error('Redeal changed balances or failed to switch the button');
          report.redeals.push({gameId:a.data.gameId,elapsedMs:performance.now()-parent.settledAt});
        }
        report.status='Playing next hand off chain';show();
      }
      if(players.every(p=>p.data.prepared) && !report.readyMs) {
        report.readyMs=performance.now()-started;
        report.preparation=players.map(p=>p.data.prepared);
        report.status='Waiting for initial funding confirmation';show();
      }
      if(a.view?.channelReady && b.view?.channelReady && !report.setupMs) {report.setupMs=performance.now()-started;report.preparation=players.map(p=>p.data.prepared);report.status='Playing off chain';}
      if(pendingNode && a.view?.node===b.view?.node && a.view?.node!==pendingNode && !a.view?.pendingMove && !b.view?.pendingMove) {
        report.moves.push({node:pendingNode,acceptedMs:performance.now()-moveStart});pendingNode=null;show();
      }
      const bufferWarm=!!report.bufferWarmedMs || !warmBuffer || (a.data.handNumber??1)>1 || players.every(p=>(p.data.buffer?.done.length??0)>=3);
      if(bufferWarm && !report.bufferWarmedMs && warmBuffer) {report.bufferWarmedMs=performance.now()-started;report.preparedAhead=players.map(p=>p.data.buffer?.jobs.map(j=>({index:j.index,stacks:j.stacks,ready:p.data.buffer.done.includes(j.id)})));}
      if(bufferWarm && !pendingNode && a.view?.node===b.view?.node && !a.view?.pendingMove && !b.view?.pendingMove) {
        const actor=players.find(p=>p.view?.channelReady && p.view.betting && p.view.actor===p.view.role);
        if(actor && !actor.busy) {
          const edge=actor.view.actions.find(e=>/Call|Check/.test(e.kind));
          if(!edge) throw new Error('No passive betting action');
          pendingNode=actor.view.node;moveStart=performance.now();await actor.act(edge.index);
        }
      }
      await delay(50);
    }
    await delay(500);
    if(players.some(p=>!p.data.sitOutNext || p.data.wantsNext || (p.data.handNumber??1)!==handCount)) throw new Error('Sitting out did not stop automatic redealing');
    report.sitOutStoppedRedeal=true;
    if(report.broadcasts.some(b=>b.afterFunding)) throw new Error('Unexpected in-game broadcast');
    if(players[0].view.node!==players[1].view.node) throw new Error('Final states disagree');
    report.hands.push({gameId:players[0].data.gameId,balances:players[0].view.nextStacks,button:players[0].data.terms.button});
    const info=await players[0].chain.spendFact({spentOutpoint:{displayTxid:Uint8Array.from(players[0].data.terms.origin.split(':')[0].match(/../g),h=>parseInt(h,16)),vout:0},minConfirmations:1});
    if(info) throw new Error('Cooperative channel funding was spent');
    report.fundingUnspentBeforeCashout=true;report.finalBalances=players[0].view.nextStacks;
    report.status='Cashing out from sitting out';show();
    players.forEach((p,i)=>p.localWallet=wallets[i]);
    await players[0].leaveTable();
    const closeDeadline=Date.now()+180000;
    while(!players.every(p=>p.data.left)) {
      if(Date.now()>closeDeadline) throw new Error('Cashout confirmation timed out');
      for(const p of players) if(p.error && !/fetch|network/i.test(p.error)) throw new Error(p.error);
      await delay(100);
    }
    if(players[0].data.cashout!==players[1].data.cashout) throw new Error('Cashout transactions disagree');
    const payout=await players[0].wallet.call('inspect',{bytes:Uint8Array.from(players[0].data.cashout.match(/../g),h=>parseInt(h,16))});
    const balances=report.finalBalances;
    const fee=players[0].data.terms.origin_value-payout.outputs.reduce((sum,o)=>sum+o.value,0);
    const reserve=players[0].data.terms.origin_value-balances[0]-balances[1]-fee;
    for(let i=0;i<2;i++) {
      const owner=players.find(p=>p.view.role===i);
      if(payout.outputs[i].script!==owner.localWallet.script || payout.outputs[i].value!==balances[i]+Math.floor(reserve/2)+(i===0?reserve%2:0)) throw new Error('Incorrect wallet payout');
    }
    report.cashout={txid:payout.txid,outputs:payout.outputs,fee,bothPlayersLeft:true};
    report.transport=await relayConnection.stats();
    report.status='PASS';
    report.finalGameId=players[0].data.gameId;
    report.aliceUrl=`/#/table/${report.finalGameId}/alice`;report.bobUrl=`/#/table/${report.finalGameId}/bob`;show();
  } catch(error) {report.status='FAIL';report.error=error.message;show();}
  finally {defenseWorker?.terminate();TableSession.prototype.publish=originalPublish;for(const player of players) player.close();document.getElementById('run').disabled=false;}
};
