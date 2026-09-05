const STREET_SLOTS = Object.freeze({ preflop: [0, 1, 2, 3], flop: [4, 5, 6], turn: [7], river: [8] });

function same(left, right) { return left.byteLength===right.byteLength&&left.every((value,index)=>value===right[index]); }

/** Run the fixed-limit demonstration policy through showdown using selective DLOG52 openings. */
export function runScriptedHand(alice, bob) {
  const cards=new Array(9), openingsA=new Array(9), openingsB=new Array(9), reveals=[];
  const reveal=(street)=>{
    for(const slot of STREET_SLOTS[street]) {
      const shareA=alice.exportShare(slot),shareB=bob.exportShare(slot);
      // The deterministic digest exercises card-key derivation and BIP340 signing.
      // It is intentionally not represented as a Bitcoin transaction sighash; the
      // native chain test covers the actual BIP341 gate-spend sighash path.
      const digest=new Uint8Array(32).fill(0x80+slot),aux=new Uint8Array(32).fill(0x20+slot);
      const resultA=alice.signCard(slot,shareB,digest,aux),resultB=bob.signCard(slot,shareA,digest,aux);
      if(resultA.cardId!==resultB.cardId||resultA.rawSum!==resultB.rawSum||!same(resultA.publicKey,resultB.publicKey)||!same(resultA.signature,resultB.signature))throw new Error(`DLOG52 slot ${slot} did not converge`);
      const gateA=alice.gateLeaf(slot,resultA.rawSum),gateB=bob.gateLeaf(slot,resultB.rawSum);
      if(gateA.cardId!==resultA.cardId||!same(gateA.outputScript,gateB.outputScript)||!same(gateA.script,gateB.script)||!same(gateA.controlBlock,gateB.controlBlock))throw new Error(`DLOG52 gate ${slot} did not converge`);
      cards[slot]=resultA.cardId;openingsA[slot]=shareA;openingsB[slot]=shareB;
      const recipient = slot < 4 ? (slot % 2 === 0 ? "alice" : "bob") : "public";
      reveals.push({street,slot,recipient,rawSum:resultA.rawSum,cardId:recipient === "public" ? resultA.cardId : null,cardPublicKey:resultA.publicKey,gate:gateA});
    }
  };
  const stacks=[10_000,10_000],committed=[0,0],actions=[];
  const pay=(role,amount,street,action)=>{if(stacks[role]<amount)throw new Error("insufficient demo stack");stacks[role]-=amount;committed[role]+=amount;actions.push({street,role,action,amount});};
  pay(0,50,"preflop","small-blind");pay(1,100,"preflop","big-blind");
  reveal("preflop");pay(0,50,"preflop","call");actions.push({street:"preflop",role:1,action:"check",amount:0});
  reveal("flop");actions.push({street:"flop",role:1,action:"check",amount:0});pay(0,100,"flop","bet");pay(1,100,"flop","call");
  reveal("turn");pay(1,200,"turn","bet");pay(0,200,"turn","call");
  reveal("river");actions.push({street:"river",role:1,action:"check",amount:0});actions.push({street:"river",role:0,action:"check",amount:0});
  const board=cards.slice(4,9),aliceSeven=[cards[0],cards[2],...board],bobSeven=[cards[1],cards[3],...board];
  for (const slot of STREET_SLOTS.preflop) {
    reveals.push({street:"showdown",slot,recipient:"public",rawSum:null,cardId:cards[slot]});
  }
  const aliceHand=alice.evaluateSeven(aliceSeven),bobHand=bob.evaluateSeven(bobSeven);
  if(aliceHand.score>bobHand.score)stacks[0]+=committed[0]+committed[1];
  else if(bobHand.score>aliceHand.score)stacks[1]+=committed[0]+committed[1];
  else {stacks[0]+=committed[0];stacks[1]+=committed[1];}
  return {complete:true,cards,actions,reveals,pot:committed[0]+committed[1],stacks,
    alice:{seven:aliceSeven,...aliceHand},bob:{seven:bobSeven,...bobHand},winner:aliceHand.score===bobHand.score?"tie":aliceHand.score>bobHand.score?"alice":"bob"};
}
