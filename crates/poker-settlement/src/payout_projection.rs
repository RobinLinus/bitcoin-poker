//! Private construction cache for rebinding terminal amounts without rebuilding scripts.
use crate::{CompilerError, PlannedState, settlement::{AuthorizationRequest, SettlementGraph}};
use bitcoin::{Amount, Transaction, TxOut, consensus::{serialize, deserialize}, hashes::Hash, taproot::TapLeafHash};
use poker_bitcoin::{TransactionTemplate, taproot_leaf_sighash_default};
use poker_settlement_types::NodeId;
use std::collections::HashMap;

fn invalid() -> CompilerError { CompilerError::Preparation { reason: "invalid payout projection" } }
pub(crate) struct ProjectionWriter(Vec<u8>);
impl ProjectionWriter {
    pub(crate) fn new() -> Self { Self(b"POKPAY01".to_vec()) }
    pub(crate) fn push(&mut self, node: NodeId, edge: usize, template: &TransactionTemplate, leaf: TapLeafHash, recipients: u8) -> Result<(),CompilerError> {
        self.0.extend(node);self.0.extend(u32::try_from(edge).map_err(|_|invalid())?.to_le_bytes());
        self.0.extend(leaf.to_byte_array());self.0.push(recipients);
        for bytes in [serialize(template.transaction()),serialize(template.parent_output())] {
            self.0.extend(u32::try_from(bytes.len()).map_err(|_|invalid())?.to_le_bytes());self.0.extend(bytes);
        }
        Ok(())
    }
    pub(crate) fn finish(self) -> Vec<u8> { self.0 }
}
fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8],CompilerError> {
    if n>input.len() {return Err(invalid());}let (a,b)=input.split_at(n);*input=b;Ok(a)
}
fn number(input: &mut &[u8]) -> Result<usize,CompilerError> {
    Ok(u32::from_le_bytes(take(input,4)?.try_into().map_err(|_|invalid())?) as usize)
}
fn frame<'a>(input: &mut &'a [u8]) -> Result<&'a [u8],CompilerError> { let n=number(input)?;take(input,n) }

impl SettlementGraph {
    /// Local-only cache, authenticated by the construction receipt before use.
    pub fn payout_projection(&self) -> Option<&[u8]> { self.payout_projection.get().map(Vec::as_slice) }

    pub(crate) fn rebind_payout_requests(&self, requests: &mut [AuthorizationRequest], mut cache: &[u8]) -> Result<(),CompilerError> {
        if !self.parameters.balance_independent()? || self.channel.is_none() || cache.len()>16_000_000
            || take(&mut cache,8)?!=b"POKPAY01" {return Err(invalid());}
        let mut payouts=HashMap::new();
        for (i,request) in requests.iter().enumerate() {
            if let AuthorizationRequest::Signature{node_id,edge_index,..}=request {
                let edge=self.node(node_id).and_then(|n|n.edges.get(*edge_index)).ok_or_else(invalid)?;
                if let PlannedState::Terminal(terminal)=self.node(&edge.child_node_id).ok_or_else(invalid)?.state {
                    payouts.insert((*node_id,*edge_index),(i,terminal,edge.fee_sat));
                }
            }
        }
        while !cache.is_empty() {
            let node:NodeId=take(&mut cache,32)?.try_into().map_err(|_|invalid())?;
            let edge=number(&mut cache)?;
            let leaf=TapLeafHash::from_byte_array(take(&mut cache,32)?.try_into().map_err(|_|invalid())?);
            let recipients=take(&mut cache,1)?[0];
            let mut tx:Transaction=deserialize(frame(&mut cache)?).map_err(|_|invalid())?;
            let parent:TxOut=deserialize(frame(&mut cache)?).map_err(|_|invalid())?;
            let (i,terminal,fee)=payouts.remove(&(node,edge)).ok_or_else(invalid)?;
            let AuthorizationRequest::Signature{sighash,..}=&mut requests[i] else {return Err(invalid());};
            if tx.input.len()!=1 || !tx.input[0].witness.is_empty()
                || taproot_leaf_sighash_default(&tx,0,std::slice::from_ref(&parent),leaf)?!=*sighash {return Err(invalid());}
            // Exact full-stack topology has the same payout recipients and scripts.
            // Only amounts change; folds, timeouts and all showdown leaves are included.
            let amounts:Vec<_>=[terminal.alice_output_sat,terminal.bob_output_sat].into_iter().filter(|n|*n!=0).collect();
            if recipients!=(u8::from(terminal.alice_output_sat!=0) | (u8::from(terminal.bob_output_sat!=0)<<1)) || amounts.len()!=tx.output.len() || amounts.iter().try_fold(fee,|sum,n|sum.checked_add(*n))!=Some(parent.value.to_sat()) {return Err(invalid());}
            for (output,amount) in tx.output.iter_mut().zip(amounts) {output.value=Amount::from_sat(amount);}
            *sighash=taproot_leaf_sighash_default(&tx,0,std::slice::from_ref(&parent),leaf)?;
        }
        if !payouts.is_empty() {return Err(invalid());}Ok(())
    }
}
