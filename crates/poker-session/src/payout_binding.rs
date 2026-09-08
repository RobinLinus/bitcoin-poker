//! Future hands retain verified internal signatures while terminal amounts bind later.
use super::*;
use poker_settlement::{settlement::AuthorizationRequest, PlannedState};

impl Session {
    pub fn defer_payouts(&mut self) -> Result<()> {
        if self.channel_mode.is_none() || self.terms.predeal_anchor.is_none()
            || !self.terms.parameters()?.balance_independent()? || self.preparation.is_some()
            || self.ready.is_some() || self.current.is_some() {
            return Err("cannot defer payouts for this hand".into());
        }
        self.deferred_payouts = true;
        Ok(())
    }

    pub fn preparation_work(&self) -> Result<Vec<usize>> {
        let p = self.preparation.as_ref().ok_or("not preparing")?;
        let graph = self.graph()?;
        p.missing_indices().into_iter().filter_map(|i| {
            if !self.deferred_payouts { return Some(Ok(i)); }
            match &p.requests()[i] {
                AuthorizationRequest::Reveal(_) => Some(Ok(i)),
                AuthorizationRequest::Signature { node_id, edge_index, .. } => {
                    let child = graph.node(node_id).and_then(|n| n.edges.get(*edge_index))
                        .and_then(|e| graph.node(&e.child_node_id));
                    match child {
                        Some(n) if matches!(n.state, PlannedState::Terminal(_)) => None,
                        Some(_) => Some(Ok(i)),
                        None => Some(Err("missing payout edge".into())),
                    }
                }
            }
        }).collect()
    }

    pub(super) fn payout_terms(&self, stacks: [u64;2]) -> Result<Terms> {
        if !self.deferred_payouts || self.ready.is_some() || self.current.is_some()
            || !self.preparation_work()?.is_empty() { return Err("hand is not ready to bind payouts".into()); }
        let mut terms = self.terms.clone(); terms.stacks = Some(stacks);
        let old = self.terms.parameters()?; let new = terms.parameters()?;
        if !new.balance_independent()? || old.rules.total_locked_value()? != new.rules.total_locked_value()?
            || old.chain_id(self.dealer.accepted()?)? != new.chain_id(self.dealer.accepted()?)? {
            return Err("balances require a different betting topology".into());
        }
        Ok(terms)
    }

    pub(super) fn bind_payouts(&mut self, stacks: [u64;2]) -> Result<usize> {
        let terms = self.payout_terms(stacks)?;
        let mut graph = SettlementGraph::compile(self.dealer.accepted()?, terms.parameters()?,
            &terms.fees()?, self.scores.clone().ok_or("missing scores")?)?;
        let profile = self.channel_materialization.as_ref().ok_or("missing commitments")?;
        let (owner, contest) = self.channel_mode.ok_or("not a channel")?;
        graph = graph.with_channel_protection(owner, contest, profile.hand_commitment, &profile.commitments)?;
        let activation = graph.activation(terms.origin_output()?, terms.scaled_fee(500))?;

        // Duplicate the authenticated partial snapshot so failure leaves the original intact.
        let previous = SettlementPreparation::open_progress_checkpoint(&self.receipt_key(),
            &self.preparation.as_ref().ok_or("not preparing")?.seal_progress_checkpoint(&self.receipt_key())?, terms.network())?;
        let cached=self.payout_projection.as_deref().or_else(||self.graph_cache.get().and_then(|(_,g)|g.payout_projection()));
        let (preparation,reused)=if let Some(cache)=cached {
            SettlementPreparation::rebind_payouts(&graph,activation,previous,cache)?
        } else {
            let mut preparation=SettlementPreparation::new(&graph,activation)?;
            let reused=preparation.reuse_unchanged(previous)?;(preparation,reused)
        };
        self.terms = terms; self.deferred_payouts = false;self.payout_projection=None;
        self.unprotected_graph_cache.take();
        self.graph_cache = OnceLock::from((serde_json::to_vec(&self.terms)?, Arc::new(graph)));
        self.sealed = Some(self.wrap_channel_artifact(preparation.seal_progress_checkpoint(&self.receipt_key())?)?);
        self.preparation = Some(preparation);
        Ok(reused)
    }
}
