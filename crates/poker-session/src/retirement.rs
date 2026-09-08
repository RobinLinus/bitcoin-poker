//! Local retirement barrier for a fixed, independently verified decision.
//!
//! This is a protocol component, not a cooperative transaction verifier. The
//! caller must verify the selected transaction in BOTH owner materializations
//! before opening a barrier, persist every mutation before releasing messages,
//! and install pending-disclosure defenses before revealing a card. Receiving a
//! retirement preimage does not prove that the peer persisted the selected move.

use poker_bitcoin::channel::retirement_commitment;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Exact abandoned-edge identity. Owner identifies a Bitcoin materialization;
/// authorizer identifies the player accountable for publishing this edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Branch {
    pub edge: u32,
    pub owner: u8,
    pub authorizer: u8,
}

/// Bind every frame to the same hand, node and selected transaction pair.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub hand: [u8; 32],
    pub node: [u8; 32],
    pub sequence: u64,
    pub selected_edge: u32,
    pub selected_txids: [[u8; 32]; 2],
}

/// Public commitments compiled into all outgoing protected branch outputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BranchCommitment {
    pub branch: Branch,
    pub hash: [u8; 32],
}

/// Private retirement data. Encrypt at rest and transmit only to the peer or
/// the narrowly scoped justice monitor, never as public relay metadata.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetirementFrame {
    pub decision: Decision,
    pub authorizer: u8,
    pub secrets: Vec<(Branch, [u8; 32])>,
}

/// A fail-closed validation error; no state changes on a rejected frame.
#[derive(Debug, thiserror::Error)]
#[error("invalid or conflicting fixed-tree retirement")]
pub struct RetirementError;

/// One pending decision. Retain this across message cuts; never replace it with
/// a different choice after a complete authorization has escaped.
pub struct RetirementBarrier {
    decision: Decision,
    required: BTreeMap<Branch, [u8; 32]>,
    received: [Option<RetirementFrame>; 2],
    closing: bool,
}

impl RetirementBarrier {
    /// Create a barrier from the independently compiled complete outgoing set.
    /// Each logical edge must occur in both owner materializations with the same
    /// authorizer. Selected branches are retained, never put in the retired set.
    pub fn new(
        decision: Decision,
        commitments: &[BranchCommitment],
    ) -> Result<Self, RetirementError> {
        if decision.hand == [0; 32]
            || decision.node == [0; 32]
            || decision.selected_txids.contains(&[0; 32])
            || decision.selected_txids[0] == decision.selected_txids[1]
        {
            return Err(RetirementError);
        }
        let mut all = BTreeMap::new();
        let mut hashes = BTreeSet::new();
        let mut pairs = BTreeMap::<u32, (u8, u8)>::new();
        for c in commitments {
            let b = c.branch;
            if b.owner > 1
                || b.authorizer > 1
                || c.hash == [0; 32]
                || !hashes.insert(c.hash)
                || all.insert(b, c.hash).is_some()
            {
                return Err(RetirementError);
            }
            let pair = pairs.entry(b.edge).or_insert((b.authorizer, 0));
            if pair.0 != b.authorizer {
                return Err(RetirementError);
            }
            pair.1 |= 1 << b.owner;
        }
        if !pairs.contains_key(&decision.selected_edge) || pairs.values().any(|p| p.1 != 3) {
            return Err(RetirementError);
        }
        let required = all
            .into_iter()
            .filter(|(b, _)| b.edge != decision.selected_edge)
            .collect();
        Ok(Self {
            decision,
            required,
            received: [None, None],
            closing: false,
        })
    }

    /// Validate the entire author's retirement atomically. Exact retransmissions
    /// are idempotent. Partial sets, sibling substitutions and cross-hand frames
    /// cannot open the disclosure barrier.
    pub fn accept(&mut self, frame: RetirementFrame) -> Result<(), RetirementError> {
        if self.closing || frame.authorizer > 1 || frame.decision != self.decision {
            return Err(RetirementError);
        }
        let mut seen = BTreeSet::new();
        for (branch, secret) in &frame.secrets {
            if branch.authorizer != frame.authorizer
                || !seen.insert(*branch)
                || self.required.get(branch) != Some(&retirement_commitment(*secret))
            {
                return Err(RetirementError);
            }
        }
        if seen.len()
            != self
                .required
                .keys()
                .filter(|b| b.authorizer == frame.authorizer)
                .count()
        {
            return Err(RetirementError);
        }
        let index = usize::from(frame.authorizer);
        if let Some(old) = &self.received[index] {
            let old: BTreeMap<_, _> = old.secrets.iter().copied().collect();
            if frame.secrets.iter().any(|(b, s)| old.get(b) != Some(s)) {
                return Err(RetirementError);
            }
            return Ok(());
        }
        self.received[index] = Some(frame);
        Ok(())
    }

    /// Both roles supplied every obsolete alternative. This is only the
    /// retirement prerequisite for disclosure; durable selected-prefix coverage
    /// and an installed pending-delivery monitor remain separate requirements.
    #[must_use]
    pub fn retired(&self) -> bool {
        !self.closing && self.received.iter().all(Option::is_some)
    }

    /// Funding publication freezes cooperative progress permanently.
    pub fn close(&mut self) {
        self.closing = true;
    }

    /// Frames to replay through `accept` when restoring the encrypted journal.
    /// Never deserialize an unauthenticated ready flag as evidence of retirement.
    pub fn frames(&self) -> impl Iterator<Item = &RetirementFrame> {
        self.received.iter().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_bitcoin::channel::{RetirementLevel, retirement_secret};
    fn fixture() -> (Decision, Vec<BranchCommitment>, [RetirementFrame; 2]) {
        let decision = Decision {
            hand: [1; 32],
            node: [2; 32],
            sequence: 3,
            selected_edge: 0,
            selected_txids: [[4; 32], [5; 32]],
        };
        let mut frames = [0, 1].map(|authorizer| RetirementFrame {
            decision: decision.clone(),
            authorizer,
            secrets: vec![],
        });
        let mut commitments = vec![];
        // Action 0 is selected. Action 1 belongs to Alice, timeout 2 to Bob.
        for edge in 0..3 {
            for owner in 0..2 {
                let authorizer = u8::from(edge == 2);
                let branch = Branch {
                    edge,
                    owner,
                    authorizer,
                };
                let secret = retirement_secret(
                    &[8; 32],
                    RetirementLevel::Branch,
                    decision.hand,
                    decision.node,
                    edge,
                    owner == 1,
                    authorizer == 1,
                );
                commitments.push(BranchCommitment {
                    branch,
                    hash: retirement_commitment(secret),
                });
                if edge != 0 {
                    frames[usize::from(authorizer)]
                        .secrets
                        .push((branch, secret));
                }
            }
        }
        (decision, commitments, frames)
    }
    #[test]
    fn every_retirement_message_cut_replays_without_opening_early()
    -> Result<(), Box<dyn std::error::Error>> {
        let (d, c, frames) = fixture();
        for order in [[0, 1], [1, 0]] {
            for cut in 0..=2 {
                let mut original = RetirementBarrier::new(d.clone(), &c)?;
                for &i in &order[..cut] {
                    original.accept(frames[i].clone())?;
                }
                let mut restored = RetirementBarrier::new(d.clone(), &c)?;
                for frame in original.frames() {
                    restored.accept(serde_json::from_slice(&serde_json::to_vec(frame)?)?)?;
                }
                assert_eq!(restored.retired(), cut == 2);
                for &i in &order {
                    restored.accept(frames[i].clone())?;
                }
                assert!(restored.retired());
                restored.close();
                assert!(!restored.retired());
                assert!(restored.accept(frames[0].clone()).is_err());
            }
        }
        Ok(())
    }
    #[test]
    fn rejects_reused_secrets_and_incomplete_owner_coverage() {
        let (d, mut c, _) = fixture();
        c[2].hash = c[0].hash;
        assert!(RetirementBarrier::new(d.clone(), &c).is_err());
        let (_, mut c, _) = fixture();
        c.pop();
        assert!(RetirementBarrier::new(d, &c).is_err());
    }
    #[test]
    fn rejects_selected_edge_partial_set_and_conflicting_choice()
    -> Result<(), Box<dyn std::error::Error>> {
        let (d, c, frames) = fixture();
        let mut b = RetirementBarrier::new(d, &c)?;
        for mutation in 0..5 {
            let mut f = frames[0].clone();
            match mutation {
                0 => {
                    f.secrets.pop();
                }
                1 => f.secrets[0].0.edge = 0,
                2 => f.decision.selected_edge = 1,
                3 => f.decision.hand = [9; 32],
                _ => f.secrets[0].1[0] ^= 1,
            }
            assert!(b.accept(f).is_err());
            assert_eq!(b.frames().count(), 0);
        }
        b.accept(frames[0].clone())?;
        assert!(!b.retired()); // Peer may have received the move and disappeared.
        Ok(())
    }
}
