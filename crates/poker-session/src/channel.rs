//! Cooperative fixed-hand driver. Transactions never enter the chain observer.
//! The host persists state before sending returned frames and registers the
//! exact watch package before authorizing delivery of any move or acknowledgment.
use super::*;
use crate::retirement::{Branch, BranchCommitment, Decision, RetirementBarrier, RetirementFrame};
use poker_bitcoin::channel::RetirementLevel;
mod redeal;
mod slot;
pub use slot::ChannelSlot;
mod cashout;
use cashout::Cashout;
use redeal::Handoff;

#[derive(Clone, Serialize, Deserialize)]
pub enum Frame {
    Retire { hand: [u8; 32], next: [u8; 32], secret: [u8; 32] },
    Retired { hand: [u8; 32], next: [u8; 32] },
    Entry {
        hand: [u8; 32],
        launches: [Vec<u8>; 2],
        root_signature: Vec<u8>,
    },
    Ready {
        hand: [u8; 32],
    },
    Move {
        authorization: MoveAuthorization,
        retirement: RetirementFrame,
    },
    Ack {
        retirement: RetirementFrame,
    },
}

/// Only data missing from the prepared tree. Ordinary poker moves contain one
/// live signature per owner variant. Transaction bodies, scripts, control blocks
/// and the already-prepared counterparty signatures are never exchanged here.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MoveAuthorization {
    pub edge: u32,
    pub witness_elements: [Vec<Vec<u8>>; 2],
}

#[derive(Clone, Serialize, Deserialize)]
enum Pending {
    Entry {
        launches: [Vec<u8>; 2],
    },
    Outgoing {
        transactions: [Vec<u8>; 2],
        retirement: RetirementFrame,
        released: bool,
        ack: Option<RetirementFrame>,
    },
    Incoming {
        transactions: [Vec<u8>; 2],
        retirement: RetirementFrame,
        own: RetirementFrame,
    },
}

#[derive(Clone, Serialize, Deserialize)]
struct AcceptedMove {
    transactions: [Vec<u8>; 2],
    retirements: [RetirementFrame; 2],
}

#[derive(Serialize, Deserialize)]
struct Journal {
    prepared_launches: Option<[Vec<u8>;2]>,
    selection: Option<Vec<u8>>,
    entry_authorization: Option<Vec<u8>>,
    play_authorization: Option<Vec<u8>>,
    cashout: Option<Cashout>,
    handoff: Option<Handoff>,
    version: u8,
    root: Option<Vec<u8>>,
    entered: bool,
    peer_ready: bool,
    closing: bool,
    pending: Option<Pending>,
    accepted: Vec<AcceptedMove>,
}

fn frame_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    out.extend(u32::try_from(bytes.len())?.to_le_bytes());
    out.extend(bytes);
    Ok(())
}
fn take_frame<'a>(input: &mut &'a [u8]) -> Result<&'a [u8]> {
    let length = u32::from_le_bytes(
        input
            .get(..4)
            .ok_or("truncated channel frame")?
            .try_into()?,
    ) as usize;
    let (frame, rest) = input
        .get(4..)
        .ok_or("truncated channel frame")?
        .split_at_checked(length)
        .ok_or("truncated channel frame")?;
    *input = rest;
    Ok(frame)
}

/// Public monitoring capability: known root IDs and selected transactions only.
/// No complete local root, signing seed, or general signing authority is included.
#[derive(Clone, Serialize, Deserialize)]
pub struct WatchPackage {
    pub version: u8,
    pub revision: u64,
    pub hand: [u8; 32],
    pub funding: String,
    pub roots: [String; 2],
    pub paths: [Vec<Vec<u8>>; 2],
    pub penalties: Vec<Vec<u8>>,
}

/// One player, two mutually exclusive Bitcoin materializations, one poker hand.
pub struct ChannelHand {
    prepared_launches: Option<[Vec<u8>;2]>,
    selection: Option<Vec<u8>>,
    entry_authorization: Option<Vec<u8>>,
    play_authorization: Option<Vec<u8>>,
    cashout: Option<Cashout>,
    handoff: Option<Handoff>,
    sessions: [Session; 2],
    root: Option<Vec<u8>>,
    entered: bool,
    peer_ready: bool,
    closing: bool,
    pending: Option<Pending>,
    accepted: Vec<AcceptedMove>,
    verified_pending: Option<[crate::play::VerifiedCooperative; 2]>,
}

impl ChannelHand {
    pub fn new(seed: [u8; 32], mut terms: Terms, contest_blocks: u16) -> Result<Self> {
        terms.initialize_slot()?;
        Ok(Self {
            prepared_launches: None,
            selection: None, entry_authorization: None, play_authorization: None,
            cashout: None,
            handoff: None,
            sessions: [
                Session::new_channel(seed, terms.clone(), Role::Alice, contest_blocks)?,
                Session::new_channel(seed, terms, Role::Bob, contest_blocks)?,
            ],
            root: None,
            entered: false,
            peer_ready: false,
            closing: false,
            pending: None,
            accepted: vec![],
            verified_pending: None,
        })
    }

    /// Share the already verified dealer result between the two private roots.
    /// Only settlement ownership differs; the hand/dealer context must match.
    pub fn share_accepted_dealer(&mut self) -> Result<()> {
        if self.entered || self.pending.is_some() {return Err("hand entry already started".into());}
        let (left,right)=self.sessions.split_at_mut(1);
        let source=&left[0];let target=&mut right[0];
        source.dealer.accepted()?;
        if source.seed!=target.seed || source.role!=target.role
            || source.terms.nonce!=target.terms.nonce
            || source.terms.parameters()?.session_anchor()!=target.terms.parameters()?.session_anchor()
            || source.terms.parameters()?.dealing_rules_hash()?!=target.terms.parameters()?.dealing_rules_hash()?
            || target.local_score.is_some() || target.preparation.is_some() || target.ready.is_some() {
            return Err("cannot share this dealer context".into());
        }
        target.dealer=Arc::clone(&source.dealer);
        target.events=source.events.clone();
        Ok(())
    }

    /// Setup operations must be applied to both variants using the same accepted
    /// dealer transcript and score keys. No live move API is exposed here.
    pub fn setup_session(&mut self, owner: usize) -> Result<&mut Session> {
        if self.entered || self.pending.is_some() {
            return Err("hand entry already started".into());
        }
        self.sessions
            .get_mut(owner)
            .ok_or_else(|| "invalid owner".into())
    }

    fn hand(&self) -> Result<[u8; 32]> {
        Ok(self.sessions[0].graph()?.plan().chain_game_id)
    }
    fn role(&self) -> Role {
        self.sessions[0].role
    }

    pub fn entry_frame(&self) -> Result<Frame> {
        if !self.entry_allowed() {return Err("candidate not selected".into());}
        if self.closing {
            return Err("channel closing".into());
        }
        Ok(Frame::Entry {
            hand: self.hand()?,
            launches: [
                self.sessions[0].activation_signature()?,
                self.sessions[1].activation_signature()?,
            ],
            root_signature: self.sessions[usize::from(self.role().other().code())]
                .peer_root_signature()?,
        })
    }

    /// Stage a selected move privately. `authorize_watch` is required before its
    /// complete authorizations and retirement secrets can leave the worker.
    pub fn propose(&mut self, edge: Option<usize>) -> Result<WatchPackage> {
        if !self.entered || !self.peer_ready || self.closing || !self.play_allowed() {
            return Err("channel not ready for play".into());
        }
        if self.pending.is_some() {
            return self.watch_package();
        }
        let transactions = [
            self.sessions[0].action(edge, 0)?,
            self.sessions[1].action(edge, 0)?,
        ];
        let verified = self.verify_pair(&transactions)?;
        let (decision, commitments) = self.decision(&transactions)?;
        let retirement = self.own_retirements(decision, &commitments)?;
        self.verified_pending = Some(verified);
        self.pending = Some(Pending::Outgoing {
            transactions,
            retirement,
            released: false,
            ack: None,
        });
        self.watch_package()
    }

    /// Receive authenticated peer transport. Returns a frame only for an exact
    /// already-committed retry; new acceptance requires monitor registration.
    pub fn receive(&mut self, frame: Frame) -> Result<Option<Frame>> {
        if !self.entry_allowed() {return Err("candidate not selected".into());}
        if matches!(&frame, Frame::Move{..} | Frame::Ack{..}) && !self.play_allowed() {return Err("previous hand not retired".into());}
        if self.closing {
            return Err("channel closing".into());
        }
        match frame {
            Frame::Retire { hand, next, secret } => return self.receive_retirement(hand, next, secret),
            Frame::Retired { hand, next } => {
                if hand != self.hand()? { return Err("foreign hand retirement".into()); }
                let target = self.handoff.as_mut().ok_or("successor not prepared")?;
                if next != target.next { return Err("conflicting successor".into()); }
                target.peer_ack = true;
            }
            Frame::Entry {
                hand,
                launches,
                root_signature,
            } => {
                if hand != self.hand()? {
                    return Err("foreign hand entry".into());
                }
                if self.entered {
                    return Ok(Some(Frame::Ready { hand }));
                }
                let root =
                    self.sessions[usize::from(self.role().code())].local_root(&root_signature)?;
                let transactions = [
                    self.sessions[0].activation(&launches[0])?,
                    self.sessions[1].activation(&launches[1])?,
                ];
                let verified = self.verify_pair(&transactions)?;
                if let Some(Pending::Entry { launches: old }) = &self.pending {
                    if old != &transactions || self.root.as_ref() != Some(&root) {
                        return Err("conflicting entry".into());
                    }
                } else if self.pending.is_some() {
                    return Err("unexpected entry".into());
                }
                self.verified_pending = Some(verified);
                self.root = Some(root);
                self.pending = Some(Pending::Entry {
                    launches: transactions,
                });
            }
            Frame::Ready { hand } => {
                if hand != self.hand()? {
                    return Err("foreign hand readiness".into());
                }
                self.peer_ready = true;
            }
            Frame::Move {
                authorization,
                retirement,
            } => {
                if !self.entered || !self.peer_ready {
                    return Err("move before channel entry".into());
                }
                if retirement.authorizer != self.role().other().code() {
                    return Err("wrong move sender".into());
                }
                if let Some(old) = self
                    .accepted
                    .iter()
                    .find(|m| m.retirements[0].decision == retirement.decision)
                {
                    if self.authorization(&old.transactions, &retirement.decision)? != authorization
                        || old.retirements[usize::from(self.role().other().code())] != retirement
                    {
                        return Err("conflicting move retry".into());
                    }
                    return Ok(Some(Frame::Ack {
                        retirement: old.retirements[usize::from(self.role().code())].clone(),
                    }));
                }
                let transactions = [
                    self.sessions[0].complete_move_authorization(
                        authorization.edge,
                        &authorization.witness_elements[0],
                    )?,
                    self.sessions[1].complete_move_authorization(
                        authorization.edge,
                        &authorization.witness_elements[1],
                    )?,
                ];
                if let Some(Pending::Incoming {
                    transactions: old,
                    retirement: prior,
                    ..
                }) = &self.pending
                {
                    if old == &transactions && prior == &retirement {
                        return Ok(None);
                    }
                }
                if self.pending.is_some() {
                    return Err("conflicting pending choice".into());
                }
                if self.sessions[0].view()?["actor"].as_u64()
                    != Some(u64::from(self.role().other().code()))
                {
                    return Err("peer moved out of turn".into());
                }
                let verified = self.verify_pair(&transactions)?;
                let (decision, commitments) = self.decision(&transactions)?;
                if retirement.decision != decision {
                    return Err("retirement does not bind selected move".into());
                }
                let mut barrier = RetirementBarrier::new(decision.clone(), &commitments)?;
                barrier.accept(retirement.clone())?;
                let own = self.own_retirements(decision, &commitments)?;
                barrier.accept(own.clone())?;
                if !barrier.retired() {
                    return Err("incomplete move retirement".into());
                }
                self.verified_pending = Some(verified);
                self.pending = Some(Pending::Incoming {
                    transactions,
                    retirement,
                    own,
                });
            }
            Frame::Ack { retirement } => {
                if retirement.authorizer != self.role().other().code() {
                    return Err("wrong ack sender".into());
                }
                if let Some(old) = self
                    .accepted
                    .iter()
                    .find(|m| m.retirements[0].decision == retirement.decision)
                {
                    return if old.retirements[usize::from(self.role().other().code())] == retirement
                    {
                        Ok(None)
                    } else {
                        Err("conflicting ack retry".into())
                    };
                }
                let Some(Pending::Outgoing {
                    transactions,
                    retirement: own,
                    released,
                    ..
                }) = &self.pending
                else {
                    return Err("ack without a pending move".into());
                };
                if !released {
                    return Err("ack before move delivery".into());
                }
                let (decision, commitments) = self.decision(transactions)?;
                let mut barrier = RetirementBarrier::new(decision, &commitments)?;
                barrier.accept(own.clone())?;
                barrier.accept(retirement.clone())?;
                if !barrier.retired() {
                    return Err("incomplete move retirement".into());
                }
                if let Some(Pending::Outgoing { ack, .. }) = &mut self.pending {
                    *ack = Some(retirement);
                }
            }
        }
        Ok(None)
    }

    fn verify_pair(
        &self,
        transactions: &[Vec<u8>; 2],
    ) -> Result<[crate::play::VerifiedCooperative; 2]> {
        Ok([
            self.sessions[0].verify_cooperative(&transactions[0])?,
            self.sessions[1].verify_cooperative(&transactions[1])?,
        ])
    }

    fn authorization(
        &self,
        transactions: &[Vec<u8>; 2],
        decision: &Decision,
    ) -> Result<MoveAuthorization> {
        Ok(MoveAuthorization {
            edge: decision.selected_edge,
            witness_elements: [
                self.sessions[0].move_authorization_elements(decision.node, &transactions[0])?,
                self.sessions[1].move_authorization_elements(decision.node, &transactions[1])?,
            ],
        })
    }

    fn commit_pair(&mut self, transactions: &[Vec<u8>; 2]) -> Result<()> {
        // Both variants were checked before staging. A storage/monitor receipt
        // does not change the transaction, so acknowledgment never repeats its
        // cryptography. Restoring a checkpoint recreates these private proofs.
        let proofs = self
            .verified_pending
            .as_ref()
            .ok_or("missing validated move")?;
        if !proofs[0].matches(&transactions[0]) || !proofs[1].matches(&transactions[1]) {
            return Err("validated move changed".into());
        }
        let [a, b] = self
            .verified_pending
            .take()
            .ok_or("missing validated move")?;
        self.sessions[0].commit_cooperative(a)?;
        self.sessions[1].commit_cooperative(b)?;
        Ok(())
    }

    fn decision(&self, transactions: &[Vec<u8>; 2]) -> Result<(Decision, Vec<BranchCommitment>)> {
        let node = self.sessions[0].current.ok_or("hand not active")?;
        if self.sessions[1].current != Some(node) {
            return Err("materializations diverged".into());
        }
        self.decision_at(node, self.accepted.len() as u64, transactions)
    }

    fn decision_at(
        &self,
        node: [u8; 32],
        sequence: u64,
        transactions: &[Vec<u8>; 2],
    ) -> Result<(Decision, Vec<BranchCommitment>)> {
        let txs: [Transaction; 2] = [
            deserialize(&transactions[0])?,
            deserialize(&transactions[1])?,
        ];
        if txs.iter().any(|t| t.input.len() != 1) {
            return Err("invalid move input count".into());
        }
        let mut selected = None;
        let mut commitments = vec![];
        for (owner, session) in self.sessions.iter().enumerate() {
            let graph = session.graph()?;
            let state = graph.node(&node).ok_or("node absent")?;
            let mut found = false;
            for (index, edge) in state.edges.iter().enumerate() {
                let template =
                    graph.transition(node, index, txs[owner].input[0].previous_output)?;
                let mut unsigned = txs[owner].clone();
                unsigned.input[0].witness = Witness::new();
                if template.transaction() == &unsigned {
                    if edge.timeout.is_some() {
                        return Err("cooperative timeout forbidden".into());
                    }
                    if let Some(old) = selected {
                        if old != index {
                            return Err("different selected branches".into());
                        }
                    }
                    selected = Some(index);
                    found = true;
                }
                let guard = graph
                    .branch_guard(edge.child_node_id)?
                    .ok_or("branch has no revocation guard")?;
                let victim = self.sessions[0]
                    .terms
                    .identities
                    .iter()
                    .position(|k| *k == guard.counterparty.serialize())
                    .ok_or("unknown justice key")?;
                commitments.push(BranchCommitment {
                    branch: Branch {
                        edge: u32::try_from(index)?,
                        owner: u8::try_from(owner)?,
                        authorizer: u8::try_from(victim ^ 1)?,
                    },
                    hash: guard.commitment,
                });
            }
            if !found {
                return Err("owner variant has no selected branch".into());
            }
        }
        Ok((
            Decision {
                hand: self.hand()?,
                node,
                sequence,
                selected_edge: u32::try_from(selected.ok_or("selected branch absent")?)?,
                selected_txids: txs.map(|t| t.compute_txid().to_byte_array()),
            },
            commitments,
        ))
    }

    fn own_retirements(
        &self,
        decision: Decision,
        commitments: &[BranchCommitment],
    ) -> Result<RetirementFrame> {
        let mut secrets = vec![];
        for c in commitments {
            if c.branch.authorizer != self.role().code() || c.branch.edge == decision.selected_edge
            {
                continue;
            }
            let session = &self.sessions[usize::from(c.branch.owner)];
            let graph = session.graph()?;
            let child = graph.node(&decision.node).ok_or("node absent")?.edges
                [c.branch.edge as usize]
                .child_node_id;
            secrets.push((
                c.branch,
                session.retirement_secret(RetirementLevel::Branch, child)?,
            ));
        }
        Ok(RetirementFrame {
            decision,
            authorizer: self.role().code(),
            secrets,
        })
    }

    /// Authorize delivery only after the host has durably registered this exact
    /// package and verified the service receipt's digest. Persist this mutation
    /// and the returned frame in a durable outbox before sending it.
    pub fn authorize_watch(&mut self, digest: [u8; 32]) -> Result<Option<Frame>> {
        if digest != self.watch_digest()? || self.closing {
            return Err("stale watch receipt".into());
        }
        if self.handoff.as_ref().is_some_and(|h| h.peer_secret.is_some() && !h.watched) {
            let hand = self.hand()?;
            let target = self.handoff.as_mut().ok_or("missing handoff")?;
            target.watched = true;
            return Ok(Some(Frame::Retired { hand, next: target.next }));
        }
        let Some(pending) = self.pending.clone() else {
            return Ok(None);
        };
        match pending {
            Pending::Entry { launches } => {
                self.commit_pair(&launches)?;
                self.entered = true;
                self.pending = None;
                Ok(Some(Frame::Ready { hand: self.hand()? }))
            }
            Pending::Outgoing {
                transactions,
                retirement,
                ack: None,
                ..
            } => {
                if let Some(Pending::Outgoing { released, .. }) = &mut self.pending {
                    *released = true;
                }
                let authorization = self.authorization(&transactions, &retirement.decision)?;
                Ok(Some(Frame::Move {
                    authorization,
                    retirement,
                }))
            }
            Pending::Outgoing {
                transactions,
                retirement,
                ack: Some(peer),
                ..
            } => {
                self.finish_move(transactions, retirement, peer)?;
                Ok(None)
            }
            Pending::Incoming {
                transactions,
                retirement,
                own,
            } => {
                self.finish_move(transactions, own.clone(), retirement)?;
                Ok(Some(Frame::Ack { retirement: own }))
            }
        }
    }

    fn finish_move(
        &mut self,
        transactions: [Vec<u8>; 2],
        own: RetirementFrame,
        peer: RetirementFrame,
    ) -> Result<()> {
        self.commit_pair(&transactions)?;
        let retirements = if self.role() == Role::Alice {
            [own, peer]
        } else {
            [peer, own]
        };
        self.accepted.push(AcceptedMove {
            transactions,
            retirements,
        });
        self.pending = None;
        Ok(())
    }

    pub fn watch_digest(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(serde_json::to_vec(&self.watch_package()?)?).into())
    }

    /// A released outgoing move waits for its peer acknowledgment. Polling must
    /// not turn that wait into a new registration or duplicate delivery loop.
    pub fn needs_watch(&self) -> bool {
        if self.handoff.as_ref().is_some_and(|h| h.peer_secret.is_some() && !h.watched) { return !self.closing; }
        !self.closing
            && match &self.pending {
                None
                | Some(Pending::Outgoing {
                    released: true,
                    ack: None,
                    ..
                }) => false,
                _ => true,
            }
    }

    pub fn watch_package(&self) -> Result<WatchPackage> {
        let paths = std::array::from_fn(|owner| {
            if self.handoff.as_ref().is_some_and(|h| h.peer_secret.is_some()) { return vec![]; }
            let mut path = self.sessions[owner].cooperative.clone();
            match &self.pending {
                Some(Pending::Entry { launches }) => path.push(launches[owner].clone()),
                Some(
                    Pending::Outgoing { transactions, .. } | Pending::Incoming { transactions, .. },
                ) => path.push(transactions[owner].clone()),
                None => {}
            }
            path
        });
        let root = |owner: usize| -> Result<String> {
            Ok(self.sessions[owner]
                .graph()?
                .hand_commitment(
                    self.sessions[owner].terms.origin_output()?,
                    self.sessions[owner].terms.scaled_fee(500),
                )?
                .transaction()
                .compute_txid()
                .to_string())
        };
        let phase = match &self.pending {
            Some(Pending::Outgoing { ack: Some(_), .. }) => 3,
            Some(Pending::Outgoing { .. } | Pending::Incoming { .. }) => 2,
            _ => 1,
        };
        Ok(WatchPackage {
            version: 1,
            revision: self.accepted.len() as u64 * 4 + phase + if self.handoff.as_ref().is_some_and(|h| h.peer_secret.is_some()) { 4 } else { 0 },
            hand: self.hand()?,
            funding: self.sessions[0].terms.origin.clone(),
            roots: [root(0)?, root(1)?],
            paths,
            penalties: self.penalties()?,
        })
    }

    fn penalties(&self) -> Result<Vec<Vec<u8>>> {
        // Whole-hand revocation supersedes its move defenses. Retain the single
        // root justice transaction instead of an ever-growing archive of paths.
        if let Some(secret) = self.handoff.as_ref().and_then(|h| h.peer_secret) {
            return Ok(vec![self.hand_penalty(secret)?]);
        }
        let mut moves: Vec<(&[Vec<u8>; 2], &RetirementFrame)> = self
            .accepted
            .iter()
            .map(|m| {
                (
                    &m.transactions,
                    &m.retirements[usize::from(self.role().other().code())],
                )
            })
            .collect();
        match &self.pending {
            Some(Pending::Incoming {
                transactions,
                retirement,
                ..
            }) => moves.push((transactions, retirement)),
            Some(Pending::Outgoing {
                transactions,
                ack: Some(peer),
                ..
            }) => moves.push((transactions, peer)),
            _ => {}
        }
        let secp = Secp256k1::new();
        let signer = keypair(derive(&self.sessions[0].seed, b"identity"))?;
        let destination = ScriptBuf::new_p2tr(&secp, signer.x_only_public_key().0, None);
        let mut result = vec![];
        for (selected, frame) in moves {
            if frame.authorizer != self.role().other().code() {
                return Err("wrong penalty author".into());
            }
            for (branch, secret) in &frame.secrets {
                let owner = usize::from(branch.owner);
                let session = &self.sessions[owner];
                let graph = session.graph()?;
                let chosen: Transaction = deserialize(&selected[owner])?;
                let edge = graph
                    .node(&frame.decision.node)
                    .ok_or("penalty node missing")?
                    .edges
                    .get(branch.edge as usize)
                    .ok_or("penalty edge missing")?;
                let template = graph.transition(
                    frame.decision.node,
                    branch.edge as usize,
                    chosen.input[0].previous_output,
                )?;
                let guard = graph
                    .branch_guard(edge.child_node_id)?
                    .ok_or("penalty guard missing")?;
                if guard.counterparty != signer.x_only_public_key().0
                    || poker_bitcoin::channel::retirement_commitment(*secret) != guard.commitment
                {
                    return Err("invalid justice authority".into());
                }
                let child = graph
                    .node(&edge.child_node_id)
                    .ok_or("penalty child missing")?;
                let recipients: Vec<_> =
                    if let poker_settlement::PlannedState::Terminal(t) = child.state {
                        [
                            (Role::Alice, t.alice_output_sat),
                            (Role::Bob, t.bob_output_sat),
                        ]
                        .into_iter()
                        .filter(|(_, value)| *value != 0)
                        .map(|(role, _)| role)
                        .collect()
                    } else {
                        vec![self.role()]
                    };
                for (vout, output) in template.transaction().output.iter().enumerate() {
                    let fee = session.terms.scaled_fee(500);
                    let value = output
                        .value
                        .to_sat()
                        .checked_sub(fee)
                        .filter(|v| *v >= 330)
                        .ok_or("penalty requires fee rescue")?;
                    let penalty = poker_bitcoin::TransactionTemplate::normal(
                        session.terms.network(),
                        OutPoint::new(template.transaction().compute_txid(), vout as u32),
                        output.clone(),
                        vec![TxOut {
                            value: Amount::from_sat(value),
                            script_pubkey: destination.clone(),
                        }],
                        fee,
                    )?;
                    let mut tx = penalty.transaction().clone();
                    if child.edges.is_empty() {
                        let payout = graph.guarded_payout(child.node_id, recipients[vout])?;
                        let digest = taproot_script_sighash_default(
                            &tx,
                            0,
                            &[output.clone()],
                            payout.justice_script(),
                        )?;
                        let sig = sign_sighash_default(&secp, &signer, digest);
                        tx.input[0].witness =
                            payout.witness(true, &[sig.to_bytes().to_vec(), secret.to_vec()])?;
                    } else {
                        let state = graph.state(child.node_id)?;
                        let leaf = state
                            .leaf(guard.predicate_id())
                            .ok_or("penalty leaf missing")?;
                        let digest = taproot_script_sighash_default(
                            &tx,
                            0,
                            &[output.clone()],
                            leaf.script(),
                        )?;
                        let sig = sign_sighash_default(&secp, &signer, digest);
                        tx.input[0].witness =
                            leaf.assemble_witness(&[sig.to_bytes().to_vec(), secret.to_vec()])?;
                    }
                    result.push(serialize(&tx));
                }
            }
        }
        Ok(result)
    }

    pub fn view(&self) -> Result<serde_json::Value> {
        let mut view = self.sessions[0].view()?;
        view["slot"] = serde_json::json!(self.sessions[0].terms.slot);
        view["entryAllowed"] = serde_json::json!(self.entry_allowed());
        view["playAllowed"] = serde_json::json!(self.play_allowed());
        view["cooperative"] = serde_json::json!(true);
        view["recoveryReady"] = serde_json::json!(self.root.is_some());
        view["channelReady"] = serde_json::json!(self.entered && self.peer_ready && !self.closing);
        view["pendingMove"] = serde_json::json!(self.pending.is_some());
        view["closing"] = serde_json::json!(self.closing);
        view["hand"] = serde_json::json!(self.hand().ok().map(hex::encode));
        view["cashout"] = serde_json::json!(self.cashout_transaction()?.map(hex::encode));
        view["cashoutStarted"] = serde_json::json!(self.cashout.is_some());
        view["handoffComplete"] = serde_json::json!(self.handoff.as_ref().is_some_and(|h| h.watched && h.peer_ack));
        view["feeReserve"] = serde_json::json!(self.sessions[0].terms.parameters()?.rules.fee_reserve_sat);
        if let Some(actions) = view["actions"].as_array_mut() {
            actions.retain(|a| a["timeoutHeight"].is_null());
        }
        Ok(view)
    }

    /// Mutable encrypted journal; immutable preparation is written separately.
    pub fn checkpoint_journal(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = Zeroizing::new(b"CHJOUR01".to_vec());
        let metadata = Zeroizing::new(serde_json::to_vec(&Journal {
            prepared_launches: self.prepared_launches.clone(),
            selection: self.selection.clone(), entry_authorization: self.entry_authorization.clone(), play_authorization: self.play_authorization.clone(),
            cashout: self.cashout.clone(),
            handoff: self.handoff.clone(),
            version: 1,
            root: self.root.clone(),
            entered: self.entered,
            peer_ready: self.peer_ready,
            closing: self.closing,
            pending: self.pending.clone(),
            accepted: self.accepted.clone(),
        })?);
        frame_bytes(&mut bytes, &metadata)?;
        for session in &self.sessions {
            frame_bytes(&mut bytes, &session.checkpoint_journal()?)?;
        }
        Ok(bytes)
    }

    pub fn checkpoint_artifact(&self) -> Result<Vec<u8>> {
        let mut bytes = b"CHPREP01".to_vec();
        for session in &self.sessions {
            frame_bytes(&mut bytes, session.checkpoint_artifact())?;
        }
        Ok(bytes)
    }

    /// Reverify cooperative history and retirement evidence when restoring.
    /// The host must reconcile the watch service's monotonic revision and current
    /// funding-spend status before allowing this restored state to send anything.
    pub fn restore(journal: &[u8], artifact: &[u8]) -> Result<Self> {
        if journal.len() > 100_000_000
            || artifact.len() > 100_000_000
            || !journal.starts_with(b"CHJOUR01")
            || !artifact.starts_with(b"CHPREP01")
        {
            return Err("invalid channel recovery format".into());
        }
        let mut input = &journal[8..];
        let meta: Journal = serde_json::from_slice(take_frame(&mut input)?)?;
        if meta.version != 1 || meta.accepted.len() > 64 {
            return Err("invalid channel journal".into());
        }
        let mut artifacts = &artifact[8..];
        let mut sessions = vec![];
        for _ in 0..2 {
            let mut checkpoint = Zeroizing::new(take_frame(&mut input)?.to_vec());
            checkpoint.extend_from_slice(take_frame(&mut artifacts)?);
            sessions.push(Session::restore(&checkpoint)?);
        }
        if !input.is_empty() || !artifacts.is_empty() {
            return Err("trailing channel recovery data".into());
        }
        let sessions: [Session; 2] = sessions.try_into().map_err(|_| "invalid session pair")?;
        if sessions[0].channel_mode.map(|m| m.0) != Some(Role::Alice)
            || sessions[1].channel_mode.map(|m| m.0) != Some(Role::Bob)
            || sessions[0].role != sessions[1].role
            || serde_json::to_vec(&sessions[0].terms)? != serde_json::to_vec(&sessions[1].terms)?
        {
            return Err("mismatched channel materializations".into());
        }
        let mut hand = Self {
            prepared_launches: meta.prepared_launches,
            selection: meta.selection, entry_authorization: meta.entry_authorization, play_authorization: meta.play_authorization,
            cashout: meta.cashout,
            handoff: meta.handoff,
            sessions,
            root: meta.root,
            entered: meta.entered,
            peer_ready: meta.peer_ready,
            closing: meta.closing,
            pending: meta.pending,
            accepted: meta.accepted,
            verified_pending: None,
        };
        if let Some(bytes) = &hand.root {
            let session = &hand.sessions[usize::from(hand.role().code())];
            let root: Transaction = deserialize(bytes)?;
            let expected = session.graph()?.hand_commitment(
                session.terms.origin_output()?,
                session.terms.scaled_fee(500),
            )?;
            let mut unsigned = root.clone();
            for input in &mut unsigned.input {
                input.witness = Witness::new();
            }
            if &unsigned != expected.transaction() {
                return Err("recovered root belongs to another hand".into());
            }
            let state = build_origin_escrow(session.terms.identities)?;
            let leaf = &state.leaves()[0];
            let witness: Vec<_> = root.input[0].witness.iter().collect();
            if witness.len() != 4
                || witness[2] != leaf.script().as_bytes()
                || witness[3] != leaf.control_block()
            {
                return Err("invalid recovered root witness".into());
            }
            let digest = taproot_script_sighash_default(
                &root,
                0,
                &[session.terms.origin_output()?],
                leaf.script(),
            )?;
            for (i, signature) in witness[..2].iter().enumerate() {
                poker_bitcoin::verify_sighash_default(
                    &Secp256k1::verification_only(),
                    session.terms.identities[i],
                    digest,
                    poker_bitcoin::DefaultSighashSignature::from_slice(signature)?,
                )?;
            }
        } else if hand.entered || hand.pending.is_some() {
            return Err("recovered channel root is missing".into());
        }
        for session in &hand.sessions {
            if session.cooperative.len() != hand.accepted.len() + usize::from(hand.entered) {
                return Err("channel journal path mismatch".into());
            }
        }
        for (sequence, accepted) in hand.accepted.iter().enumerate() {
            for owner in 0..2 {
                if hand.sessions[owner].cooperative[sequence + 1] != accepted.transactions[owner] {
                    return Err("channel accepted move differs from verified path".into());
                }
            }
            let (decision, commitments) = hand.decision_at(
                accepted.retirements[0].decision.node,
                sequence as u64,
                &accepted.transactions,
            )?;
            let mut barrier = RetirementBarrier::new(decision, &commitments)?;
            for frame in &accepted.retirements {
                barrier.accept(frame.clone())?;
            }
            if !barrier.retired() {
                return Err("unretired recovered decision".into());
            }
        }
        match &hand.pending {
            Some(Pending::Entry { .. }) => {}
            Some(Pending::Outgoing {
                transactions,
                retirement,
                ack,
                ..
            }) => {
                let (decision, commitments) = hand.decision(transactions)?;
                let mut barrier = RetirementBarrier::new(decision, &commitments)?;
                barrier.accept(retirement.clone())?;
                if let Some(ack) = ack {
                    barrier.accept(ack.clone())?;
                }
            }
            Some(Pending::Incoming {
                transactions,
                retirement,
                own,
            }) => {
                let (decision, commitments) = hand.decision(transactions)?;
                let mut barrier = RetirementBarrier::new(decision, &commitments)?;
                barrier.accept(retirement.clone())?;
                barrier.accept(own.clone())?;
            }
            None => {}
        }
        hand.verified_pending = match &hand.pending {
            Some(Pending::Entry { launches }) => Some(hand.verify_pair(launches)?),
            Some(
                Pending::Outgoing { transactions, .. } | Pending::Incoming { transactions, .. },
            ) => Some(hand.verify_pair(transactions)?),
            None => None,
        };
        if let Some(launches)=hand.prepared_launches.clone() {hand.verify_prepared_launches(&launches)?;}
        hand.validate_selection()?;
        hand.validate_handoff()?;
        hand.validate_cashout()?;
        Ok(hand)
    }

    /// Freeze cooperation before allowing publication of the local root.
    pub fn begin_close(&mut self) -> Result<Vec<u8>> {
        if self.handoff.is_some() { return Err("use the stored successor recovery root".into()); }
        let root = self.root.clone().ok_or("no enforceable local root")?;
        self.closing = true;
        Ok(root)
    }
}
