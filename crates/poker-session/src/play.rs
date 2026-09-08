use super::*;
use dealer_openings::{ShareOpening, derive_card_signing_key, verify_share_opening};
use poker_score_ots::{
    AliceScoreCertificate, BobScoreCertificate, Score24, issue_alice_score_certificate,
    issue_bob_score_certificate,
};
use poker_settlement::PlannedState;
use poker_settlement_types::{Action, EdgeKind, ShowdownOutcome};
use serde_json::json;
fn observed_number(bytes: &[u8]) -> Result<u32> {
    if bytes.len() > 4 || bytes.last().is_some_and(|b| b & 0x80 != 0) {
        return Err("invalid showdown number".into());
    }
    let mut number = [0; 4];
    number[..bytes.len()].copy_from_slice(bytes);
    Ok(u32::from_le_bytes(number))
}
fn unsigned(tx: &Transaction) -> Transaction {
    let mut t = tx.clone();
    for i in &mut t.input {
        i.witness = Witness::new();
    }
    t
}
pub(super) fn actor(state: &PlannedState) -> Option<Role> {
    match state {
        PlannedState::Reveal { pattern, .. } => Some(pattern.revealer()),
        PlannedState::Betting { state, .. } => Some(state.actor),
        PlannedState::AliceShowdown { .. } => Some(Role::Alice),
        PlannedState::BobTerminal { .. } => Some(Role::Bob),
        PlannedState::Terminal(_) => None,
    }
}
struct TransitionEffects {
    next: Option<[u8; 32]>,
    terminal: bool,
    openings: Vec<((u8, u8), (u8, k256::Scalar))>,
    alice: Option<poker_bitcoin::showdown_witness::ObservedAliceScoreCertificate>,
    shown: Option<(u8, [u8; 2])>,
}
pub(super) struct VerifiedCooperative {
    transaction: Transaction,
    parent: Option<OutPoint>,
    effects: TransitionEffects,
}
impl VerifiedCooperative {
    pub(super) fn matches(&self, bytes: &[u8]) -> bool {
        serialize(&self.transaction) == bytes
    }
}
impl Session {
    fn visible_card(&self, slot: u8) -> Result<Option<u8>> {
        // Community cards become visible only after both required reveals confirm.
        if slot >= 4 && !self.observed.contains_key(&(self.role.code(), slot)) {
            return Ok(None);
        }
        let Some(&(value, blinding)) = self.observed.get(&(self.role.other().code(), slot)) else {
            return Ok(None);
        };
        let local = &self.dealer.setup_secrets()?.openings[usize::from(slot)];
        let own = ShareOpening {
            value: local.value(),
            blinding: *local.gamma(),
        };
        let peer = ShareOpening { value, blinding };
        let (a, b) = if self.role == Role::Alice {
            (own, peer)
        } else {
            (peer, own)
        };
        let deal = self.dealer.accepted()?;
        let a = verify_share_opening(deal, dealer_protocol::Role::A, slot, a)?;
        let b = verify_share_opening(deal, dealer_protocol::Role::B, slot, b)?;
        Ok(Some(derive_card_signing_key(deal, slot, &a, &b)?.card_id()))
    }
    pub fn view(&self) -> Result<serde_json::Value> {
        let mut v = json!({"role":self.role.code(),"dealer":self.dealer_status(),"ready":self.ready.is_some(),"terminal":self.terminal,"tip":self.tip.map(|o|o.to_string()),"height":self.height,"pending":self.pending.as_ref().map(|t|t.compute_txid().to_string()),"missing":self.preparation.as_ref().map(SettlementPreparation::missing_count)});
        v["opponentCards"] = json!(self.public_holes.get(&self.role.other().code()));
        v["originScript"] = json!(hex::encode(
            self.terms.origin_output()?.script_pubkey.as_bytes()
        ));
        if let Some(id) = self.current {
            let g = self.graph()?;
            let n = g.node(&id).ok_or("node missing")?;
            let amounts = n.state.amounts();
            v["stacks"] = json!([amounts.alice_remaining, amounts.bob_remaining]);
            v["pot"] = json!(amounts.pot);
            v["feeReserve"] = json!(amounts.fee_reserve_remaining);
            v["betting"] = json!(matches!(n.state, PlannedState::Betting { .. }));
            v["roundBets"] = json!([0, 0]);
            v["revealing"] = json!(matches!(n.state, PlannedState::Reveal { .. }));
            if let PlannedState::Betting { state, .. } = &n.state {
                v["roundBets"] = json!([
                    state.alice_committed_this_street,
                    state.bob_committed_this_street
                ]);
                let committed = if self.role == Role::Alice {
                    state.alice_committed_this_street
                } else {
                    state.bob_committed_this_street
                };
                v["toCall"] = json!(
                    state
                        .current_wager
                        .saturating_sub(committed)
                        .min(amounts.remaining(self.role))
                );
            }
            if let PlannedState::Terminal(t) = &n.state {
                v["payouts"] = json!([t.alice_output_sat, t.bob_output_sat]);
                v["nextStacks"] = json!([t.accounting.alice_sat, t.accounting.bob_sat]);
                v["outcome"] = json!(format!("{:?}", t.outcome));
            }
            let slots = if self.role == Role::Alice {
                [0, 2]
            } else {
                [1, 3]
            };
            v["holeCards"] = json!(
                slots
                    .into_iter()
                    .map(|slot| self.visible_card(slot))
                    .collect::<Result<Vec<_>>>()?
            );
            v["board"] = json!(
                (4..9)
                    .map(|slot| self.visible_card(slot))
                    .collect::<Result<Vec<_>>>()?
            );
            v["node"] = json!(hex::encode(id));
            v["phase"] = json!(format!("{:?}", n.state.phase()));
            v["actor"] = json!(actor(&n.state).map(|r| r.code()));
            v["actions"]=json!(n.edges.iter().enumerate().map(|(i,e)|json!({"index":i,"kind":format!("{:?}",e.kind),"betAmount": if matches!(e.kind, EdgeKind::Action(Action::Bet | Action::Raise | Action::Call)) { g.node(&e.child_node_id).map(|child| amounts.remaining(self.role).saturating_sub(child.state.amounts().remaining(self.role))) } else { None },"timeoutHeight":e.timeout.map(|t|self.height+u32::from(t.csv)),"beneficiary":e.timeout.map(|t|t.beneficiary.code())})).collect::<Vec<_>>());
        }
        Ok(v)
    }
    pub(super) fn issue_score(&mut self, score: u32) -> Result<Vec<u8>> {
        if self.issued_score.is_some_and(|s| s != score) {
            return Err("score key already used for another score".into());
        }
        if let Some(c) = &self.issued_certificate {
            return Ok(c.clone());
        }
        let key = self.score.as_mut().ok_or("score key missing")?;
        let c = if self.role == Role::Alice {
            issue_alice_score_certificate(key, Score24::new(score)?)?.encode()
        } else {
            issue_bob_score_certificate(key, Score24::new(score)?)?.encode()
        };
        self.issued_score = Some(score);
        self.issued_certificate = Some(c.clone());
        Ok(c)
    }
    /// Select a deterministic legal passive path, or a requested edge. Timeout
    /// maturity is enforced again by the chain; the UI supplies the observed tip.
    pub fn action(&mut self, requested: Option<usize>, chain_height: u32) -> Result<Vec<u8>> {
        if let Some(tx) = &self.pending {
            return Ok(serialize(tx));
        }
        if self.terminal {
            return Err("game finished".into());
        }
        let id = self.current.ok_or("activation not confirmed")?;
        let mut keys = Vec::new();
        let mut best = (0, 0);
        let (mut chosen, is_showdown) = {
            let g = self.graph()?;
            let n = g.node(&id).ok_or("node missing")?;
            let showdown = matches!(
                n.state,
                PlannedState::AliceShowdown { .. } | PlannedState::BobTerminal { .. }
            );
            let chosen = requested.unwrap_or_else(|| {
                n.edges
                    .iter()
                    .position(|e| matches!(e.kind, EdgeKind::Action(Action::Call | Action::Check)))
                    .unwrap_or(0)
            });
            let edge = n.edges.get(chosen).ok_or("invalid edge")?;
            if let Some(t) = edge.timeout {
                if t.beneficiary != self.role || chain_height < self.height + u32::from(t.csv) {
                    return Err("timeout unavailable".into());
                }
            } else if actor(&n.state) != Some(self.role) {
                return Err("not local turn".into());
            }
            (chosen, showdown && edge.timeout.is_none())
        };
        if is_showdown {
            let slots = if self.role == Role::Alice {
                poker_bitcoin::ALICE_SEVEN_SLOTS
            } else {
                poker_bitcoin::BOB_SEVEN_SLOTS
            };
            let deal = self.dealer.accepted()?;
            for slot in slots {
                let local = &self.dealer.setup_secrets()?.openings[usize::from(slot)];
                let own = ShareOpening {
                    value: local.value(),
                    blinding: *local.gamma(),
                };
                let &(value, blinding) = self
                    .observed
                    .get(&(self.role.other().code(), slot))
                    .ok_or("peer opening not confirmed")?;
                let peer = ShareOpening { value, blinding };
                let (a, b) = if self.role == Role::Alice {
                    (own, peer)
                } else {
                    (peer, own)
                };
                let a = verify_share_opening(deal, dealer_protocol::Role::A, slot, a)?;
                let b = verify_share_opening(deal, dealer_protocol::Role::B, slot, b)?;
                keys.push(derive_card_signing_key(deal, slot, &a, &b)?);
            }
            let cards = std::array::from_fn(|i| keys[i].card_id());
            for subset in 0..21 {
                let score =
                    poker_eval::evaluate_five_cards(poker_eval::selected_five(cards, subset)?)?;
                if score > best.0 {
                    best = (score, subset);
                }
            }
            if self.role == Role::Bob {
                let a = self
                    .alice_certificate
                    .as_ref()
                    .ok_or("Alice score not confirmed")?
                    .score_a()
                    .get();
                let outcome = match best.0.cmp(&a) {
                    std::cmp::Ordering::Less => ShowdownOutcome::AliceWin,
                    std::cmp::Ordering::Equal => ShowdownOutcome::Split,
                    std::cmp::Ordering::Greater => ShowdownOutcome::BobWin,
                };
                let g = self.graph()?;
                chosen = g
                    .node(&id)
                    .ok_or("node missing")?
                    .edges
                    .iter()
                    .position(|e| e.kind == EdgeKind::BobPayout(outcome))
                    .ok_or("payout missing")?;
                if requested.is_some_and(|index| index != chosen) {
                    return Err("requested payout does not match confirmed cards and score".into());
                }
            }
        }
        let certificate = if !keys.is_empty() {
            Some(self.issue_score(best.0)?)
        } else {
            None
        };
        let g = self.graph()?;
        let n = g.node(&id).ok_or("node missing")?;
        let e = n.edges.get(chosen).ok_or("invalid edge")?;
        if let Some(t) = e.timeout {
            if t.beneficiary != self.role || chain_height < self.height + u32::from(t.csv) {
                return Err("timeout unavailable".into());
            }
        } else if actor(&n.state) != Some(self.role) {
            return Err("not local turn".into());
        }
        let template = g.transition(id, chosen, self.tip.ok_or("tip missing")?)?;
        let state = g.state(id)?;
        let leaf = state
            .leaf(g.program(id, chosen)?.predicate_id())
            .ok_or("leaf missing")?;
        let digest = taproot_script_sighash_default(
            template.transaction(),
            0,
            &[template.parent_output().clone()],
            leaf.script(),
        )?;
        let live = sign_sighash_default(
            &Secp256k1::new(),
            &keypair(derive(&self.seed, b"identity"))?,
            digest,
        )
        .to_bytes();
        let ready = self.ready.as_ref().ok_or("preparation incomplete")?;
        let elements = if let PlannedState::Reveal { pattern, .. } = n.state {
            if e.timeout.is_none() {
                let mut elements = vec![live.to_vec()];
                for &slot in pattern.slots() {
                    let opening = &self.dealer.setup_secrets()?.openings[usize::from(slot)];
                    elements.push(
                        ready
                            .reveal(id, slot)?
                            .complete(opening.value(), *opening.gamma())?
                            .to_vec(),
                    );
                }
                elements
            } else {
                let (_, fixed) = ready.signature(id, chosen)?;
                if self.role == Role::Alice {
                    vec![live.to_vec(), fixed.to_bytes().to_vec()]
                } else {
                    vec![fixed.to_bytes().to_vec(), live.to_vec()]
                }
            }
        } else {
            let (other, fixed) = ready.signature(id, chosen)?;
            if other != self.role.other() {
                return Err("presignature role mismatch".into());
            }
            let auth = if self.role == Role::Alice {
                [live, fixed.to_bytes()]
            } else {
                [fixed.to_bytes(), live]
            };
            if keys.is_empty() {
                auth.map(|s| s.to_vec()).to_vec()
            } else {
                let mut sigs = [[0; 64]; 7];
                for i in 0..7 {
                    sigs[i] = keys[i]
                        .sign_tapscript_sighash(&digest, &derive(&self.seed, b"card-aux"))?
                        .to_bytes();
                }
                let hand = poker_bitcoin::showdown_witness::ShowdownWitness::verify(
                    self.dealer.accepted()?,
                    self.role,
                    digest,
                    std::array::from_fn(|i| keys[i].raw_sum()),
                    sigs,
                    best.1,
                    best.0,
                )?;
                let c = certificate.ok_or("score certificate missing")?;
                if self.role == Role::Alice {
                    hand.alice_elements(auth, &AliceScoreCertificate::decode(&c)?)?
                } else {
                    hand.bob_elements_with_observed_alice(
                        auth,
                        self.alice_certificate
                            .as_ref()
                            .ok_or("Alice certificate missing")?,
                        &BobScoreCertificate::decode(&c)?,
                    )?
                }
            }
        };
        let mut tx = template.transaction().clone();
        tx.input[0].witness = leaf.assemble_witness(&elements)?;
        self.pending = Some(tx.clone());
        Ok(serialize(&tx))
    }
    /// Apply a transaction only after the configured chain adapter has established
    /// its confirmation. Rejects a changed branch, template, script or control block.
    pub fn observe(&mut self, record: ChainRecord) -> Result<()> {
        let tx: Transaction = deserialize(&record.transaction)?;
        if record.height == 0
            || record.block_hash.len() != 64
            || hex::decode(&record.block_hash)?.len() != 32
        {
            return Err("invalid confirmation".into());
        }
        if let Some(old) = self.chain.iter().find(|r| {
            deserialize::<Transaction>(&r.transaction)
                .is_ok_and(|t| t.compute_txid() == tx.compute_txid())
        }) {
            if old.transaction == record.transaction
                && old.block_hash == record.block_hash
                && old.height == record.height
            {
                return Ok(());
            }
            return Err("chain observation changed; reconciliation required".into());
        }
        if !self.cooperative.is_empty() {
            return Err("use a separate chain recovery replay after cooperative play".into());
        }
        self.apply_transaction(tx, Some(record))
    }

    /// Used only by the channel driver after its retirement and durability gates.
    /// There are no invented block heights. Timeout edges are never cooperative.
    pub(super) fn accept_cooperative(&mut self, bytes: &[u8]) -> Result<()> {
        if self.channel_mode.is_none() || !self.chain.is_empty() {
            return Err("not an active cooperative hand".into());
        }
        let tx: Transaction = deserialize(bytes)?;
        for old in &self.cooperative {
            let previous: Transaction = deserialize(old)?;
            if previous.compute_txid() == tx.compute_txid() {
                return if old == bytes {
                    Ok(())
                } else {
                    Err("conflicting cooperative witness".into())
                };
            }
        }
        let step = self.verify_cooperative(bytes)?;
        self.commit_cooperative(step)
    }

    pub(super) fn verify_cooperative(&self, bytes: &[u8]) -> Result<VerifiedCooperative> {
        if self.channel_mode.is_none() || !self.chain.is_empty() {
            return Err("not a cooperative hand".into());
        }
        let transaction = deserialize(bytes)?;
        let effects = self.validate_transaction(&transaction, &None)?;
        Ok(VerifiedCooperative {
            transaction,
            parent: self.tip,
            effects,
        })
    }

    pub(super) fn commit_cooperative(&mut self, step: VerifiedCooperative) -> Result<()> {
        if step.parent != self.tip {
            return Err("cooperative step became stale".into());
        }
        let bytes = serialize(&step.transaction);
        self.apply_effects(step.transaction, step.effects, None);
        self.cooperative.push(bytes);
        Ok(())
    }

    fn apply_transaction(&mut self, tx: Transaction, record: Option<ChainRecord>) -> Result<()> {
        let effects = self.validate_transaction(&tx, &record)?;
        self.apply_effects(tx, effects, record);
        Ok(())
    }

    fn validate_transaction(
        &self,
        tx: &Transaction,
        record: &Option<ChainRecord>,
    ) -> Result<TransitionEffects> {
        if self.terminal {
            return Err("game already terminal".into());
        }
        if tx.input.len() != 1 {
            return Err("unexpected input count".into());
        }
        let g = self.graph()?;
        let ready = self.ready.as_ref().ok_or("not prepared")?;
        let mut shown = None;
        let (next, terminal, openings, alice) = if let Some(id) = self.current {
            if tx.input[0].previous_output != self.tip.ok_or("tip missing")? {
                return Err("wrong parent".into());
            }
            let n = g.node(&id).ok_or("node missing")?;
            let mut matched = None;
            for (i, e) in n.edges.iter().enumerate() {
                let template = g.transition(id, i, self.tip.ok_or("tip missing")?)?;
                if unsigned(&tx) == *template.transaction() {
                    matched = Some((i, e));
                    break;
                }
            }
            let (index, e) = matched.ok_or("not an authorized graph transaction")?;
            if let Some(t) = e.timeout {
                let height = record
                    .as_ref()
                    .ok_or("timeouts cannot advance cooperative state")?
                    .height;
                if height < self.height + u32::from(t.csv) + u32::from(g.contest_delay(id)) {
                    return Err("premature timeout".into());
                }
            }
            let state = g.state(id)?;
            let leaf = state
                .leaf(g.program(id, index)?.predicate_id())
                .ok_or("leaf missing")?;
            let witness: Vec<_> = tx.input[0].witness.iter().collect();
            let suffix = [leaf.script().as_bytes(), leaf.control_block()];
            if witness.len() < 2 || witness[witness.len() - 2..] != suffix[..] {
                return Err("wrong witness script/control".into());
            }
            if record.is_none() {
                if witness.len() != leaf.expected_witness_elements() + 2 {
                    return Err("noncanonical cooperative witness".into());
                }
                let template = g.transition(id, index, self.tip.ok_or("tip missing")?)?;
                let digest = taproot_script_sighash_default(
                    &tx,
                    0,
                    &[template.parent_output().clone()],
                    leaf.script(),
                )?;
                let elements = &witness[..witness.len() - 2];
                match n.state {
                    PlannedState::AliceShowdown { .. } | PlannedState::BobTerminal { .. } => {
                        let outcome = match e.kind {
                            EdgeKind::BobPayout(o) => Some(o),
                            _ => None,
                        };
                        poker_bitcoin::showdown_witness::ShowdownWitness::verify_cooperative_elements(
                            self.dealer.accepted()?, actor(&n.state).ok_or("missing actor")?, digest,
                            self.terms.identities, self.scores.as_ref().ok_or("missing scores")?, outcome, elements)?;
                        if outcome.is_some() {
                            let prior = self
                                .alice_certificate
                                .as_ref()
                                .ok_or("missing prior Alice score")?;
                            if observed_number(elements[0])? != prior.score_a().get() {
                                return Err("Alice score changed".into());
                            }
                        }
                    }
                    PlannedState::Reveal { pattern, .. } => {
                        poker_bitcoin::verify_sighash_default(
                            &Secp256k1::verification_only(),
                            self.terms.identities[usize::from(pattern.revealer().code())],
                            digest,
                            poker_bitcoin::DefaultSighashSignature::from_slice(elements[0])?,
                        )?;
                    }
                    _ => {
                        // The counterpart's exact authorization was verified
                        // during preparation. Only the actor's signature is new.
                        let actor = usize::from(actor(&n.state).ok_or("missing actor")?.code());
                        let (_, fixed) = ready.signature(id, index)?;
                        if elements[actor ^ 1] != fixed.to_bytes().as_slice() {
                            return Err("prepared authorization changed".into());
                        }
                        poker_bitcoin::verify_sighash_default(
                            &Secp256k1::verification_only(),
                            self.terms.identities[actor],
                            digest,
                            poker_bitcoin::DefaultSighashSignature::from_slice(elements[actor])?,
                        )?;
                    }
                }
            }
            if e.timeout.is_none() {
                let showing = match n.state {
                    PlannedState::AliceShowdown { .. } => Some(Role::Alice),
                    PlannedState::BobTerminal { .. } => Some(Role::Bob),
                    _ => None,
                };
                if let Some(showing) = showing {
                    if witness.len() < 17 {
                        return Err("showdown hand absent".into());
                    }
                    let start = witness.len() - 16;
                    let mut sums = [0u8; 7];
                    let mut signatures = [[0u8; 64]; 7];
                    for i in 0..7 {
                        signatures[i] = witness[start + 2 * i]
                            .try_into()
                            .map_err(|_| "invalid card signature")?;
                        sums[i] = observed_number(witness[start + 2 * i + 1])?.try_into()?;
                    }
                    let subset = observed_number(witness[start - 1])?.try_into()?;
                    let score_index = if showing == Role::Alice { 0 } else { 49 };
                    let score =
                        observed_number(witness.get(score_index).ok_or("showdown score absent")?)?;
                    let template = g.transition(id, index, self.tip.ok_or("tip missing")?)?;
                    let digest = taproot_script_sighash_default(
                        &tx,
                        0,
                        &[template.parent_output().clone()],
                        leaf.script(),
                    )?;
                    // Cooperative certificate validation above already checked
                    // the card signatures and selected five-card score.
                    if record.is_some() {
                        poker_bitcoin::showdown_witness::ShowdownWitness::verify(
                            self.dealer.accepted()?,
                            showing,
                            digest,
                            sums,
                            signatures,
                            subset,
                            score,
                        )?;
                    }
                    shown = Some((showing.code(), [sums[0] % 52, sums[1] % 52]));
                }
            }
            let mut openings = vec![];
            if e.timeout.is_none() {
                if let PlannedState::Reveal { pattern, .. } = n.state {
                    for (i, &slot) in pattern.slots().iter().enumerate() {
                        let sig: [u8; 64] = witness
                            .get(i + 1)
                            .ok_or("reveal signature absent")?
                            .to_vec()
                            .try_into()
                            .map_err(|_| "invalid reveal signature")?;
                        openings.push((
                            (pattern.revealer().code(), slot),
                            ready.reveal(id, slot)?.extract(&sig)?,
                        ));
                    }
                }
            }
            let mut alice = None;
            if e.timeout.is_none() && matches!(n.state, PlannedState::AliceShowdown { .. }) {
                use poker_bitcoin::showdown_witness::ObservedAliceScoreCertificate;

                let p = &self.scores.as_ref().ok_or("score keys missing")?[0];
                let elements = witness
                    .get(..ObservedAliceScoreCertificate::WITNESS_ELEMENTS)
                    .ok_or("score certificate missing")?;
                alice = Some(ObservedAliceScoreCertificate::from_witness_elements(
                    elements, p,
                )?);
            }
            (
                Some(e.child_node_id),
                matches!(
                    g.node(&e.child_node_id).ok_or("child missing")?.state,
                    PlannedState::Terminal(_)
                ),
                openings,
                alice,
            )
        } else {
            if unsigned(&tx) != *ready.activation().transaction() {
                return Err("wrong activation".into());
            }
            if record.is_none() {
                let (state, predicate) = self.activation_state()?;
                let leaf = state.leaf(predicate).ok_or("activation leaf missing")?;
                let elements: Vec<_> = tx.input[0].witness.iter().collect();
                if elements.len() != 4
                    || elements[2] != leaf.script().as_bytes()
                    || elements[3] != leaf.control_block()
                {
                    return Err("invalid cooperative activation witness".into());
                }
                let digest = taproot_script_sighash_default(
                    &tx,
                    0,
                    &[ready.activation().parent_output().clone()],
                    leaf.script(),
                )?;
                for i in 0..2 {
                    poker_bitcoin::verify_sighash_default(
                        &Secp256k1::verification_only(),
                        self.terms.identities[i],
                        digest,
                        poker_bitcoin::DefaultSighashSignature::from_slice(elements[i])?,
                    )?;
                }
            }
            (Some(g.plan().root_node_id), false, vec![], None)
        };
        Ok(TransitionEffects {
            next,
            terminal,
            openings,
            alice,
            shown,
        })
    }

    fn apply_effects(
        &mut self,
        tx: Transaction,
        effects: TransitionEffects,
        record: Option<ChainRecord>,
    ) {
        let TransitionEffects {
            next,
            terminal,
            openings,
            alice,
            shown,
        } = effects;
        self.current = next;
        self.terminal = terminal;
        self.tip = Some(OutPoint {
            txid: tx.compute_txid(),
            vout: 0,
        });
        if let Some(record) = &record {
            self.height = record.height;
        }
        for (k, v) in openings {
            self.observed.insert(k, v);
        }
        if let Some(c) = alice {
            self.alice_certificate = Some(c);
        }
        if let Some((role, cards)) = shown {
            self.public_holes.insert(role, cards);
        }
        self.pending = None;
        if let Some(record) = record {
            self.chain.push(record);
        }
    }
}
