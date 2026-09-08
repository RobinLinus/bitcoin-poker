//! Stable future hand contexts and local activation capabilities.
use super::*;
use hmac::{Hmac, Mac};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSlot {
    pub channel: [u8; 32],
    pub index: u32,
    pub opening_nonce: [u8; 32],
    pub opening_button: u8,
}
impl Terms {
    fn channel_id(&self, opening_nonce: [u8; 32], button: u8) -> Result<[u8; 32]> {
        let mut base = self.clone();
        base.slot = None;
        base.nonce = opening_nonce;
        base.predeal_anchor = None;
        base.stacks = None;
        base.button = Some(button);
        let mut hash = Sha256::new();
        hash.update(b"POKER/channel-context/v1");
        hash.update(serde_json::to_vec(&base)?);
        Ok(hash.finalize().into())
    }
    pub(crate) fn initialize_slot(&mut self) -> Result<()> {
        if self.slot.is_none() {
            self.slot = Some(ChannelSlot {
                channel: self.channel_id(self.nonce, self.button.unwrap_or(0))?,
                index: 0,
                opening_nonce: self.nonce,
                opening_button: self.button.unwrap_or(0),
            });
        }
        let slot = self.slot.as_ref().unwrap();
        if slot.opening_button > 1
            || slot.channel != self.channel_id(slot.opening_nonce, slot.opening_button)?
            || self.button.unwrap_or(0) != (slot.opening_button ^ (slot.index as u8 & 1))
        {
            return Err("invalid channel slot".into());
        }
        if slot.index == 0 {
            if self.nonce != slot.opening_nonce || self.predeal_anchor == Some([0;32]) {
                return Err("invalid opening hand".into());
            }
        } else if self.nonce != slot.nonce(self.predeal_anchor.ok_or("missing slot anchor")?) {
            return Err("invalid future hand nonce".into());
        }
        Ok(())
    }
}
impl ChannelSlot {
    fn nonce(&self, anchor: [u8; 32]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"POKER/channel-slot/v1");
        hash.update(self.channel);
        hash.update(self.index.to_le_bytes());
        hash.update(anchor);
        hash.finalize().into()
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Candidate {
    pub terms: Terms,
    pub hand: [u8; 32],
}
impl ChannelHand {
    fn capability(&self, domain: &[u8], payload: &[u8]) -> Result<Hmac<Sha256>> {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&derive(&self.sessions[0].seed, b"channel-capability"))?;
        mac.update(domain);
        mac.update(payload);
        Ok(mac)
    }
    fn seal_capability(&self, domain: &[u8], payload: &Candidate) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(payload)?;
        let tag = self.capability(domain, &bytes)?.finalize().into_bytes();
        bytes.extend_from_slice(&tag);
        Ok(bytes)
    }
    fn open_capability(&self, domain: &[u8], bytes: &[u8]) -> Result<Candidate> {
        if !(33..=16384).contains(&bytes.len()) {
            return Err("invalid candidate capability".into());
        }
        let (body, tag) = bytes.split_at(bytes.len() - 32);
        self.capability(domain, body)?.verify_slice(tag)?;
        Ok(serde_json::from_slice(body)?)
    }
    pub fn future_terms(&self, index: u32, anchor: [u8; 32], stacks: [u64; 2]) -> Result<Terms> {
        let mut terms = self.sessions[0].terms.clone();
        let slot = terms.slot.as_mut().ok_or("channel slot missing")?;
        if index <= slot.index || index > slot.index.saturating_add(3) || anchor == [0; 32] {
            return Err("future slot outside buffer".into());
        }
        slot.index = index;
        terms.nonce = slot.nonce(anchor);
        terms.button = Some(slot.opening_button ^ (index as u8 & 1));
        terms.predeal_anchor = Some(anchor);
        terms.stacks = Some(stacks);
        terms.initialize_slot()?;
        Ok(terms)
    }
    pub fn prepared_certificate(&self) -> Result<Vec<u8>> {
        if self.closing
            || self.entered
            || self.prepared_launches.is_none()
            || self.sessions.iter().any(|s| s.ready.is_none())
        {
            return Err("candidate not prepared".into());
        }
        self.seal_capability(
            b"prepared",
            &Candidate {
                terms: self.sessions[0].terms.clone(),
                hand: self.hand()?,
            },
        )
    }
    pub(super) fn check_successor(&self, next: &Candidate) -> Result<()> {
        let session = &self.sessions[0];
        if self.pending.is_some() || !self.sessions.iter().all(|s| s.terminal) {
            return Err("parent hand not settled".into());
        }
        let stacks: [u64; 2] = serde_json::from_value(session.view()?["nextStacks"].clone())?;
        let index = session
            .terms
            .slot
            .as_ref()
            .ok_or("missing parent slot")?
            .index
            .checked_add(1)
            .ok_or("hand index overflow")?;
        let expected = self.future_terms(
            index,
            next.terms
                .predeal_anchor
                .ok_or("missing successor anchor")?,
            stacks,
        )?;
        if stacks.iter().any(|n| *n < 200)
            || next.hand == self.hand()?
            || serde_json::to_vec(&expected)? != serde_json::to_vec(&next.terms)?
        {
            return Err("successor changes funding or settled balances".into());
        }
        Ok(())
    }
    pub fn select_candidate(&mut self, prepared: &[u8]) -> Result<Vec<u8>> {
        if self.closing {
            return Err("channel closing".into());
        }
        let next = self.open_capability(b"prepared", prepared)?;
        self.check_successor(&next)?;
        let certificate = self.seal_capability(b"selected", &next)?;
        if self
            .selection
            .as_ref()
            .is_some_and(|old| old != &certificate)
        {
            return Err("another candidate already selected".into());
        }
        self.selection = Some(certificate.clone());
        Ok(certificate)
    }
    pub fn authorize_entry(&mut self, certificate: &[u8]) -> Result<()> {
        let next = self.open_capability(b"selected", certificate)?;
        if next.hand != self.hand()?
            || serde_json::to_vec(&next.terms)? != serde_json::to_vec(&self.sessions[0].terms)?
        {
            return Err("candidate selection mismatch".into());
        }
        if self
            .entry_authorization
            .as_ref()
            .is_some_and(|old| old != certificate)
        {
            return Err("conflicting entry selection".into());
        }
        self.entry_authorization = Some(certificate.to_vec());
        Ok(())
    }
    pub fn play_certificate(&self) -> Result<Vec<u8>> {
        let handoff = self.handoff.as_ref().ok_or("handoff not started")?;
        if !handoff.watched || !handoff.peer_ack {
            return Err("previous hand not retired".into());
        }
        let next = self.open_capability(
            b"selected",
            self.selection.as_ref().ok_or("candidate not selected")?,
        )?;
        self.seal_capability(b"active", &next)
    }
    pub fn authorize_play(&mut self, certificate: &[u8]) -> Result<()> {
        let next = self.open_capability(b"active", certificate)?;
        if self.entry_authorization.is_none()
            || next.hand != self.hand()?
            || serde_json::to_vec(&next.terms)? != serde_json::to_vec(&self.sessions[0].terms)?
        {
            return Err("invalid play authorization".into());
        }
        self.play_authorization = Some(certificate.to_vec());
        Ok(())
    }
    pub(super) fn entry_allowed(&self) -> bool {
        self.sessions[0]
            .terms
            .slot
            .as_ref()
            .is_some_and(|s| s.index == 0)
            || self.entry_authorization.is_some()
    }
    pub(super) fn play_allowed(&self) -> bool {
        self.sessions[0]
            .terms
            .slot
            .as_ref()
            .is_some_and(|s| s.index == 0)
            || self.play_authorization.is_some()
    }
    pub(super) fn validate_selection(&mut self) -> Result<()> {
        if let Some(cert) = self.selection.clone() {
            let next = self.open_capability(b"selected", &cert)?;
            self.check_successor(&next)?;
        }
        if let Some(cert) = self.entry_authorization.clone() {
            self.authorize_entry(&cert)?;
        }
        if let Some(cert) = self.play_authorization.clone() {
            self.authorize_play(&cert)?;
        }
        if (self.root.is_some() && !self.entry_allowed())
            || (!self.accepted.is_empty() && !self.play_allowed())
        {
            return Err("unselected candidate recovery".into());
        }
        Ok(())
    }
}

impl ChannelHand {
    pub fn fork_predeal(&self, terms: Terms) -> Result<Self> {
        let mut fork = Self::new(
            *self.sessions[0].seed,
            terms.clone(),
            self.sessions[0].channel_mode.ok_or("not channel")?.1,
        )?;
        for i in 0..2 {
            let source = &self.sessions[i];
            source.dealer.accepted()?;
            if source.local_score.is_some()
                || source.preparation.is_some()
                || source.terms.nonce != terms.nonce
                || source.terms.parameters()?.session_anchor()
                    != terms.parameters()?.session_anchor()
                || source.terms.parameters()?.dealing_rules_hash()?
                    != terms.parameters()?.dealing_rules_hash()?
            {
                return Err("cannot fork this dealer context".into());
            }
            fork.sessions[i].dealer = Arc::clone(&source.dealer);
            fork.sessions[i].events = source.events.clone();
        }
        Ok(fork)
    }
    /// Public exact outcomes only; no card values affect preparation priorities.
    pub fn reachable_balances(&self) -> Result<Vec<[u64; 2]>> {
        use poker_settlement::PlannedState;
        use std::collections::{HashSet, VecDeque};
        let session = &self.sessions[0];
        let graph = session.graph()?;
        let mut queue = VecDeque::from([session.current.unwrap_or(graph.plan().root_node_id)]);
        let mut seen = HashSet::new();
        let mut balances = vec![];
        while let Some(id) = queue.pop_front() {
            if !seen.insert(id) {
                continue;
            }
            let node = graph.node(&id).ok_or("missing reachable node")?;
            if let PlannedState::Terminal(t) = &node.state {
                let pair = [t.accounting.alice_sat, t.accounting.bob_sat];
                if pair.iter().all(|n| *n >= 200) && !balances.contains(&pair) {
                    balances.push(pair);
                }
            } else {
                for edge in &node.edges {
                    if edge.timeout.is_none() {
                        queue.push_back(edge.child_node_id);
                    }
                }
            }
        }
        Ok(balances)
    }
}

impl ChannelHand {
    pub fn launch_signatures(&self) -> Result<[Vec<u8>; 2]> {
        Ok([
            self.sessions[0].activation_signature()?,
            self.sessions[1].activation_signature()?,
        ])
    }
    pub(super) fn verify_prepared_launches(&mut self, signatures: &[Vec<u8>; 2]) -> Result<()> {
        for (i, signature) in signatures.iter().enumerate() {
            let pending = self.sessions[i].pending.clone();
            let result = self.sessions[i].activation(signature);
            self.sessions[i].pending = pending;
            result?;
        }
        Ok(())
    }
    pub fn accept_prepared_launches(&mut self, signatures: [Vec<u8>; 2]) -> Result<()> {
        if self.entered
            || self
                .prepared_launches
                .as_ref()
                .is_some_and(|old| old != &signatures)
        {
            return Err("conflicting prepared launch".into());
        }
        self.verify_prepared_launches(&signatures)?;
        self.prepared_launches = Some(signatures);
        Ok(())
    }
}

impl ChannelHand {
    pub fn defer_payouts(&mut self) -> Result<()> {
        if self.selection.is_some() || self.entry_authorization.is_some() || self.entered || self.pending.is_some() {
            return Err("hand already selected".into());
        }
        for session in &mut self.sessions { session.defer_payouts()?; }
        Ok(())
    }
    pub fn bind_payouts(&mut self, stacks: [u64;2]) -> Result<[usize;2]> {
        if self.selection.is_some() || self.entry_authorization.is_some() || self.entered || self.pending.is_some()
            || self.root.is_some() || self.prepared_launches.is_some() {
            return Err("hand already selected".into());
        }
        for session in &self.sessions { session.payout_terms(stacks)?; }
        Ok([self.sessions[0].bind_payouts(stacks)?,self.sessions[1].bind_payouts(stacks)?])
    }
}
