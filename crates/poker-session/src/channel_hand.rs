//! One owner materialization of a fixed cooperative hand. The channel driver
//! must retain BOTH materializations and complete retirement/disclosure barriers.
use super::*;
use poker_bitcoin::channel::{RetirementLevel, retirement_commitment, retirement_secret};
use poker_settlement::PlannedState;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ChannelMaterialization {
    pub owner: u8,
    pub contest_blocks: u16,
    pub hand_commitment: [u8; 32],
    pub commitments: Vec<[u8; 32]>,
}

impl Session {
    fn fixed_authorization_index(state: &PlannedState) -> Result<Option<usize>> {
        let actor = crate::play::actor(state).ok_or("terminal has no move")?;
        let prefix = match state {
            PlannedState::Reveal { .. } => return Ok(None),
            PlannedState::AliceShowdown { .. } => 49,
            PlannedState::BobTerminal { .. } => 98,
            _ => 0,
        };
        Ok(Some(prefix + usize::from(actor.other().code())))
    }

    pub(super) fn move_authorization_elements(
        &self,
        node: [u8; 32],
        bytes: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        let graph = self.graph()?;
        let state = &graph.node(&node).ok_or("move node absent")?.state;
        let tx: Transaction = deserialize(bytes)?;
        if tx.input.len() != 1 || tx.input[0].witness.len() < 2 {
            return Err("invalid local recovery transaction".into());
        }
        let mut elements: Vec<_> = tx.input[0].witness.iter().map(<[u8]>::to_vec).collect();
        elements.truncate(elements.len() - 2);
        if let Some(index) = Self::fixed_authorization_index(state)? {
            if index >= elements.len() {
                return Err("missing local preauthorization".into());
            }
            elements.remove(index);
        }
        Ok(elements)
    }

    pub(super) fn complete_move_authorization(
        &self,
        edge: u32,
        dynamic: &[Vec<u8>],
    ) -> Result<Vec<u8>> {
        let node = self.current.ok_or("hand not active")?;
        let graph = self.graph()?;
        let state = graph.node(&node).ok_or("move node absent")?;
        let edge = usize::try_from(edge)?;
        if state
            .edges
            .get(edge)
            .ok_or("move edge absent")?
            .timeout
            .is_some()
        {
            return Err("cooperative timeout forbidden".into());
        }
        let template = graph.transition(node, edge, self.tip.ok_or("move parent absent")?)?;
        let program = graph.program(node, edge)?;
        let taproot = graph.state(node)?;
        let leaf = taproot
            .leaf(program.predicate_id())
            .ok_or("move leaf absent")?;
        let mut elements = dynamic.to_vec();
        if let Some(index) = Self::fixed_authorization_index(&state.state)? {
            if index > elements.len() {
                return Err("truncated move authorization".into());
            }
            let (_, signature) = self
                .ready
                .as_ref()
                .ok_or("hand not prepared")?
                .signature(node, edge)?;
            elements.insert(index, signature.to_bytes().to_vec());
        }
        let mut tx = template.transaction().clone();
        tx.input[0].witness = leaf.assemble_witness(&elements)?;
        Ok(serialize(&tx))
    }
    pub(super) fn activation_state(
        &self,
    ) -> Result<(poker_bitcoin::CompiledTaprootState, [u8; 32])> {
        if self.channel_mode.is_some() {
            let graph = self.graph()?;
            let program = poker_bitcoin::LeafProgram::Action(poker_bitcoin::ActionProgram::new(
                graph.plan().chain_game_id,
                graph.plan().root_node_id,
                poker_settlement_types::Action::Check,
                self.terms.identities,
            )?);
            Ok((graph.hand_gate()?, program.predicate_id()))
        } else {
            let state = build_origin_escrow(self.terms.identities)?;
            let id = state.leaves()[0].predicate_id();
            Ok((state, id))
        }
    }

    /// Send only the counterparty signature for the other owner's root. The
    /// owner never exports its own funding signature during cooperative setup.
    pub fn peer_root_signature(&self) -> Result<Vec<u8>> {
        let (owner, _) = self.channel_mode.ok_or("not a channel hand")?;
        if owner == self.role || self.ready.is_none() {
            return Err("cannot release owner's root signature".into());
        }
        let root = self
            .graph()?
            .hand_commitment(self.terms.origin_output()?, self.terms.scaled_fee(500))?;
        let state = build_origin_escrow(self.terms.identities)?;
        let digest = taproot_script_sighash_default(
            root.transaction(),
            0,
            &[self.terms.origin_output()?],
            state.leaves()[0].script(),
        )?;
        Ok(sign_sighash_default(
            &Secp256k1::new(),
            &keypair(derive(&self.seed, b"identity"))?,
            digest,
        )
        .to_bytes()
        .to_vec())
    }

    /// Complete the local root for private recovery storage. Its bytes must not
    /// enter a cooperative message or passive-monitor registration.
    pub fn local_root(&self, peer_signature: &[u8]) -> Result<Vec<u8>> {
        let (owner, _) = self.channel_mode.ok_or("not a channel hand")?;
        if owner != self.role || self.ready.is_none() {
            return Err("not the local root".into());
        }
        let root = self
            .graph()?
            .hand_commitment(self.terms.origin_output()?, self.terms.scaled_fee(500))?;
        let state = build_origin_escrow(self.terms.identities)?;
        let leaf = &state.leaves()[0];
        let digest = taproot_script_sighash_default(
            root.transaction(),
            0,
            &[self.terms.origin_output()?],
            leaf.script(),
        )?;
        poker_bitcoin::verify_sighash_default(
            &Secp256k1::verification_only(),
            self.terms.identities[usize::from(self.role.other().code())],
            digest,
            poker_bitcoin::DefaultSighashSignature::from_slice(peer_signature)?,
        )?;
        let own = sign_sighash_default(
            &Secp256k1::new(),
            &keypair(derive(&self.seed, b"identity"))?,
            digest,
        )
        .to_bytes()
        .to_vec();
        let signatures = if self.role == Role::Alice {
            [own, peer_signature.to_vec()]
        } else {
            [peer_signature.to_vec(), own]
        };
        let mut tx = root.transaction().clone();
        tx.input[0].witness = leaf.assemble_witness(&signatures)?;
        Ok(serialize(&tx))
    }
    /// Create a new protected hand using stable channel signing identities.
    /// Fresh nonce-separated dealer and score entropy prevents reuse across hands.
    pub fn new_channel(
        seed: [u8; 32],
        terms: Terms,
        owner: Role,
        contest_blocks: u16,
    ) -> Result<Self> {
        if !(2..=144).contains(&contest_blocks) {
            return Err("invalid channel contest delay".into());
        }
        Self::new_inner(seed, terms, Some((owner, contest_blocks)))
    }

    pub(super) fn compile_graph(&self) -> Result<Arc<SettlementGraph>> {
        let binding=serde_json::to_vec(&self.terms)?;
        if let Some((original,graph))=self.unprotected_graph_cache.get() {
            if original!=&binding {return Err("terms changed after graph compilation".into());}
            return Ok(Arc::clone(graph));
        }
        let scores = self.scores.as_ref().ok_or("score keys missing")?;
        let graph=Arc::new(SettlementGraph::compile(
            self.dealer.accepted()?,
            self.terms.parameters()?,
            &self.terms.fees()?,
            [scores[0].clone(), scores[1].clone()],
        )?);
        let _=self.unprotected_graph_cache.set((binding,Arc::clone(&graph)));
        Ok(graph)
    }

    fn channel_authors(graph: &SettlementGraph) -> Result<HashMap<[u8; 32], Role>> {
        let mut authors = HashMap::new();
        for node in &graph.plan().nodes {
            for edge in &node.edges {
                let role = if let Some(t) = edge.timeout {
                    t.beneficiary
                } else {
                    match node.state {
                        PlannedState::Betting { state, .. } => state.actor,
                        PlannedState::Reveal { pattern, .. } => pattern.revealer(),
                        PlannedState::AliceShowdown { .. } => Role::Alice,
                        PlannedState::BobTerminal { .. } => Role::Bob,
                        PlannedState::Terminal(_) => return Err("invalid channel topology".into()),
                    }
                };
                authors.insert(edge.child_node_id, role);
            }
        }
        Ok(authors)
    }

    pub(super) fn retirement_secret(
        &self,
        level: RetirementLevel,
        node: [u8; 32],
    ) -> Result<[u8; 32]> {
        let (owner, _) = self.channel_mode.ok_or("not a channel hand")?;
        Ok(retirement_secret(
            &self.seed,
            level,
            self.graph()?.plan().chain_game_id,
            node,
            0,
            owner == Role::Bob,
            self.role == Role::Bob,
        ))
    }

    /// Only locally owned commitments, in independently derived graph order.
    /// No placeholders, node IDs, or retirement secrets cross the relay.
    pub fn channel_commitments(&self) -> Result<Vec<u8>> {
        let (owner, _) = self.channel_mode.ok_or("not a channel hand")?;
        let graph = self.compile_graph()?;
        let authors = Self::channel_authors(&graph)?;
        let mut out = b"CHCOM002".to_vec();
        out.extend(graph.plan().chain_game_id);
        out.extend([owner.code(), self.role.code()]);
        out.extend(u32::try_from(graph.plan().nodes.len())?.to_le_bytes());
        for node in &graph.plan().nodes {
            let root = node.node_id == graph.plan().root_node_id;
            let author = if root {
                owner
            } else {
                *authors.get(&node.node_id).ok_or("missing author")?
            };
            if author == self.role { out.extend(retirement_commitment(retirement_secret(
                    &self.seed,
                    if root {
                        RetirementLevel::Hand
                    } else {
                        RetirementLevel::Branch
                    },
                    graph.plan().chain_game_id,
                    node.node_id,
                    0,
                    owner == Role::Bob,
                    self.role == Role::Bob,
                ))); }
        }
        Ok(out)
    }

    /// Merge exactly the peer-owned slots, then compile and validate the complete
    /// protection inventory before exposing any preparation or root signature.
    pub fn accept_channel_commitments(&mut self, bytes: &[u8]) -> Result<()> {
        if self.preparation.is_some() || self.ready.is_some() {
            return Err("channel already prepared".into());
        }
        let local = self.channel_commitments()?;
        if bytes.len() < 46
            || bytes.get(..41) != local.get(..41)
            || bytes.get(41) != Some(&self.role.other().code())
            || bytes.get(42..46) != local.get(42..46)
        {
            return Err("foreign channel commitment frame".into());
        }
        let graph = self.compile_graph()?;
        let authors = Self::channel_authors(&graph)?;
        let (owner, contest_blocks) = self.channel_mode.ok_or("not a channel hand")?;
        let mut merged = Vec::with_capacity(graph.plan().nodes.len());
        let mut own_at=46;let mut peer_at=46;
        for node in &graph.plan().nodes {
            let author = if node.node_id == graph.plan().root_node_id {
                owner
            } else {
                *authors.get(&node.node_id).ok_or("missing author")?
            };
            let (frame,offset)=if author==self.role {(&local[..],&mut own_at)} else {(bytes,&mut peer_at)};
            let value:[u8;32]=frame.get(*offset..*offset+32).ok_or("truncated commitment frame")?.try_into()?;
            if value==[0;32] {return Err("zero retirement commitment".into());}
            *offset+=32;merged.push(value);
        }
        if own_at!=local.len() || peer_at!=bytes.len() {return Err("extra retirement commitments".into());}
        let profile = ChannelMaterialization {
            owner: owner.code(),
            contest_blocks,
            hand_commitment: merged[0],
            commitments: merged[1..].to_vec(),
        };
        let graph = (*graph).clone().with_channel_protection(
            owner,
            contest_blocks,
            profile.hand_commitment,
            &profile.commitments,
        )?;
        if let Some(existing) = &self.channel_materialization {
            if existing.hand_commitment != profile.hand_commitment
                || existing.commitments != profile.commitments
            {
                return Err("conflicting channel commitments".into());
            }
            return Ok(());
        }
        self.channel_materialization = Some(profile);
        self.graph_cache.take();
        let _ = self
            .graph_cache
            .set((serde_json::to_vec(&self.terms)?, Arc::new(graph)));
        Ok(())
    }

    pub(super) fn wrap_channel_artifact(&self, preparation: Vec<u8>) -> Result<Vec<u8>> {
        let Some(profile) = &self.channel_materialization else {
            return Ok(preparation);
        };
        let mut out = b"CHARTF01".to_vec();
        out.push(profile.owner);
        out.extend(profile.contest_blocks.to_le_bytes());
        out.extend(profile.hand_commitment);
        out.extend(u32::try_from(profile.commitments.len())?.to_le_bytes());
        for hash in &profile.commitments {
            out.extend(hash);
        }
        out.extend(preparation);
        Ok(out)
    }

    pub(super) fn unwrap_channel_artifact(
        bytes: &[u8],
    ) -> Result<(Option<ChannelMaterialization>, &[u8])> {
        if !bytes.starts_with(b"CHARTF01") {
            return Ok((None, bytes));
        }
        if bytes.len() < 47 {
            return Err("truncated channel artifact".into());
        }
        let owner = match bytes[8] {
            0 => Role::Alice,
            1 => Role::Bob,
            _ => return Err("invalid owner".into()),
        };
        let contest_blocks = u16::from_le_bytes(bytes[9..11].try_into()?);
        let hand_commitment = bytes[11..43].try_into()?;
        let count = u32::from_le_bytes(bytes[43..47].try_into()?) as usize;
        if count > 100_000 {
            return Err("channel inventory too large".into());
        }
        let end = 47 + count * 32;
        let commitments = bytes
            .get(47..end)
            .ok_or("truncated channel commitments")?
            .chunks_exact(32)
            .map(|chunk| chunk.try_into().map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;
        Ok((
            Some(ChannelMaterialization {
                owner: owner.code(),
                contest_blocks,
                hand_commitment,
                commitments,
            }),
            bytes.get(end..).ok_or("truncated channel preparation")?,
        ))
    }
}
