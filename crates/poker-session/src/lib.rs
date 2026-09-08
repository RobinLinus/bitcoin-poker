//! One player's on-chain state. Network observations enter through the caller's
//! validated chain adapter; relay messages never advance the confirmed game node.
#![forbid(unsafe_code)]
pub mod buyin;
pub mod channel;
mod channel_hand;
pub mod crypto;
pub mod funding;
mod play;
mod construction;
mod payout_binding;
pub mod retirement;
pub mod rollover;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Transaction, TxOut, Witness,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1, SecretKey},
};
use dealer_protocol::{GameConfig, LiveParticipant};
use poker_bitcoin::{
    ClassFeePolicy, FeePolicy, custom_signet_network_id, sign_sighash_default,
    taproot_script_sighash_default,
};
use poker_score_ots::{
    KeyContext, LamportPublicKey, LamportPurpose, LamportSecretKey, generate_key,
};
use poker_settlement::{
    preparation::{PreparedAuthorizations, SettlementPreparation},
    settlement::{SettlementConfig, SettlementGraph, build_origin_escrow},
};
use poker_settlement_types::{
    PokerRules, RevealOrder, Role, TimeoutSettlementPolicy, root_node_id,
};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};
use zeroize::Zeroizing;
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub const MUTINY_CHALLENGE: &str =
    "512102f7561d208dd9ae99bf497273e16f389bdbd6c4742ddb8e6b216e64fa2928ad8f51ae";

#[derive(Clone, Serialize, Deserialize)]
pub struct Terms {
    #[serde(default)]
    pub slot: Option<channel::ChannelSlot>,
    pub regtest: bool,
    pub identities: [[u8; 32]; 2],
    /// Indexed by revealer, then slot. The opposite role controls each secret.
    pub reveal_keys: [[[u8; 32]; 9]; 2],
    pub origin: String,
    pub origin_value: u64,
    pub nonce: [u8; 32],
    #[serde(default)]
    pub predeal_anchor: Option<[u8; 32]>,
    #[serde(default)]
    pub fee_reserve: Option<u64>,
    pub full: bool,
    pub fee_multiplier: f64,
    pub csv: u16,
    #[serde(default)]
    pub stacks: Option<[u64; 2]>,
    #[serde(default)]
    pub button: Option<u8>,
}
impl Terms {
    pub fn scaled_fee(&self, value: u64) -> u64 { (value as f64 * self.fee_multiplier).ceil() as u64 }
    pub fn network(&self) -> Network {
        if self.regtest {
            Network::Regtest
        } else {
            Network::Signet
        }
    }
    pub fn fees(&self) -> Result<ClassFeePolicy> {
        if !self.fee_multiplier.is_finite() || !(0.1..=10.0).contains(&self.fee_multiplier) {
            return Err("fee multiplier out of range".into());
        }
        let n = |value| self.scaled_fee(value);
        Ok(ClassFeePolicy::new(
            n(500),
            n(700),
            n(11_000),
            n(12_000),
            n(500),
            330,
        )?)
    }
    pub fn parameters(&self) -> Result<SettlementConfig> {
        if self.identities[0] >= self.identities[1] || !(2..=144).contains(&self.csv) {
            return Err("invalid roles or CSV".into());
        }
        let network = self.network();
        let network_id = if self.regtest {
            bitcoin::blockdata::constants::genesis_block(network)
                .block_hash()
                .to_byte_array()
        } else {
            custom_signet_network_id(&ScriptBuf::from_bytes(hex::decode(MUTINY_CHALLENGE)?))
        };
        let stack = if self.full { 20_000 } else { 200 };
        let stacks = self.stacks.unwrap_or([stack; 2]);
        let button = match self.button.unwrap_or(0) {
            0 => Role::Alice,
            1 => Role::Bob,
            _ => return Err("invalid button".into()),
        };
        Ok(SettlementConfig {
            network,
            network_id,
            origin: self.origin.parse()?,
            predeal_anchor: self.predeal_anchor,
            rules: PokerRules {
                button,
                unit_sat: 100,
                max_bets_per_street: 4,
                alice_starting_stack_sat: stacks[0],
                bob_starting_stack_sat: stacks[1],
                fee_reserve_sat: self.fee_reserve.unwrap_or(self.scaled_fee(45_000)),
                action_csv: self.csv,
                reveal_csv: self.csv,
                showdown_csv: self.csv,
                reveal_order: RevealOrder {
                    flop_first: Role::Alice,
                    turn_first: Role::Bob,
                    river_first: Role::Alice,
                },
                timeout_policy: TimeoutSettlementPolicy::PotOnly,
                split_remainder_recipient: Role::Alice,
            },
            fee_policy_id: self.fees()?.policy_id(),
            reveal_keys: self.reveal_keys,
        })
    }
    pub fn origin_output(&self) -> Result<TxOut> {
        Ok(TxOut {
            value: Amount::from_sat(self.origin_value),
            script_pubkey: build_origin_escrow(self.identities)?.script_pubkey(),
        })
    }
}
#[derive(Serialize, Deserialize)]
pub struct PublicKeys {
    pub identity: [u8; 32],
    pub reveal: [[u8; 32]; 9],
}
pub fn derive(seed: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"POKER/session-seed/v1");
    h.update(seed);
    h.update(label);
    h.finalize().into()
}
pub fn keypair(secret: [u8; 32]) -> Result<Keypair> {
    Ok(Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&secret)?,
    ))
}
pub fn public_keys(seed: &[u8; 32]) -> Result<PublicKeys> {
    let mut reveal = [[0; 32]; 9];
    for (i, k) in reveal.iter_mut().enumerate() {
        *k = keypair(derive(seed, &[b'r', i as u8]))?
            .x_only_public_key()
            .0
            .serialize();
    }
    Ok(PublicKeys {
        identity: keypair(derive(seed, b"identity"))?
            .x_only_public_key()
            .0
            .serialize(),
        reveal,
    })
}
#[derive(Clone, Serialize, Deserialize)]
pub enum DealEvent {
    Sent(Vec<u8>),
    Received(Vec<u8>),
    Retry(u32),
}
#[derive(Clone, Serialize, Deserialize)]
pub struct ChainRecord {
    pub transaction: Vec<u8>,
    pub height: u32,
    pub block_hash: String,
}
#[derive(Serialize, Deserialize)]
struct Checkpoint {
    #[serde(default)]
    deferred_payouts: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    channel_mode: Option<(u8, u16)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    channel_materialization: Option<channel_hand::ChannelMaterialization>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    cooperative: Vec<Vec<u8>>,
    version: u32,
    seed: [u8; 32],
    terms: Terms,
    deal_events: Vec<DealEvent>,
    peer_score: Option<Vec<u8>>,
    preparation: Option<Vec<u8>>,
    chain: Vec<ChainRecord>,
    issued_score: Option<u32>,
    pending: Option<Vec<u8>>,
}
/// The caller must encrypt checkpoints before storage and enforce one writer.
pub struct Session {
    deferred_payouts: bool,
    payout_projection: Option<Vec<u8>>,
    channel_mode: Option<(Role, u16)>,
    channel_materialization: Option<channel_hand::ChannelMaterialization>,
    cooperative: Vec<Vec<u8>>,
    seed: Zeroizing<[u8; 32]>,
    pub terms: Terms,
    pub role: Role,
    dealer: Arc<LiveParticipant>,
    graph_cache: OnceLock<(Vec<u8>, Arc<SettlementGraph>)>,
    unprotected_graph_cache: OnceLock<(Vec<u8>, Arc<SettlementGraph>)>,
    events: Vec<DealEvent>,
    score: Option<LamportSecretKey>,
    scores: Option<[LamportPublicKey; 2]>,
    local_score: Option<LamportPublicKey>,
    peer_score: Option<Vec<u8>>,
    preparation: Option<SettlementPreparation>,
    ready: Option<PreparedAuthorizations>,
    sealed: Option<Vec<u8>>,
    current: Option<[u8; 32]>,
    tip: Option<OutPoint>,
    height: u32,
    terminal: bool,
    observed: HashMap<(u8, u8), (u8, k256::Scalar)>,
    public_holes: HashMap<u8, [u8; 2]>,
    alice_certificate: Option<poker_bitcoin::showdown_witness::ObservedAliceScoreCertificate>,
    chain: Vec<ChainRecord>,
    issued_score: Option<u32>,
    issued_certificate: Option<Vec<u8>>,
    pending: Option<Transaction>,
}
impl Session {
    pub fn new(seed: [u8; 32], terms: Terms) -> Result<Self> {
        Self::new_inner(seed, terms, None)
    }
    fn new_inner(seed: [u8; 32], terms: Terms, channel_mode: Option<(Role, u16)>) -> Result<Self> {
        let keys = public_keys(&seed)?;
        let index = terms
            .identities
            .iter()
            .position(|k| *k == keys.identity)
            .ok_or("local identity missing")?;
        if terms.reveal_keys[1 - index] != keys.reveal {
            return Err("local reveal keys misbound".into());
        }
        let p = terms.parameters()?;
        if terms.origin_value
            != p.rules.total_locked_value()?
                + terms.scaled_fee(if channel_mode.is_some() { 1000 } else { 500 })
        {
            return Err("origin value mismatch".into());
        }
        let config = GameConfig {
            network_genesis: bitcoin::blockdata::constants::genesis_block(terms.network())
                .block_hash()
                .to_byte_array(),
            session_anchor: p.session_anchor(),
            identity_a: terms.identities[0],
            identity_b: terms.identities[1],
            session_nonce: terms.nonce,
            rules_hash: p.dealing_rules_hash()?,
        };
        let dealer = LiveParticipant::new(
            config,
            if index == 0 {
                dealer_protocol::Role::A
            } else {
                dealer_protocol::Role::B
            },
            derive(&seed, b"identity"),
            if channel_mode.is_some() {
                derive(&derive(&seed, &terms.nonce), b"channel-deal")
            } else {
                derive(&seed, b"deal")
            },
        )?;
        Ok(Self {
            deferred_payouts: false,
            payout_projection: None,
            channel_mode,
            channel_materialization: None,
            cooperative: vec![],
            seed: Zeroizing::new(seed),
            terms,
            role: if index == 0 { Role::Alice } else { Role::Bob },
            dealer: Arc::new(dealer),
            graph_cache: OnceLock::new(),
            unprotected_graph_cache: OnceLock::new(),
            events: vec![],
            score: None,
            scores: None,
            local_score: None,
            peer_score: None,
            preparation: None,
            ready: None,
            sealed: None,
            current: None,
            tip: None,
            height: 0,
            terminal: false,
            observed: HashMap::new(),
            public_holes: HashMap::new(),
            alice_certificate: None,
            chain: vec![],
            issued_score: None,
            issued_certificate: None,
            pending: None,
        })
    }
    pub fn outgoing(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(Arc::get_mut(&mut self.dealer).ok_or("accepted dealer is immutable")?.prepare_outgoing()?)
    }
    pub fn confirm_outgoing(&mut self, bytes: &[u8]) -> Result<()> {
        Arc::get_mut(&mut self.dealer).ok_or("accepted dealer is immutable")?.confirm_persisted_outgoing(bytes)?;
        self.events.push(DealEvent::Sent(bytes.to_vec()));
        Ok(())
    }
    pub fn accept_peer(&mut self, bytes: &[u8]) -> Result<()> {
        Arc::get_mut(&mut self.dealer).ok_or("accepted dealer is immutable")?.accept_peer(bytes)?;
        self.events.push(DealEvent::Received(bytes.to_vec()));
        Ok(())
    }
    pub fn retry(&mut self, attempt: u32) -> Result<()> {
        Arc::get_mut(&mut self.dealer).ok_or("accepted dealer is immutable")?.start_retry(attempt)?;
        self.events.push(DealEvent::Retry(attempt));
        Ok(())
    }
    pub fn dealer_status(&self) -> serde_json::Value {
        let s = self.dealer.snapshot();
        serde_json::json!({"accepted":s.accepted,"retry":s.retry_required,"attempt":s.attempt,"stage":s.stage})
    }
    /// Adopt final funding and amounts before creating any settlement keys or signatures.
    pub fn bind_predeal(&mut self, mut terms: Terms) -> Result<()> {
        if self.channel_mode.is_some() {terms.initialize_slot()?;}
        if self.terms.predeal_anchor.is_none()
            || self.terms.predeal_anchor != terms.predeal_anchor
            || self.terms.nonce != terms.nonce
            || self.terms.identities != terms.identities
            || self.terms.full != terms.full
            || self.local_score.is_some()
            || self.preparation.is_some()
            || self.ready.is_some()
            || self.pending.is_some()
            || !self.chain.is_empty()
        {
            return Err("predeal cannot be rebound".into());
        }
        let current = self.terms.parameters()?;
        let next = terms.parameters()?;
        if current.session_anchor() != next.session_anchor()
            || current.dealing_rules_hash()? != next.dealing_rules_hash()?
            || terms.origin_value != next.rules.total_locked_value()? + terms.scaled_fee(500) * if self.channel_mode.is_some() { 2 } else { 1 }
        {
            return Err("predeal context changed".into());
        }
        self.terms = terms;
        Ok(())
    }
    pub fn score_public(&mut self) -> Result<Vec<u8>> {
        if let Some(k) = &self.local_score {
            return Ok(k.encode());
        }
        let id = self.terms.parameters()?.chain_id(self.dealer.accepted()?)?;
        let purpose = if self.role == Role::Alice {
            LamportPurpose::AliceScore24Bit
        } else {
            LamportPurpose::BobScore24Bit
        };
        let (secret, public) = generate_key(
            &mut ChaCha20Rng::from_seed(if self.channel_mode.is_some() {
                derive(&derive(&derive(&self.seed, &self.terms.nonce), &id), b"channel-score")
            } else {
                derive(&self.seed, b"score")
            }),
            KeyContext::new(id, root_node_id(&id), purpose),
        )?;
        let out = public.encode();
        self.score = Some(secret);
        self.local_score = Some(public);
        Ok(out)
    }
    pub fn accept_score(&mut self, bytes: &[u8]) -> Result<()> {
        if let Some(old) = &self.peer_score {
            if old != bytes {
                return Err("conflicting score key".into());
            }
            return Ok(());
        }
        let local = LamportPublicKey::decode(&self.score_public()?)?;
        let peer = LamportPublicKey::decode(bytes)?;
        let id = self.terms.parameters()?.chain_id(self.dealer.accepted()?)?;
        let purpose = if self.role == Role::Alice {
            LamportPurpose::BobScore24Bit
        } else {
            LamportPurpose::AliceScore24Bit
        };
        if peer.context() != KeyContext::new(id, root_node_id(&id), purpose) {
            return Err("wrong score context".into());
        }
        self.scores = Some(if self.role == Role::Alice {
            [local, peer]
        } else {
            [peer, local]
        });
        self.peer_score = Some(bytes.to_vec());
        Ok(())
    }
    fn graph(&self) -> Result<Arc<SettlementGraph>> {
        // Terms are public for existing callers. Fail closed if they mutate
        // after compilation rather than serving a graph for stale funding.
        let binding = serde_json::to_vec(&self.terms)?;
        if let Some((original, graph)) = self.graph_cache.get() {
            if original != &binding {
                return Err("terms changed after graph compilation".into());
            }
            return Ok(Arc::clone(graph));
        }
        let mut graph = (*self.compile_graph()?).clone();
        if let Some((owner, contest)) = self.channel_mode {
            let profile = self
                .channel_materialization
                .as_ref()
                .ok_or("channel commitments missing")?;
            if profile.owner != owner.code() || profile.contest_blocks != contest {
                return Err("channel profile mismatch".into());
            }
            graph = graph.with_channel_protection(
                owner,
                contest,
                profile.hand_commitment,
                &profile.commitments,
            )?;
        }
        let graph = Arc::new(graph);
        let _ = self.graph_cache.set((binding, Arc::clone(&graph)));
        Ok(graph)
    }
    pub fn prepare(&mut self) -> Result<()> {
        if self.preparation.is_some() || self.ready.is_some() {
            return Ok(());
        }
        let graph = self.graph()?;
        let activation =
            graph.activation(self.terms.origin_output()?, self.terms.scaled_fee(500))?;
        self.preparation = Some(SettlementPreparation::new(&graph, activation)?);
        Ok(())
    }
    pub fn inventory(&self) -> Result<Vec<u8>> {
        Ok(self
            .preparation
            .as_ref()
            .ok_or("not preparing")?
            .encode_inventory()?)
    }
    pub fn receipt_key(&self) -> [u8; 32] {
        derive(&self.seed, b"receipts")
    }
    pub fn signing_material(&self) -> SigningMaterial {
        SigningMaterial {
            role: self.role.code(),
            identity: derive(&self.seed, b"identity"),
            reveal: std::array::from_fn(|i| derive(&self.seed, &[b'r', i as u8])),
        }
    }
    pub fn accept_batch(&mut self, receipt: &[u8]) -> Result<()> {
        let key = self.receipt_key();
        self.preparation
            .as_mut()
            .ok_or("not preparing")?
            .accept_verified_batch(&key, receipt)?;
        Ok(())
    }
    pub fn finish_preparation(&mut self) -> Result<()> {
        let p = self.preparation.as_ref().ok_or("not preparing")?;
        let sealed = if self.deferred_payouts {p.seal_progress_checkpoint(&self.receipt_key())?}
            else {p.seal_checkpoint(&self.receipt_key())?};
        if self.deferred_payouts {
            if !self.preparation_work()?.is_empty() { return Err("internal authorizations missing".into()); }
            self.sealed = Some(self.wrap_channel_artifact(sealed)?);
        } else {
            let ready = SettlementPreparation::open_checkpoint(
                &self.receipt_key(), &sealed, self.terms.network(),
            )?.into_prepared_authorizations()?;
            self.sealed = Some(self.wrap_channel_artifact(sealed)?);
            self.ready = Some(ready);
            self.preparation = None;
        }
        Ok(())
    }
    pub fn checkpoint(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = self.checkpoint_journal()?;
        if let Some(preparation) = &self.sealed {
            out.extend_from_slice(preparation);
        }
        Ok(out)
    }
    /// Mutable recovery data in the existing framing, without the immutable
    /// preparation suffix. Persist the artifact before a journal referencing it.
    /// Both parts are private and must be authenticated and encrypted at rest.
    pub fn checkpoint_journal(&self) -> Result<Zeroizing<Vec<u8>>> {
        // Pending dealer bytes must be persisted by the transport before confirm_outgoing.
        let metadata = Zeroizing::new(serde_json::to_vec(&Checkpoint {
            deferred_payouts: self.deferred_payouts,
            channel_mode: self.channel_mode.map(|(owner, csv)| (owner.code(), csv)),
            channel_materialization: if self.sealed.is_none() {
                self.channel_materialization.clone()
            } else {
                None
            },
            cooperative: self.cooperative.clone(),
            version: 2,
            seed: *self.seed,
            terms: self.terms.clone(),
            deal_events: self.events.clone(),
            peer_score: self.peer_score.clone(),
            preparation: None,
            chain: self.chain.clone(),
            issued_score: self.issued_score,
            pending: self.pending.as_ref().map(serialize),
        })?);
        let mut out = Zeroizing::new(b"PSESSION2".to_vec());
        out.extend(u32::try_from(metadata.len())?.to_le_bytes());
        out.extend_from_slice(&metadata);
        Ok(out)
    }
    /// Immutable authenticated preparation. Empty until preparation completes.
    pub fn checkpoint_artifact(&self) -> &[u8] {
        self.sealed.as_deref().unwrap_or_default()
    }
    pub fn restore(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 100_000_000 {
            return Err("checkpoint too large".into());
        }
        let c: Checkpoint = if bytes.starts_with(b"PSESSION2") {
            let length =
                u32::from_le_bytes(bytes.get(9..13).ok_or("truncated checkpoint")?.try_into()?)
                    as usize;
            if length > 32_000_000 {
                return Err("checkpoint metadata too large".into());
            }
            let mut c: Checkpoint = serde_json::from_slice(
                bytes
                    .get(13..13 + length)
                    .ok_or("truncated checkpoint metadata")?,
            )?;
            if c.preparation.is_some() || c.version != 2 {
                return Err("invalid checkpoint framing".into());
            }
            let preparation = &bytes[13 + length..];
            if !preparation.is_empty() {
                c.preparation = Some(preparation.to_vec());
            }
            c
        } else {
            serde_json::from_slice(bytes)?
        };
        if c.version != 1 && c.version != 2 {
            return Err("unsupported checkpoint".into());
        }
        let channel_mode = c
            .channel_mode
            .map(|(role, csv)| -> Result<_> {
                let owner = match role {
                    0 => Role::Alice,
                    1 => Role::Bob,
                    _ => return Err("invalid channel owner".into()),
                };
                if !(2..=144).contains(&csv) {
                    return Err("invalid contest delay".into());
                }
                Ok((owner, csv))
            })
            .transpose()?;
        let mut s = Self::new_inner(c.seed, c.terms, channel_mode)?;
        s.channel_materialization = c.channel_materialization;
        s.deferred_payouts = c.deferred_payouts;
        for e in c.deal_events {
            match e {
                DealEvent::Sent(b) => {
                    if s.outgoing()?.as_deref() != Some(&b) {
                        return Err("outgoing replay mismatch".into());
                    }
                    s.confirm_outgoing(&b)?;
                }
                DealEvent::Received(b) => s.accept_peer(&b)?,
                DealEvent::Retry(a) => s.retry(a)?,
            }
        }
        if let Some(k) = c.peer_score {
            s.accept_score(&k)?;
        }
        if let Some(b) = c.preparation {
            let (profile, preparation) = Self::unwrap_channel_artifact(&b)?;
            if profile.is_some() != s.channel_mode.is_some() {
                return Err("recovery channel mode mismatch".into());
            }
            if let Some(profile) = profile {
                s.channel_materialization = Some(profile);
            }
            let p = SettlementPreparation::open_progress_checkpoint(
                &s.receipt_key(),
                preparation,
                s.terms.network(),
            )?;
            if p.missing_count() == 0 && !s.deferred_payouts {
                s.ready = Some(p.into_prepared_authorizations()?);
            } else { s.preparation = Some(p); }
            s.sealed = Some(b);
        }
        for record in c.chain {
            s.observe(record)?;
        }
        for transaction in c.cooperative {
            s.accept_cooperative(&transaction)?;
        }
        s.issued_score = c.issued_score;
        if let Some(score) = c.issued_score {
            s.issue_score(score)?;
        }
        s.pending = c.pending.map(|b| deserialize(&b)).transpose()?;
        Ok(s)
    }
    pub fn activation_signature(&self) -> Result<Vec<u8>> {
        let ready = self.ready.as_ref().ok_or("preparation incomplete")?;
        let (origin, predicate) = self.activation_state()?;
        let leaf = origin.leaf(predicate).ok_or("activation leaf missing")?;
        let digest = taproot_script_sighash_default(
            ready.activation().transaction(),
            0,
            &[ready.activation().parent_output().clone()],
            leaf.script(),
        )?;
        Ok(sign_sighash_default(
            &Secp256k1::new(),
            &keypair(derive(&self.seed, b"identity"))?,
            digest,
        )
        .to_bytes()
        .to_vec())
    }
    pub fn activation(&mut self, peer: &[u8]) -> Result<Vec<u8>> {
        let own = self.activation_signature()?;
        let ready = self.ready.as_ref().ok_or("not ready")?;
        let (origin, predicate) = self.activation_state()?;
        let leaf = origin.leaf(predicate).ok_or("activation leaf missing")?;
        let sigs = if self.role == Role::Alice {
            [own, peer.to_vec()]
        } else {
            [peer.to_vec(), own]
        };
        let mut tx = ready.activation().transaction().clone();
        let digest = taproot_script_sighash_default(
            &tx,
            0,
            &[ready.activation().parent_output().clone()],
            leaf.script(),
        )?;
        for (i, sig) in sigs.iter().enumerate() {
            Secp256k1::verification_only().verify_schnorr(
                &bitcoin::secp256k1::schnorr::Signature::from_slice(sig)?,
                &bitcoin::secp256k1::Message::from_digest(digest),
                &bitcoin::secp256k1::XOnlyPublicKey::from_slice(&self.terms.identities[i])?,
            )?;
        }
        tx.input[0].witness = leaf.assemble_witness(&sigs)?;
        self.pending = Some(tx.clone());
        Ok(serialize(&tx))
    }
}
/// Private capability passed only to this player's local crypto workers.
#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SigningMaterial {
    pub role: u8,
    pub identity: [u8; 32],
    pub reveal: [[u8; 32]; 9],
}
