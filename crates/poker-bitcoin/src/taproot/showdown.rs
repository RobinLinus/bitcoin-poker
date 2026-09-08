//! Showdown programs.
use super::{
    ALICE_SEVEN_SLOTS, BOB_SEVEN_SLOTS, BitcoinBackendError, Builder, HandCategory, KeyContext,
    LamportPublicKey, LamportPurpose, OP_CHECKSIGVERIFY, OP_DUP, OP_ENDIF, OP_FROMALTSTACK,
    OP_GREATERTHAN, OP_GREATERTHANOREQUAL, OP_IF, OP_LESSTHANOREQUAL, OP_NUMEQUAL,
    OP_NUMEQUALVERIFY, OP_SUB, OP_SWAP, OP_TOALTSTACK, OP_VERIFY, ScriptBuf, ShowdownOutcome,
    append_candidate_selector, append_distinct_seven, append_eval5, append_eval5_for_category,
    append_keys, append_length_prefixed, append_score_certificate, append_signature_checks,
    append_subset_selection, root_node_id, validate_authorizers, validate_identifier,
    validate_lamport_context, validate_xonly,
};
use std::sync::Arc;

/// Game-scoped candidate encodings, normalized once from a verified deal.
#[derive(Clone, Debug)]
pub struct PreparedShowdownCards {
    deal_id: [u8; 32],
    keys: Vec<Arc<[[u8; 32]]>>,
}
impl PreparedShowdownCards {
    /// Normalize all 927 candidates once for all showdown programs.
    ///
    /// # Errors
    /// Rejects any degenerate candidate point.
    pub fn new(deal: &dealer_protocol::VerifiedAcceptedDeal) -> Result<Self, BitcoinBackendError> {
        let keys = deal
            .catalogue()
            .keys
            .iter()
            .map(|slot| {
                slot.iter()
                    .map(|key| {
                        dealer_protocol::point_xonly(key).map_err(|_| {
                            BitcoinBackendError::InvalidXOnlyPublicKey {
                                purpose: "dlog candidate",
                            }
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(Arc::from)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            deal_id: dealer_protocol::accepted_body_hash(&deal.as_deal().body),
            keys,
        })
    }
    /// Accepted deal identifier shared by all game scripts.
    #[must_use]
    pub const fn deal_id(&self) -> [u8; 32] {
        self.deal_id
    }
}

/// Complete public inputs to Alice's showdown predicate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliceShowdownProgram {
    pub(super) chain_game_id: [u8; 32],
    pub(super) node_id: [u8; 32],
    openings: ShowdownOpenings,
    script: Arc<ScriptBuf>,
    pub(super) script_hash: [u8; 32],
    pub(super) score_public_key: LamportPublicKey,
    pub(super) authorizers: [[u8; 32]; 2],
    pub(super) claimed_category: Option<HandCategory>,
}

impl AliceShowdownProgram {
    /// Construct the dlog predicate from a replay-verified candidate catalogue.
    /// Each of seven cards is authenticated under this transaction's sighash.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn new(
        deal: &dealer_protocol::VerifiedAcceptedDeal,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        score_public_key: LamportPublicKey,
        authorizers: [[u8; 32]; 2],
    ) -> Result<Self, BitcoinBackendError> {
        Self::from_prepared(
            &PreparedShowdownCards::new(deal)?,
            chain_game_id,
            node_id,
            score_public_key,
            authorizers,
        )
    }

    /// Construct using game-scoped candidate encodings.
    ///
    /// # Errors
    /// Rejects invalid node, identity, or score-key contexts.
    pub fn from_prepared(
        cards: &PreparedShowdownCards,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        score_public_key: LamportPublicKey,
        authorizers: [[u8; 32]; 2],
    ) -> Result<Self, BitcoinBackendError> {
        Self::new_inner(
            ShowdownOpenings::from_prepared(cards, ALICE_SEVEN_SLOTS),
            chain_game_id,
            node_id,
            score_public_key,
            authorizers,
            None,
        )
    }

    fn new_inner(
        openings: ShowdownOpenings,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        score_public_key: LamportPublicKey,
        authorizers: [[u8; 32]; 2],
        claimed_category: Option<HandCategory>,
    ) -> Result<Self, BitcoinBackendError> {
        validate_identifier(chain_game_id, "Alice showdown chain game id")?;
        validate_identifier(node_id, "Alice showdown node id")?;
        validate_lamport_context(
            score_public_key.context(),
            KeyContext::new(
                chain_game_id,
                root_node_id(&chain_game_id),
                LamportPurpose::AliceScore24Bit,
            ),
        )?;
        validate_authorizers(&authorizers)?;
        let mut program = Self {
            chain_game_id,
            node_id,
            openings,
            script: Arc::new(ScriptBuf::new()),
            script_hash: [0; 32],
            score_public_key,
            authorizers,
            claimed_category,
        };
        program.script = Arc::new(program.build_tapscript());
        super::validate_script_size(&program.script)?;
        program.script_hash = super::tapleaf_hash(&program.script);
        Ok(program)
    }

    /// Bind a validated game template to one logical node.
    ///
    /// # Errors
    /// Rejects a zero node identifier.
    pub fn at_node(&self, node_id: [u8; 32]) -> Result<Self, BitcoinBackendError> {
        validate_identifier(node_id, "Alice showdown node id")?;
        let mut program = self.clone();
        program.node_id = node_id;
        Ok(program)
    }

    /// Category proved by this individual Taproot leaf.
    #[must_use]
    pub const fn claimed_category(&self) -> Option<HandCategory> {
        self.claimed_category
    }

    pub(super) fn encode_into(&self, encoded: &mut Vec<u8>) {
        encoded.push(3);
        encoded.extend_from_slice(&self.chain_game_id);
        encoded.extend_from_slice(&self.node_id);
        append_keys(encoded, &self.authorizers);
        self.openings.encode_into(encoded);
        append_length_prefixed(encoded, &self.score_public_key.encode());
        encoded.push(match self.claimed_category {
            Some(category) => category.as_u8(),
            None => u8::MAX,
        });
    }

    pub(super) fn to_tapscript(&self) -> ScriptBuf {
        self.script.as_ref().clone()
    }

    fn build_tapscript(&self) -> ScriptBuf {
        let builder = Builder::new();
        let builder = self.openings.append_to(builder);
        let builder = append_subset_selection(builder);
        let builder = match self.claimed_category {
            Some(category) => append_eval5_for_category(builder, category),
            None => append_eval5(builder),
        }
        .push_opcode(OP_TOALTSTACK);
        let builder = append_signature_checks(builder, &self.authorizers);
        append_score_certificate(builder, &self.score_public_key)
            .push_opcode(OP_FROMALTSTACK)
            .push_opcode(OP_NUMEQUAL)
            .into_script()
    }
}

/// Complete public inputs to one branch-specific Bob terminal predicate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BobPayoutProgram {
    pub(super) chain_game_id: [u8; 32],
    pub(super) node_id: [u8; 32],
    pub(super) alice_showdown_node_id: [u8; 32],
    pub(super) outcome: ShowdownOutcome,
    openings: ShowdownOpenings,
    script: Arc<ScriptBuf>,
    pub(super) script_hash: [u8; 32],
    pub(super) alice_score_public_key: LamportPublicKey,
    pub(super) bob_score_public_key: LamportPublicKey,
    pub(super) alice_authorizer: [u8; 32],
    pub(super) bob_live_key: [u8; 32],
    pub(super) claimed_category: Option<HandCategory>,
}

impl BobPayoutProgram {
    /// Construct a dlog payout, repeating candidate authentication of Bob's
    /// cards and authenticating both score certificates before comparison.
    #[allow(clippy::too_many_arguments)]
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn new(
        deal: &dealer_protocol::VerifiedAcceptedDeal,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        alice_showdown_node_id: [u8; 32],
        outcome: ShowdownOutcome,
        alice_score_public_key: LamportPublicKey,
        bob_score_public_key: LamportPublicKey,
        terminal_authorizers: [[u8; 32]; 2],
    ) -> Result<Self, BitcoinBackendError> {
        Self::from_prepared(
            &PreparedShowdownCards::new(deal)?,
            chain_game_id,
            node_id,
            alice_showdown_node_id,
            outcome,
            alice_score_public_key,
            bob_score_public_key,
            terminal_authorizers,
        )
    }

    /// Construct using game-scoped candidate encodings.
    ///
    /// # Errors
    /// Rejects invalid node, identity, or score-key contexts.
    #[allow(clippy::too_many_arguments)]
    pub fn from_prepared(
        cards: &PreparedShowdownCards,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        alice_showdown_node_id: [u8; 32],
        outcome: ShowdownOutcome,
        alice_score_public_key: LamportPublicKey,
        bob_score_public_key: LamportPublicKey,
        terminal_authorizers: [[u8; 32]; 2],
    ) -> Result<Self, BitcoinBackendError> {
        Self::new_inner(
            ShowdownOpenings::from_prepared(cards, BOB_SEVEN_SLOTS),
            chain_game_id,
            node_id,
            alice_showdown_node_id,
            outcome,
            alice_score_public_key,
            bob_score_public_key,
            terminal_authorizers,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        openings: ShowdownOpenings,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        alice_showdown_node_id: [u8; 32],
        outcome: ShowdownOutcome,
        alice_score_public_key: LamportPublicKey,
        bob_score_public_key: LamportPublicKey,
        terminal_authorizers: [[u8; 32]; 2],
        claimed_category: Option<HandCategory>,
    ) -> Result<Self, BitcoinBackendError> {
        validate_identifier(chain_game_id, "Bob payout chain game id")?;
        validate_identifier(node_id, "Bob payout node id")?;
        validate_identifier(alice_showdown_node_id, "preceding Alice showdown node id")?;
        validate_xonly(terminal_authorizers[0], "Alice terminal preauthorization")?;
        validate_xonly(terminal_authorizers[1], "Bob live terminal authorization")?;
        validate_lamport_context(
            alice_score_public_key.context(),
            KeyContext::new(
                chain_game_id,
                root_node_id(&chain_game_id),
                LamportPurpose::AliceScore24Bit,
            ),
        )?;
        validate_lamport_context(
            bob_score_public_key.context(),
            KeyContext::new(
                chain_game_id,
                root_node_id(&chain_game_id),
                LamportPurpose::BobScore24Bit,
            ),
        )?;
        let mut program = Self {
            chain_game_id,
            node_id,
            alice_showdown_node_id,
            outcome,
            openings,
            script: Arc::new(ScriptBuf::new()),
            script_hash: [0; 32],
            alice_score_public_key,
            bob_score_public_key,
            alice_authorizer: terminal_authorizers[0],
            bob_live_key: terminal_authorizers[1],
            claimed_category,
        };
        program.script = Arc::new(program.build_tapscript());
        super::validate_script_size(&program.script)?;
        program.script_hash = super::tapleaf_hash(&program.script);
        Ok(program)
    }

    /// Bind a validated game/outcome template to its two logical nodes.
    ///
    /// # Errors
    /// Rejects zero node identifiers.
    pub fn at_node(
        &self,
        node_id: [u8; 32],
        alice_node_id: [u8; 32],
    ) -> Result<Self, BitcoinBackendError> {
        validate_identifier(node_id, "Bob payout node id")?;
        validate_identifier(alice_node_id, "preceding Alice showdown node id")?;
        let mut program = self.clone();
        program.node_id = node_id;
        program.alice_showdown_node_id = alice_node_id;
        Ok(program)
    }

    /// Category proved by this individual Taproot leaf.
    #[must_use]
    pub const fn claimed_category(&self) -> Option<HandCategory> {
        self.claimed_category
    }

    pub(super) fn encode_into(&self, encoded: &mut Vec<u8>) {
        encoded.push(4);
        encoded.extend_from_slice(&self.chain_game_id);
        encoded.extend_from_slice(&self.node_id);
        encoded.extend_from_slice(&self.alice_showdown_node_id);
        encoded.push(self.outcome.code());
        encoded.extend_from_slice(&self.alice_authorizer);
        encoded.extend_from_slice(&self.bob_live_key);
        self.openings.encode_into(encoded);
        append_length_prefixed(encoded, &self.alice_score_public_key.encode());
        append_length_prefixed(encoded, &self.bob_score_public_key.encode());
        encoded.push(match self.claimed_category {
            Some(category) => category.as_u8(),
            None => u8::MAX,
        });
    }

    pub(super) fn to_tapscript(&self) -> ScriptBuf {
        self.script.as_ref().clone()
    }

    fn build_tapscript(&self) -> ScriptBuf {
        let builder = Builder::new();
        let builder = self.openings.append_to(builder);
        let builder = append_subset_selection(builder);
        let builder = match self.claimed_category {
            Some(category) => append_eval5_for_category(builder, category),
            None => append_eval5(builder),
        }
        .push_opcode(OP_TOALTSTACK);
        let builder = append_signature_checks(builder, &[self.alice_authorizer, self.bob_live_key]);

        // Bob's score certificate is directly beneath the two transaction
        // signatures. Authenticate it, require equality with the evaluator,
        // then preserve score_B for the final comparison with score_A.
        let builder = append_score_certificate(builder, &self.bob_score_public_key)
            .push_opcode(OP_FROMALTSTACK)
            .push_opcode(OP_DUP)
            .push_opcode(OP_TOALTSTACK)
            .push_opcode(OP_NUMEQUALVERIFY);
        let builder = append_score_certificate(builder, &self.alice_score_public_key)
            .push_opcode(OP_FROMALTSTACK);
        let builder = match self.outcome {
            // Stack is `score_a score_b`.
            ShowdownOutcome::AliceWin => builder.push_opcode(OP_GREATERTHAN),
            ShowdownOutcome::BobWin => builder.push_opcode(OP_SWAP).push_opcode(OP_GREATERTHAN),
            ShowdownOutcome::Split => builder.push_opcode(OP_NUMEQUAL),
        };
        builder.into_script()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ShowdownOpenings {
    pub(super) deal_id: [u8; 32],
    pub(super) keys: Vec<Arc<[[u8; 32]]>>,
}

impl ShowdownOpenings {
    fn from_prepared(cards: &PreparedShowdownCards, slots: [u8; 7]) -> Self {
        Self {
            deal_id: cards.deal_id,
            keys: slots
                .iter()
                .map(|&slot| Arc::clone(&cards.keys[usize::from(slot)]))
                .collect(),
        }
    }

    pub(super) fn encode_into(&self, encoded: &mut Vec<u8>) {
        encoded.push(255);
        encoded.extend_from_slice(&self.deal_id);
        for slot in &self.keys {
            for key in slot.iter() {
                encoded.extend_from_slice(key);
            }
        }
    }

    pub(super) fn append_to(&self, mut builder: Builder) -> Builder {
        let Self { keys, .. } = self;
        // Pair order: signature, raw sum. The last slot is at the stack top.
        for candidates in keys.iter().rev() {
            builder = builder
                .push_opcode(OP_DUP)
                .push_int(0)
                .push_opcode(OP_GREATERTHANOREQUAL)
                .push_opcode(OP_VERIFY)
                .push_opcode(OP_DUP)
                .push_int(102)
                .push_opcode(OP_LESSTHANOREQUAL)
                .push_opcode(OP_VERIFY)
                .push_opcode(OP_DUP)
                .push_opcode(OP_DUP)
                .push_int(52)
                .push_opcode(OP_GREATERTHANOREQUAL)
                .push_opcode(OP_IF)
                .push_int(52)
                .push_opcode(OP_SUB)
                .push_opcode(OP_ENDIF)
                .push_opcode(OP_TOALTSTACK);
            builder =
                append_candidate_selector(builder, candidates, 0).push_opcode(OP_CHECKSIGVERIFY);
        }
        for _ in 0..7 {
            builder = builder.push_opcode(OP_FROMALTSTACK);
        }
        append_distinct_seven(builder)
    }
}
