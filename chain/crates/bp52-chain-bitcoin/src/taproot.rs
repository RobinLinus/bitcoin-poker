//! Deterministic Taproot programs for fixed BP52 state transitions.
//!
//! Every emitted leaf implements its complete consensus predicate. Program
//! construction fails closed if a script exceeds the bounded v1 profile.

use std::collections::HashSet;

use bitcoin::blockdata::opcodes::all::{
    OP_ADD, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV, OP_DROP, OP_DUP, OP_ELSE, OP_ENDIF,
    OP_EQUALVERIFY, OP_FROMALTSTACK, OP_GREATERTHAN, OP_GREATERTHANOREQUAL, OP_IF, OP_LESSTHAN,
    OP_LESSTHANOREQUAL, OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_PICK, OP_RETURN,
    OP_SHA256, OP_SIZE, OP_SUB, OP_SWAP, OP_TOALTSTACK, OP_VERIFY,
};
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::Hash;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::secp256k1::{Secp256k1, Verification, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{ScriptBuf, Witness};
/// NUMS internal key shared by script-only state outputs.
pub const SCRIPT_PATH_NUMS_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];
use bp52_chain_types::{Action, ShowdownOutcome, root_node_id};
use bp52_lamport::{
    AliceScoreCertificate, BobScoreCertificate, KeyContext, LamportMessage, LamportPublicKey,
    LamportPurpose, LamportSignature, Score24,
};
use bp52_poker::{HandCategory, SUBSETS_5_OF_7};
use sha2::{Digest, Sha256};

use crate::eval5_script::{
    EVAL5_PROOF_ELEMENTS, append_eval5, append_eval5_for_category, encode_script_num,
};
use crate::{ALICE_SEVEN_SLOTS, BOB_SEVEN_SLOTS, BitcoinBackendError, DefaultSighashSignature};

/// Dlog profile script-size bound; tapscript has no consensus 10,000-byte limit.
pub const MAX_CONSENSUS_SCRIPT_BYTES: usize = 65_536;
/// Consensus maximum ordinary witness stack-element size.
pub const MAX_WITNESS_ELEMENT_BYTES: usize = 520;
/// Defensive maximum executable leaves for one v1 state (plus one hidden commitment leaf).
pub const MAX_TAPROOT_LEAVES: usize = 32;
/// Every category-specific showdown leaf, weakest to strongest.
pub const SHOWDOWN_CATEGORIES: [HandCategory; 9] = [
    HandCategory::HighCard,
    HandCategory::OnePair,
    HandCategory::TwoPair,
    HandCategory::ThreeOfAKind,
    HandCategory::Straight,
    HandCategory::Flush,
    HandCategory::FullHouse,
    HandCategory::FourOfAKind,
    HandCategory::StraightFlush,
];
// The semantic domain and program-codec bump prevent predicate IDs from
// aliasing superseded executable scripts.
const PREDICATE_TAG: &[u8] = b"BP52/chain-predicate/v6/lower-bound-hand-claims";
const PROGRAM_MAGIC: &[u8; 8] = b"BP52BSP7";
const STATE_COMMITMENT_MAGIC: &[u8; 7] = b"BP52SC1";

/// Deterministic semantic program for one Taproot leaf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LeafProgram {
    /// Opponent presignature plus the acting player's live Bitcoin signature.
    Action(ActionProgram),
    /// Reusable dlog adaptor openings plus the revealer live signature.
    DlogReveal(DlogRevealProgram),
    /// Opponent preauthorization plus beneficiary live signature after CSV.
    Timeout(TimeoutProgram),
    /// Alice openings, one category-specific lower-bound proof, and score certificate.
    AliceShowdown(AliceShowdownProgram),
    /// Bob openings, one category proof, both score certificates, comparison, and signature.
    BobPayout(BobPayoutProgram),
}

impl LeafProgram {
    /// Return the claimed category for a specialized showdown leaf.
    #[must_use]
    pub const fn showdown_category(&self) -> Option<HandCategory> {
        match self {
            Self::AliceShowdown(program) => program.claimed_category(),
            Self::BobPayout(program) => program.claimed_category(),
            Self::Action(_) | Self::DlogReveal(_) | Self::Timeout(_) => None,
        }
    }

    /// Return Bob's payout outcome for a showdown leaf.
    #[must_use]
    pub const fn showdown_outcome(&self) -> Option<ShowdownOutcome> {
        match self {
            Self::BobPayout(program) => Some(program.outcome),
            Self::Action(_) | Self::DlogReveal(_) | Self::Timeout(_) | Self::AliceShowdown(_) => {
                None
            }
        }
    }
    /// Return the complete canonical semantic program encoding.
    #[must_use]
    pub fn encode_program(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(PROGRAM_MAGIC);
        match self {
            Self::Action(program) => program.encode_into(&mut encoded),
            Self::DlogReveal(program) => {
                encoded.push(5);
                encoded.extend_from_slice(program.script.as_bytes());
            }
            Self::Timeout(program) => program.encode_into(&mut encoded),
            Self::AliceShowdown(program) => program.encode_into(&mut encoded),
            Self::BobPayout(program) => program.encode_into(&mut encoded),
        }
        encoded
    }

    /// Return a tagged identifier binding every public predicate parameter.
    #[must_use]
    pub fn predicate_id(&self) -> [u8; 32] {
        tagged_sha256(PREDICATE_TAG, &self.encode_program())
    }

    /// Return the exact number of ordinary witness elements.
    ///
    /// # Errors
    ///
    /// Returns an error only if a future program variant is unsupported.
    pub fn expected_witness_elements(&self) -> Result<usize, BitcoinBackendError> {
        match self {
            Self::Action(_) | Self::Timeout(_) => Ok(2),
            Self::DlogReveal(program) => Ok(program.elements),
            Self::AliceShowdown(_) => Ok(ALICE_SHOWDOWN_WITNESS_ELEMENTS),
            Self::BobPayout(_) => Ok(BOB_PAYOUT_WITNESS_ELEMENTS),
        }
    }

    /// Compile reviewed predicate classes to executable tapscript.
    ///
    /// # Errors
    ///
    /// Rejects scripts over the selected profile's size limit. It never emits a
    /// weakened or placeholder spend.
    pub fn to_tapscript(&self) -> Result<ScriptBuf, BitcoinBackendError> {
        let script = match self {
            Self::Action(program) => program.to_tapscript(),
            Self::DlogReveal(program) => program.script.clone(),
            Self::Timeout(program) => program.to_tapscript(),
            Self::AliceShowdown(program) => program.to_tapscript(),
            Self::BobPayout(program) => program.to_tapscript(),
        };
        let dlog = match self {
            Self::AliceShowdown(p) => p.openings.is_dlog(),
            Self::BobPayout(p) => p.openings.is_dlog(),
            _ => false,
        };
        if dlog {
            if script.len() > 65_536 {
                return Err(BitcoinBackendError::OversizedConsensusScript {
                    actual: script.len(),
                    maximum: 65_536,
                });
            }
        } else {
            validate_script_size(&script)?;
        }
        Ok(script)
    }
}

/// Specialized action authorization program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionProgram {
    chain_game_id: [u8; 32],
    node_id: [u8; 32],
    action: Action,
    authorizers: [[u8; 32]; 2],
}

impl ActionProgram {
    /// Bind one action branch to its exact game/node and both identity keys.
    ///
    /// The opponent distributes their transaction-specific signature in
    /// advance. The acting player selects this branch by supplying their own
    /// live signature. Both signatures remain in canonical Alice/Bob witness
    /// order regardless of which player acts.
    ///
    /// # Errors
    ///
    /// Rejects zero game/node identifiers and malformed x-only authorizer keys.
    pub fn new(
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        action: Action,
        authorizers: [[u8; 32]; 2],
    ) -> Result<Self, BitcoinBackendError> {
        validate_identifier(chain_game_id, "action chain game id")?;
        validate_identifier(node_id, "action node id")?;
        validate_authorizers(&authorizers)?;
        Ok(Self {
            chain_game_id,
            node_id,
            action,
            authorizers,
        })
    }

    fn encode_into(&self, encoded: &mut Vec<u8>) {
        encoded.push(0);
        encoded.extend_from_slice(&self.chain_game_id);
        encoded.extend_from_slice(&self.node_id);
        encoded.push(self.action.code());
        append_keys(encoded, &self.authorizers);
    }

    fn to_tapscript(&self) -> ScriptBuf {
        let builder = Builder::new()
            .push_int(i64::from(self.action.code()))
            .push_opcode(OP_DROP);
        append_terminal_signature_checks(builder, &self.authorizers).into_script()
    }
}

/// Exact candidate-adaptor checks for one on-chain dlog reveal obligation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DlogRevealProgram {
    script: ScriptBuf,
    elements: usize,
}
impl DlogRevealProgram {
    /// Bind the accepted deal, node, actor, and distinct per-slot authorizers.
    pub fn new(
        deal_id: [u8; 32],
        node_id: [u8; 32],
        actor: [u8; 32],
        slots: &[(u8, [u8; 32])],
    ) -> Result<Self, BitcoinBackendError> {
        let script = dlog52_bitcoin::reveal::reveal_tapscript(deal_id, node_id, actor, slots)
            .map_err(|_| BitcoinBackendError::InvalidBitcoinSignature)?;
        Ok(Self {
            script,
            elements: 1 + slots.len(),
        })
    }
}

/// Both canonical player signatures gated by a block-height CSV delay.
///
/// The opponent supplies an exact-transaction preauthorization before play;
/// the beneficiary supplies their signature after maturity. Consensus sees
/// both signatures in canonical Alice/Bob order, independent of timing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeoutProgram {
    chain_game_id: [u8; 32],
    node_id: [u8; 32],
    csv: u16,
    authorizers: [[u8; 32]; 2],
}

impl TimeoutProgram {
    /// Construct a nonzero block-height timeout program.
    ///
    /// # Errors
    ///
    /// `authorizers` must be ordered as Alice then Bob.
    ///
    /// Rejects a zero delay or either malformed x-only identity key.
    pub fn new(
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        csv: u16,
        authorizers: [[u8; 32]; 2],
    ) -> Result<Self, BitcoinBackendError> {
        validate_identifier(chain_game_id, "timeout chain game id")?;
        validate_identifier(node_id, "timeout node id")?;
        if csv == 0 {
            return Err(BitcoinBackendError::InvalidTransactionTemplate {
                reason: "timeout CSV must be nonzero",
            });
        }
        validate_authorizers(&authorizers)?;
        Ok(Self {
            chain_game_id,
            node_id,
            csv,
            authorizers,
        })
    }

    /// Return the exact BIP68 block delay.
    #[must_use]
    pub const fn csv(&self) -> u16 {
        self.csv
    }

    fn encode_into(&self, encoded: &mut Vec<u8>) {
        encoded.push(2);
        encoded.extend_from_slice(&self.chain_game_id);
        encoded.extend_from_slice(&self.node_id);
        encoded.extend_from_slice(&self.csv.to_le_bytes());
        append_keys(encoded, &self.authorizers);
    }

    fn to_tapscript(&self) -> ScriptBuf {
        let builder = Builder::new()
            .push_int(i64::from(self.csv))
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP);
        append_terminal_signature_checks(builder, &self.authorizers).into_script()
    }
}

/// Complete public inputs to Alice's showdown predicate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AliceShowdownProgram {
    chain_game_id: [u8; 32],
    node_id: [u8; 32],
    openings: ShowdownOpenings,
    score_public_key: LamportPublicKey,
    authorizers: [[u8; 32]; 2],
    claimed_category: Option<HandCategory>,
}

impl AliceShowdownProgram {
    /// Construct the dlog predicate from a replay-verified candidate catalogue.
    /// Each of seven cards is authenticated under this transaction's sighash.
    pub fn new_dlog(
        deal: &dlog52_protocol::VerifiedAcceptedDeal,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        score_public_key: LamportPublicKey,
        authorizers: [[u8; 32]; 2],
    ) -> Result<Self, BitcoinBackendError> {
        Self::new_inner(
            ShowdownOpenings::dlog(deal, &ALICE_SEVEN_SLOTS)?,
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
        Ok(Self {
            chain_game_id,
            node_id,
            openings,
            score_public_key,
            authorizers,
            claimed_category,
        })
    }

    /// Category proved by this individual Taproot leaf.
    #[must_use]
    pub const fn claimed_category(&self) -> Option<HandCategory> {
        self.claimed_category
    }

    fn encode_into(&self, encoded: &mut Vec<u8>) {
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

    fn to_tapscript(&self) -> ScriptBuf {
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
    chain_game_id: [u8; 32],
    node_id: [u8; 32],
    alice_showdown_node_id: [u8; 32],
    outcome: ShowdownOutcome,
    openings: ShowdownOpenings,
    alice_score_public_key: LamportPublicKey,
    bob_score_public_key: LamportPublicKey,
    alice_authorizer: [u8; 32],
    bob_live_key: [u8; 32],
    claimed_category: Option<HandCategory>,
}

impl BobPayoutProgram {
    /// Construct a dlog payout, repeating candidate authentication of Bob's
    /// cards and authenticating both score certificates before comparison.
    #[allow(clippy::too_many_arguments)]
    pub fn new_dlog(
        deal: &dlog52_protocol::VerifiedAcceptedDeal,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        alice_showdown_node_id: [u8; 32],
        outcome: ShowdownOutcome,
        alice_score_public_key: LamportPublicKey,
        bob_score_public_key: LamportPublicKey,
        terminal_authorizers: [[u8; 32]; 2],
    ) -> Result<Self, BitcoinBackendError> {
        Self::new_inner(
            ShowdownOpenings::dlog(deal, &BOB_SEVEN_SLOTS)?,
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
        Ok(Self {
            chain_game_id,
            node_id,
            alice_showdown_node_id,
            outcome,
            openings,
            alice_score_public_key,
            bob_score_public_key,
            alice_authorizer: terminal_authorizers[0],
            bob_live_key: terminal_authorizers[1],
            claimed_category,
        })
    }

    /// Category proved by this individual Taproot leaf.
    #[must_use]
    pub const fn claimed_category(&self) -> Option<HandCategory> {
        self.claimed_category
    }

    fn encode_into(&self, encoded: &mut Vec<u8>) {
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

    fn to_tapscript(&self) -> ScriptBuf {
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

/// One compiled leaf and its deterministic control block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledTapLeaf {
    predicate_id: [u8; 32],
    script: ScriptBuf,
    control_block: Vec<u8>,
    expected_witness_elements: usize,
    showdown_category: Option<HandCategory>,
    showdown_outcome: Option<ShowdownOutcome>,
}

impl CompiledTapLeaf {
    /// Return the semantic predicate identifier.
    #[must_use]
    pub const fn predicate_id(&self) -> [u8; 32] {
        self.predicate_id
    }

    /// Return the exact tapscript.
    #[must_use]
    pub const fn script(&self) -> &ScriptBuf {
        &self.script
    }

    /// Return the serialized BIP341 control block.
    #[must_use]
    pub fn control_block(&self) -> &[u8] {
        &self.control_block
    }

    /// Return the exact count before script and control-block elements.
    #[must_use]
    pub const fn expected_witness_elements(&self) -> usize {
        self.expected_witness_elements
    }

    /// Category selected by this showdown leaf, if it is a showdown leaf.
    #[must_use]
    pub const fn showdown_category(&self) -> Option<HandCategory> {
        self.showdown_category
    }

    /// Bob payout branch associated with this leaf, if any.
    #[must_use]
    pub const fn showdown_outcome(&self) -> Option<ShowdownOutcome> {
        self.showdown_outcome
    }

    /// Assemble a strictly sized script-path witness.
    ///
    /// `elements` are supplied in Bitcoin's bottom-to-top stack order. Action
    /// and timeout leaves use `[alice_signature, bob_signature]`. Dlog reveal
    /// and showdown callers should use their typed witness builders to preserve
    /// the required signature, score-bit, and evaluator-proof ordering.
    ///
    /// # Errors
    ///
    /// Rejects the wrong number of elements or an element larger than 520 bytes.
    pub fn assemble_witness(&self, elements: &[Vec<u8>]) -> Result<Witness, BitcoinBackendError> {
        if elements.len() != self.expected_witness_elements {
            return Err(BitcoinBackendError::WrongWitnessElementCount {
                expected: self.expected_witness_elements,
                actual: elements.len(),
            });
        }
        if let Some(actual) = elements
            .iter()
            .map(Vec::len)
            .find(|length| *length > MAX_WITNESS_ELEMENT_BYTES)
        {
            return Err(BitcoinBackendError::OversizedWitnessElement {
                actual,
                maximum: MAX_WITNESS_ELEMENT_BYTES,
            });
        }
        let mut witness = Witness::new();
        for element in elements {
            witness.push(element);
        }
        witness.push(self.script.as_bytes());
        witness.push(&self.control_block);
        Ok(witness)
    }
}

/// Deterministically compiled script-only Taproot state output.
#[derive(Clone, Debug)]
pub struct CompiledTaprootState {
    spend_info: TaprootSpendInfo,
    leaves: Vec<CompiledTapLeaf>,
    logical_state_digest: [u8; 32],
}

impl CompiledTaprootState {
    /// Compile all executable programs plus one hidden state-commitment leaf
    /// under the BIP341 NUMS internal key.
    ///
    /// # Errors
    ///
    /// Rejects empty, duplicate, oversized, too-large, unsupported, or
    /// otherwise unconstructable trees.
    pub fn compile<C: Verification>(
        secp: &Secp256k1<C>,
        logical_state_digest: [u8; 32],
        programs: &[LeafProgram],
    ) -> Result<Self, BitcoinBackendError> {
        if programs.is_empty() {
            return Err(BitcoinBackendError::EmptyTaprootTree);
        }
        if programs.len() > MAX_TAPROOT_LEAVES {
            return Err(BitcoinBackendError::TooManyTaprootLeaves {
                actual: programs.len(),
                maximum: MAX_TAPROOT_LEAVES,
            });
        }

        let mut compiled = Vec::with_capacity(programs.len());
        let mut ids = HashSet::with_capacity(programs.len());
        for program in programs {
            let predicate_id = program.predicate_id();
            if !ids.insert(predicate_id) {
                return Err(BitcoinBackendError::DuplicatePredicateId);
            }
            compiled.push((
                predicate_id,
                program.to_tapscript()?,
                program.expected_witness_elements()?,
                program.showdown_category(),
                program.showdown_outcome(),
            ));
        }
        compiled.sort_unstable_by_key(|(predicate_id, _, _, _, _)| *predicate_id);

        let commitment_script = state_commitment_script(logical_state_digest);
        let mut tree_scripts = compiled
            .iter()
            .map(|(_, script, _, _, _)| (EXECUTABLE_LEAF_WEIGHT, script.clone()))
            .collect::<Vec<_>>();
        tree_scripts.push((COMMITMENT_LEAF_WEIGHT, commitment_script));
        tree_scripts.sort_unstable_by(|(_, left), (_, right)| {
            TapLeafHash::from_script(left, LeafVersion::TapScript)
                .to_byte_array()
                .cmp(&TapLeafHash::from_script(right, LeafVersion::TapScript).to_byte_array())
                .then_with(|| left.as_bytes().cmp(right.as_bytes()))
        });
        let builder = TaprootBuilder::with_huffman_tree(tree_scripts)
            .map_err(|_| BitcoinBackendError::TaprootConstruction)?;
        let internal_key = UntweakedPublicKey::from_slice(&SCRIPT_PATH_NUMS_KEY)
            .map_err(|_| BitcoinBackendError::TaprootConstruction)?;
        let spend_info = builder
            .finalize(secp, internal_key)
            .map_err(|_| BitcoinBackendError::TaprootConstruction)?;

        let mut leaves = Vec::with_capacity(compiled.len());
        for (
            predicate_id,
            script,
            expected_witness_elements,
            showdown_category,
            showdown_outcome,
        ) in compiled
        {
            let control_block = spend_info
                .control_block(&(script.clone(), LeafVersion::TapScript))
                .ok_or(BitcoinBackendError::TaprootConstruction)?
                .serialize();
            leaves.push(CompiledTapLeaf {
                predicate_id,
                script,
                control_block,
                expected_witness_elements,
                showdown_category,
                showdown_outcome,
            });
        }
        Ok(Self {
            spend_info,
            leaves,
            logical_state_digest,
        })
    }

    /// Return the P2TR script pubkey for this state.
    #[must_use]
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.spend_info.output_key())
    }

    /// Return Taproot construction details.
    #[must_use]
    pub const fn spend_info(&self) -> &TaprootSpendInfo {
        &self.spend_info
    }

    /// Return leaves in canonical predicate-ID order.
    #[must_use]
    pub fn leaves(&self) -> &[CompiledTapLeaf] {
        &self.leaves
    }

    /// Return the canonical logical-state digest committed by the hidden,
    /// provably unspendable Taproot leaf.
    #[must_use]
    pub const fn logical_state_digest(&self) -> [u8; 32] {
        self.logical_state_digest
    }

    /// Locate a compiled leaf by semantic predicate identifier.
    #[must_use]
    pub fn leaf(&self, predicate_id: [u8; 32]) -> Option<&CompiledTapLeaf> {
        self.leaves
            .binary_search_by_key(&predicate_id, CompiledTapLeaf::predicate_id)
            .ok()
            .map(|index| &self.leaves[index])
    }

    /// Locate the unique category-specific showdown leaf in this state.
    #[must_use]
    pub fn showdown_leaf(
        &self,
        category: HandCategory,
        outcome: Option<ShowdownOutcome>,
    ) -> Option<&CompiledTapLeaf> {
        self.leaves.iter().find(|leaf| {
            leaf.showdown_category() == Some(category) && leaf.showdown_outcome() == outcome
        })
    }
}

/// Return a leaf's BIP341 script-path hash.
#[must_use]
pub fn tapleaf_hash(script: &bitcoin::Script) -> [u8; 32] {
    TapLeafHash::from_script(script, LeafVersion::TapScript).to_byte_array()
}

fn state_commitment_script(logical_state_digest: [u8; 32]) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(STATE_COMMITMENT_MAGIC)
        .push_slice(logical_state_digest)
        .into_script()
}

const EXECUTABLE_LEAF_WEIGHT: u32 = 1_000_000;
const COMMITMENT_LEAF_WEIGHT: u32 = 1;

const SCORE_CERTIFICATE_WITNESS_ELEMENTS: usize = 1 + 48;

const ALICE_SHOWDOWN_WITNESS_ELEMENTS: usize =
    // Score certificate, two Bitcoin signatures, evaluator decomposition,
    // subset, and fourteen card-share openings.
    SCORE_CERTIFICATE_WITNESS_ELEMENTS + 2 + EVAL5_PROOF_ELEMENTS + 1 + 14;

const BOB_PAYOUT_WITNESS_ELEMENTS: usize =
    ALICE_SHOWDOWN_WITNESS_ELEMENTS + SCORE_CERTIFICATE_WITNESS_ELEMENTS;

/// Assemble the exact ordinary timeout stack in canonical Alice/Bob order.
///
/// The caller decides which signature was fixed in advance and which was
/// produced live; witness order depends only on role.
#[must_use]
pub fn assemble_timeout_witness_elements(
    alice_signature: DefaultSighashSignature,
    bob_signature: DefaultSighashSignature,
) -> Vec<Vec<u8>> {
    vec![
        alice_signature.to_bytes().to_vec(),
        bob_signature.to_bytes().to_vec(),
    ]
}

pub(crate) fn alice_score_certificate_elements(
    certificate: &AliceScoreCertificate,
) -> Vec<Vec<u8>> {
    score_certificate_elements(
        certificate.score_a(),
        LamportMessage::AliceScore(certificate.score_a()),
        certificate.lamport_signature(),
    )
}

pub(crate) fn bob_score_certificate_elements(certificate: &BobScoreCertificate) -> Vec<Vec<u8>> {
    score_certificate_elements(
        certificate.score_b(),
        LamportMessage::BobScore(certificate.score_b()),
        certificate.lamport_signature(),
    )
}

fn score_certificate_elements(
    score: Score24,
    message: LamportMessage,
    signature: &LamportSignature,
) -> Vec<Vec<u8>> {
    let bits = message.bits_msb_first();
    let mut elements = Vec::with_capacity(1 + 2 * bits.len());
    elements.push(encode_script_num(i64::from(score.get())));
    for (preimage, bit) in signature.preimages().iter().zip(bits) {
        elements.push(preimage.to_vec());
        elements.push(encode_script_num(i64::from(bit)));
    }
    elements
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ShowdownOpenings {
    Dlog {
        deal_id: [u8; 32],
        keys: Vec<Vec<[u8; 32]>>,
    },
}

impl ShowdownOpenings {
    fn is_dlog(&self) -> bool {
        matches!(self, Self::Dlog { .. })
    }

    fn dlog(
        deal: &dlog52_protocol::VerifiedAcceptedDeal,
        slots: &[u8; 7],
    ) -> Result<Self, BitcoinBackendError> {
        let mut keys = Vec::with_capacity(7);
        for slot in slots {
            let mut candidates = Vec::with_capacity(103);
            for key in &deal.catalogue().keys[usize::from(*slot)] {
                candidates.push(dlog52_protocol::point_xonly(key).map_err(|_| {
                    BitcoinBackendError::InvalidXOnlyPublicKey {
                        purpose: "dlog candidate",
                    }
                })?);
            }
            keys.push(candidates);
        }
        Ok(Self::Dlog {
            deal_id: dlog52_protocol::accepted_body_hash(&deal.as_deal().body),
            keys,
        })
    }

    fn encode_into(&self, encoded: &mut Vec<u8>) {
        match self {
            Self::Dlog { deal_id, keys } => {
                // Fixed dlog candidate-catalogue encoding marker.
                encoded.push(255);
                encoded.extend_from_slice(deal_id);
                for slot in keys {
                    for key in slot {
                        encoded.extend_from_slice(key);
                    }
                }
            }
        }
    }

    fn append_to(&self, mut builder: Builder) -> Builder {
        let (deal_id, keys) = match self {
            Self::Dlog { deal_id, keys } => (deal_id, keys),
        };
        builder = builder.push_slice(deal_id).push_opcode(OP_DROP);
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

fn append_candidate_selector(builder: Builder, keys: &[[u8; 32]], first: usize) -> Builder {
    if keys.len() == 1 {
        return builder.push_opcode(OP_DROP).push_slice(keys[0]);
    }
    let left = keys.len() / 2;
    let builder = builder
        .push_opcode(OP_DUP)
        .push_int((first + left) as i64)
        .push_opcode(OP_LESSTHAN)
        .push_opcode(OP_IF);
    let builder = append_candidate_selector(builder, &keys[..left], first).push_opcode(OP_ELSE);
    append_candidate_selector(builder, &keys[left..], first + left).push_opcode(OP_ENDIF)
}

fn append_distinct_seven(mut builder: Builder) -> Builder {
    // Native `selected_five` rejects duplicates anywhere in the seven-card
    // hand, including either card omitted by the selected subset. Compare all
    // 21 pairs before selection while preserving the source-card stack.
    for left in 0..7 {
        for right in (left + 1)..7 {
            let left_depth = 6_usize.saturating_sub(left);
            let right_depth = 6_usize.saturating_sub(right).saturating_add(1);
            builder = builder
                .push_int(i64::try_from(left_depth).unwrap_or(i64::MAX))
                .push_opcode(OP_PICK)
                .push_int(i64::try_from(right_depth).unwrap_or(i64::MAX))
                .push_opcode(OP_PICK)
                .push_opcode(OP_NUMNOTEQUAL)
                .push_opcode(OP_VERIFY);
        }
    }
    builder
}

fn append_subset_selection(builder: Builder) -> Builder {
    let mut builder = append_subset_case(builder, 0);
    // Move the five selected copies aside, delete subset plus all seven source
    // cards, then restore the selected cards in evaluator order.
    for _ in 0..5 {
        builder = builder.push_opcode(OP_TOALTSTACK);
    }
    for _ in 0..8 {
        builder = builder.push_opcode(OP_DROP);
    }
    for _ in 0..5 {
        builder = builder.push_opcode(OP_FROMALTSTACK);
    }
    builder
}

fn append_subset_case(mut builder: Builder, subset_id: u8) -> Builder {
    // Before selection the fixed local layout is `subset c0 ... c6`; subset is
    // therefore depth seven. Every copied selected card increases source-card
    // depth by one.
    builder = builder
        .push_int(7)
        .push_opcode(OP_PICK)
        .push_int(i64::from(subset_id))
        .push_opcode(OP_NUMEQUAL)
        .push_opcode(OP_IF);
    for (selected_count, position) in SUBSETS_5_OF_7[usize::from(subset_id)]
        .into_iter()
        .enumerate()
    {
        let depth = 6_usize
            .saturating_sub(usize::from(position))
            .saturating_add(selected_count);
        builder = builder
            .push_int(i64::try_from(depth).unwrap_or(i64::MAX))
            .push_opcode(OP_PICK);
    }
    builder = builder.push_opcode(OP_ELSE);
    if subset_id == 20 {
        builder = builder.push_int(0).push_opcode(OP_VERIFY);
    } else {
        builder = append_subset_case(builder, subset_id + 1);
    }
    builder.push_opcode(OP_ENDIF)
}

fn append_score_certificate(mut builder: Builder, public_key: &LamportPublicKey) -> Builder {
    // Witness entries are `(preimage_0, bit_0, ..., preimage_23, bit_23)` in
    // canonical MSB-first index order. Script consumes them in reverse and
    // places bits on the altstack, making bit zero the first one recovered.
    for pair in public_key.public_hash_pairs().iter().rev() {
        builder = builder
            .push_opcode(OP_DUP)
            .push_opcode(OP_TOALTSTACK)
            .push_opcode(OP_IF)
            .push_slice(pair[1])
            .push_opcode(OP_ELSE)
            .push_slice(pair[0])
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_SWAP)
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_SHA256)
            .push_opcode(OP_EQUALVERIFY);
    }

    // Recover six big-endian nibbles from the verified bits. They remain on
    // the main stack as `(category, r1, ..., r5)` for canonical layout checks.
    for _ in 0..6 {
        builder = builder.push_int(0);
        for _ in 0..4 {
            builder = builder
                .push_opcode(OP_DUP)
                .push_opcode(OP_ADD)
                .push_opcode(OP_FROMALTSTACK)
                .push_opcode(OP_ADD);
        }
    }
    let builder = crate::eval5_script::append_canonical_score(builder);
    // Keep the reconstructed value while consuming the separately supplied
    // score field. Numeric equality accepts the four-byte Script-number
    // encoding required by scores whose top 24-bit sign bit is set.
    builder
        .push_opcode(OP_DUP)
        .push_opcode(OP_TOALTSTACK)
        .push_opcode(OP_NUMEQUALVERIFY)
        .push_opcode(OP_FROMALTSTACK)
}

fn append_signature_checks(mut builder: Builder, keys: &[[u8; 32]]) -> Builder {
    for key in keys.iter().rev() {
        builder = append_signature_check(builder, *key);
    }
    builder
}

fn append_signature_check(builder: Builder, key: [u8; 32]) -> Builder {
    builder.push_slice(key).push_opcode(OP_CHECKSIGVERIFY)
}

fn append_terminal_signature_checks(mut builder: Builder, keys: &[[u8; 32]]) -> Builder {
    for (index, key) in keys.iter().rev().enumerate() {
        builder = builder
            .push_slice(*key)
            .push_opcode(if index + 1 == keys.len() {
                OP_CHECKSIG
            } else {
                OP_CHECKSIGVERIFY
            });
    }
    builder
}

fn validate_authorizers(keys: &[[u8; 32]; 2]) -> Result<(), BitcoinBackendError> {
    validate_xonly(keys[0], "Alice preauthorization")?;
    validate_xonly(keys[1], "Bob preauthorization")
}

fn validate_xonly(key: [u8; 32], purpose: &'static str) -> Result<(), BitcoinBackendError> {
    XOnlyPublicKey::from_slice(&key)
        .map(|_| ())
        .map_err(|_| BitcoinBackendError::InvalidXOnlyPublicKey { purpose })
}

fn validate_identifier(
    identifier: [u8; 32],
    field: &'static str,
) -> Result<(), BitcoinBackendError> {
    if identifier.iter().all(|byte| *byte == 0) {
        Err(BitcoinBackendError::ZeroIdentifier { field })
    } else {
        Ok(())
    }
}

fn validate_lamport_context(
    actual: KeyContext,
    expected: KeyContext,
) -> Result<(), BitcoinBackendError> {
    if actual.chain_game_id != expected.chain_game_id {
        return Err(bp52_lamport::LamportError::WrongGame.into());
    }
    if actual.node_id != expected.node_id {
        return Err(bp52_lamport::LamportError::WrongNode.into());
    }
    if actual.purpose != expected.purpose {
        return Err(bp52_lamport::LamportError::WrongPurpose.into());
    }
    Ok(())
}

fn validate_script_size(script: &bitcoin::Script) -> Result<(), BitcoinBackendError> {
    if script.len() > MAX_CONSENSUS_SCRIPT_BYTES {
        Err(BitcoinBackendError::OversizedConsensusScript {
            actual: script.len(),
            maximum: MAX_CONSENSUS_SCRIPT_BYTES,
        })
    } else {
        Ok(())
    }
}

fn append_keys(encoded: &mut Vec<u8>, keys: &[[u8; 32]; 2]) {
    encoded.extend_from_slice(&keys[0]);
    encoded.extend_from_slice(&keys[1]);
}

fn append_length_prefixed(encoded: &mut Vec<u8>, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    encoded.extend_from_slice(&length.to_le_bytes());
    encoded.extend_from_slice(bytes);
}

fn tagged_sha256(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hash = Sha256::new();
    hash.update(tag_hash);
    hash.update(tag_hash);
    hash.update(message);
    hash.finalize().into()
}
