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
use bp52_bitcoin::SCRIPT_PATH_NUMS_KEY;
use bp52_chain_types::{AcceptedDeal, Action, Role, ShowdownOutcome, root_node_id};
use bp52_lamport::{
    AliceScoreCertificate, BobScoreCertificate, KeyContext, LamportMessage, LamportPublicKey,
    LamportPurpose, LamportSignature, Score24,
};
use bp52_poker::{HandCategory, HandScore, SUBSETS_5_OF_7};
use sha2::{Digest, Sha256};

use crate::eval5_script::{
    EVAL5_PROOF_ELEMENTS, Eval5ScriptWitness, append_eval5, append_eval5_for_category,
    encode_script_num,
};
use crate::{
    ALICE_SEVEN_SLOTS, BOB_SEVEN_SLOTS, BitcoinBackendError, DefaultSighashSignature,
    ShareRevealPredicate, ShowdownHandWitness, verify_showdown_hand,
};

/// Legacy profile script-size bound. Tapscript has no consensus 10,000-byte limit.
pub const MAX_CONSENSUS_SCRIPT_BYTES: usize = 10_000;
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
    /// Both fixed Bitcoin signatures plus exact committed share preimages.
    Reveal(RevealProgram),
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
            Self::Action(_) | Self::Reveal(_) | Self::DlogReveal(_) | Self::Timeout(_) => None,
        }
    }

    /// Return Bob's payout outcome for a showdown leaf.
    #[must_use]
    pub const fn showdown_outcome(&self) -> Option<ShowdownOutcome> {
        match self {
            Self::BobPayout(program) => Some(program.outcome),
            Self::Action(_)
            | Self::Reveal(_)
            | Self::DlogReveal(_)
            | Self::Timeout(_)
            | Self::AliceShowdown(_) => None,
        }
    }
    /// Return the complete canonical semantic program encoding.
    #[must_use]
    pub fn encode_program(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(PROGRAM_MAGIC);
        match self {
            Self::Action(program) => program.encode_into(&mut encoded),
            Self::Reveal(program) => program.encode_into(&mut encoded),
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
            Self::Reveal(program) => Ok(2 + program.predicate.expected_hashes().len()),
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
            Self::Reveal(program) => program.to_tapscript(),
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

/// One exact phase-specific share-reveal program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevealProgram {
    chain_game_id: [u8; 32],
    node_id: [u8; 32],
    predicate: ShareRevealPredicate,
    authorizers: [[u8; 32]; 2],
}

impl RevealProgram {
    /// Bind a native reveal predicate and both fixed transaction signers.
    ///
    /// # Errors
    ///
    /// Returns an error if either authorizer is not a valid x-only key.
    pub fn new(
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        predicate: ShareRevealPredicate,
        authorizers: [[u8; 32]; 2],
    ) -> Result<Self, BitcoinBackendError> {
        validate_identifier(chain_game_id, "reveal chain game id")?;
        validate_identifier(node_id, "reveal node id")?;
        validate_authorizers(&authorizers)?;
        Ok(Self {
            chain_game_id,
            node_id,
            predicate,
            authorizers,
        })
    }

    /// Return the native predicate mirrored by the script.
    #[must_use]
    pub const fn predicate(&self) -> &ShareRevealPredicate {
        &self.predicate
    }

    fn encode_into(&self, encoded: &mut Vec<u8>) {
        encoded.push(1);
        encoded.extend_from_slice(&self.chain_game_id);
        encoded.extend_from_slice(&self.node_id);
        encoded.push(self.predicate.pattern().code());
        append_keys(encoded, &self.authorizers);
        encoded.push(u8::try_from(self.predicate.expected_hashes().len()).unwrap_or(u8::MAX));
        for hash in self.predicate.expected_hashes() {
            encoded.extend_from_slice(hash);
        }
    }

    fn to_tapscript(&self) -> ScriptBuf {
        let mut builder = Builder::new();
        for expected_hash in self.predicate.expected_hashes().iter().rev() {
            builder = append_share_check(builder, expected_hash);
        }
        append_terminal_signature_checks(builder, &self.authorizers).into_script()
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

    /// Construct the deterministic program description.
    ///
    /// # Errors
    ///
    /// Rejects a score key with the wrong exact context or invalid authorizers.
    pub fn new(
        deal: &AcceptedDeal,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        score_public_key: LamportPublicKey,
        authorizers: [[u8; 32]; 2],
    ) -> Result<Self, BitcoinBackendError> {
        Self::new_inner(
            ShowdownOpenings::Legacy(opening_hashes(deal, &ALICE_SEVEN_SLOTS)),
            chain_game_id,
            node_id,
            score_public_key,
            authorizers,
            None,
        )
    }

    /// Construct one category-specific lower-bound showdown leaf.
    pub fn new_for_category(
        deal: &AcceptedDeal,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        score_public_key: LamportPublicKey,
        authorizers: [[u8; 32]; 2],
        claimed_category: HandCategory,
    ) -> Result<Self, BitcoinBackendError> {
        Self::new_inner(
            ShowdownOpenings::Legacy(opening_hashes(deal, &ALICE_SEVEN_SLOTS)),
            chain_game_id,
            node_id,
            score_public_key,
            authorizers,
            Some(claimed_category),
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

    /// Construct one branch-specific deterministic terminal program description.
    /// `terminal_authorizers` is ordered as Alice's fixed preauthorization
    /// followed by Bob's live terminal key.
    ///
    /// # Errors
    ///
    /// Rejects malformed Bitcoin keys, zero context identifiers, an Alice
    /// score key not bound to the exact preceding showdown node, or a Bob
    /// score key not bound to this terminal node.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deal: &AcceptedDeal,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        alice_showdown_node_id: [u8; 32],
        outcome: ShowdownOutcome,
        alice_score_public_key: LamportPublicKey,
        bob_score_public_key: LamportPublicKey,
        terminal_authorizers: [[u8; 32]; 2],
    ) -> Result<Self, BitcoinBackendError> {
        Self::new_inner(
            ShowdownOpenings::Legacy(opening_hashes(deal, &BOB_SEVEN_SLOTS)),
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

    /// Construct one category-specific lower-bound payout leaf.
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_category(
        deal: &AcceptedDeal,
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        alice_showdown_node_id: [u8; 32],
        outcome: ShowdownOutcome,
        alice_score_public_key: LamportPublicKey,
        bob_score_public_key: LamportPublicKey,
        terminal_authorizers: [[u8; 32]; 2],
        claimed_category: HandCategory,
    ) -> Result<Self, BitcoinBackendError> {
        Self::new_inner(
            ShowdownOpenings::Legacy(opening_hashes(deal, &BOB_SEVEN_SLOTS)),
            chain_game_id,
            node_id,
            alice_showdown_node_id,
            outcome,
            alice_score_public_key,
            bob_score_public_key,
            terminal_authorizers,
            Some(claimed_category),
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
    /// and timeout leaves use `[alice_signature, bob_signature]`. Reveal leaves use
    /// `[alice_signature, bob_signature, preimage_0, ...]`,
    /// with preimages in [`crate::RevealPattern::slots`] order. Showdown callers should use
    /// [`assemble_alice_showdown_witness_elements`] or
    /// [`assemble_bob_payout_witness_elements`] rather than reproduce their
    /// score-bit and evaluator-proof layouts. The compiler emits checks in
    /// reverse order so the last ordinary witness element is consumed first.
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

/// Assemble Alice's exact ordinary showdown stack, bottom to top.
///
/// The result contains the score certificate (including explicit public score
/// bits), fixed signatures, canonical evaluator decomposition, subset number,
/// and seven Alice/Bob opening pairs. The returned elements exclude tapscript
/// and control block.
///
/// # Errors
///
/// Rejects an invalid hand, subset, opening, score, or a certificate score
/// that differs from the selected hand.
pub fn assemble_alice_showdown_witness_elements(
    deal: &AcceptedDeal,
    alice_signature: DefaultSighashSignature,
    bob_signature: DefaultSighashSignature,
    hand: &ShowdownHandWitness,
    certificate: &AliceScoreCertificate,
) -> Result<Vec<Vec<u8>>, BitcoinBackendError> {
    let verified = verify_showdown_hand(deal, Role::Alice, hand)?;
    let certificate_score = HandScore::try_from(certificate.score_a().get())?;
    if certificate_score != verified.score() {
        return Err(BitcoinBackendError::AliceCertificateMismatch {
            certificate: certificate_score.as_u32(),
            hand: verified.score().as_u32(),
        });
    }

    let mut elements = alice_score_certificate_elements(certificate);
    elements.push(alice_signature.to_bytes().to_vec());
    elements.push(bob_signature.to_bytes().to_vec());
    append_hand_elements(&mut elements, hand, verified.selected())?;
    debug_assert_eq!(elements.len(), ALICE_SHOWDOWN_WITNESS_ELEMENTS);
    Ok(elements)
}

/// Assemble Bob's exact ordinary payout stack, bottom to top.
///
/// This repeats Alice's score certificate, adds Bob's terminal-node score
/// certificate and canonical selected-hand proof, and preserves the
/// fixed-Alice/live-Bob signature order. The returned elements exclude
/// tapscript and control block.
///
/// # Errors
///
/// Rejects an invalid Bob hand, malformed score certificate, a Bob certificate
/// that differs from his selected hand, or scores that do not satisfy the
/// selected branch.
pub fn assemble_bob_payout_witness_elements(
    deal: &AcceptedDeal,
    outcome: ShowdownOutcome,
    alice_signature: DefaultSighashSignature,
    bob_signature: DefaultSighashSignature,
    hand: &ShowdownHandWitness,
    alice_certificate: &AliceScoreCertificate,
    bob_certificate: &BobScoreCertificate,
) -> Result<Vec<Vec<u8>>, BitcoinBackendError> {
    let score_a = HandScore::try_from(alice_certificate.score_a().get())?;
    let verified_bob = verify_showdown_hand(deal, Role::Bob, hand)?;
    let certified_score_b = HandScore::try_from(bob_certificate.score_b().get())?;
    if certified_score_b != verified_bob.score() {
        return Err(BitcoinBackendError::BobCertificateMismatch {
            certificate: certified_score_b.as_u32(),
            hand: verified_bob.score().as_u32(),
        });
    }
    let valid = match outcome {
        ShowdownOutcome::AliceWin => score_a > certified_score_b,
        ShowdownOutcome::BobWin => score_a < certified_score_b,
        ShowdownOutcome::Split => score_a == certified_score_b,
    };
    if !valid {
        return Err(BitcoinBackendError::WrongShowdownOutcome {
            score_a: score_a.as_u32(),
            score_b: certified_score_b.as_u32(),
            outcome: match outcome {
                ShowdownOutcome::AliceWin => "AliceWin",
                ShowdownOutcome::BobWin => "BobWin",
                ShowdownOutcome::Split => "Split",
            },
        });
    }

    let mut elements = alice_score_certificate_elements(alice_certificate);
    elements.extend(bob_score_certificate_elements(bob_certificate));
    elements.push(alice_signature.to_bytes().to_vec());
    elements.push(bob_signature.to_bytes().to_vec());
    append_hand_elements(&mut elements, hand, verified_bob.selected())?;
    debug_assert_eq!(elements.len(), BOB_PAYOUT_WITNESS_ELEMENTS);
    Ok(elements)
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

fn append_hand_elements(
    elements: &mut Vec<Vec<u8>>,
    hand: &ShowdownHandWitness,
    selected: [u8; 5],
) -> Result<(), BitcoinBackendError> {
    let claimed_score = HandScore::try_from(hand.claimed_score())?;
    elements.extend(
        Eval5ScriptWitness::from_claimed_score(selected, claimed_score)?.to_witness_elements(),
    );
    elements.push(encode_script_num(i64::from(hand.subset_id())));
    for opening in hand.openings() {
        elements.push(opening.preimage_a().to_vec());
        elements.push(opening.preimage_b().to_vec());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ShowdownOpenings {
    Legacy(Vec<[[u8; 32]; 2]>),
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
            Self::Legacy(hashes) => append_opening_hashes(encoded, hashes),
            Self::Dlog { deal_id, keys } => {
                // 255 cannot be the legacy seven-card opening count.
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
            Self::Legacy(hashes) => return append_seven_card_openings(builder, hashes),
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

fn append_seven_card_openings(mut builder: Builder, opening_hashes: &[[[u8; 32]; 2]]) -> Builder {
    // Witness pairs are ordered by the role-specific seven-card order. The
    // last Bob preimage starts on top, so cards are reconstructed in reverse
    // and parked on the altstack. Pulling them later restores forward order.
    for hashes in opening_hashes.iter().rev() {
        builder = append_share_value_check(builder, &hashes[1]).push_opcode(OP_SWAP);
        builder = append_share_value_check(builder, &hashes[0])
            .push_opcode(OP_ADD)
            .push_opcode(OP_DUP)
            .push_int(52)
            .push_opcode(OP_GREATERTHANOREQUAL)
            .push_opcode(OP_IF)
            .push_int(52)
            .push_opcode(OP_SUB)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_TOALTSTACK);
    }
    for _ in 0..7 {
        builder = builder.push_opcode(OP_FROMALTSTACK);
    }
    append_distinct_seven(builder)
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

fn append_share_value_check(builder: Builder, expected_hash: &[u8; 32]) -> Builder {
    builder
        .push_opcode(OP_SIZE)
        .push_opcode(OP_DUP)
        .push_int(16)
        .push_opcode(OP_GREATERTHANOREQUAL)
        .push_opcode(OP_VERIFY)
        .push_opcode(OP_DUP)
        .push_int(67)
        .push_opcode(OP_LESSTHANOREQUAL)
        .push_opcode(OP_VERIFY)
        .push_int(16)
        .push_opcode(OP_SUB)
        .push_opcode(OP_SWAP)
        .push_opcode(OP_SHA256)
        .push_slice(expected_hash)
        .push_opcode(OP_EQUALVERIFY)
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

fn append_share_check(builder: Builder, expected_hash: &[u8; 32]) -> Builder {
    builder
        .push_opcode(OP_SIZE)
        .push_int(16)
        .push_opcode(OP_GREATERTHANOREQUAL)
        .push_verify()
        .push_opcode(OP_SIZE)
        .push_int(67)
        .push_opcode(OP_LESSTHANOREQUAL)
        .push_verify()
        .push_opcode(OP_SHA256)
        .push_slice(expected_hash)
        .push_opcode(OP_EQUALVERIFY)
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

fn opening_hashes(deal: &AcceptedDeal, slots: &[u8]) -> Vec<[[u8; 32]; 2]> {
    slots
        .iter()
        .map(|slot| {
            let index = usize::from(*slot);
            [deal.hashes_a[index], deal.hashes_b[index]]
        })
        .collect()
}

fn append_opening_hashes(encoded: &mut Vec<u8>, hashes: &[[[u8; 32]; 2]]) {
    encoded.push(u8::try_from(hashes.len()).unwrap_or(u8::MAX));
    for pair in hashes {
        encoded.extend_from_slice(&pair[0]);
        encoded.extend_from_slice(&pair[1]);
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

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut, Txid};
    use bp52_chain_types::{AcceptedDeal, Action, Role, ShowdownOutcome, root_node_id};
    use bp52_lamport::{
        AliceScoreCertificate, BobScoreCertificate, KeyContext, LamportMessage, LamportPublicKey,
        LamportPurpose, LamportSignature, Score24,
    };
    use bp52_poker::{HandCategory, SUBSETS_5_OF_7, eval5};
    use sha2::{Digest, Sha256};

    use super::{
        ActionProgram, AliceShowdownProgram, BobPayoutProgram, CompiledTaprootState, LeafProgram,
        RevealProgram, SHOWDOWN_CATEGORIES, TimeoutProgram,
        assemble_alice_showdown_witness_elements, assemble_bob_payout_witness_elements,
        assemble_timeout_witness_elements,
    };
    use crate::eval5_script::{
        encode_script_num,
        tests::{TEST_SIGHASH, execute, execute_with_sighash},
    };
    use crate::{
        ALICE_SEVEN_SLOTS, BOB_SEVEN_SLOTS, BitcoinBackendError, CardOpeningWitness, RevealPattern,
        ShareRevealPredicate, ShowdownHandWitness, TransactionTemplate, sign_sighash_default,
        taproot_script_sighash_default,
    };

    struct ShowdownFixture {
        deal: AcceptedDeal,
        cards: [u8; 9],
        preimages_a: [Vec<u8>; 9],
        preimages_b: [Vec<u8>; 9],
    }

    impl ShowdownFixture {
        fn hand(
            &self,
            role: Role,
            subset_id: u8,
        ) -> Result<ShowdownHandWitness, Box<dyn std::error::Error>> {
            let slots = match role {
                Role::Alice => ALICE_SEVEN_SLOTS,
                Role::Bob => BOB_SEVEN_SLOTS,
            };
            let seven = slots.map(|slot| self.cards[usize::from(slot)]);
            let selected =
                SUBSETS_5_OF_7[usize::from(subset_id)].map(|position| seven[usize::from(position)]);
            let score = eval5(selected)?.as_u32();
            let openings = slots.map(|slot| {
                let index = usize::from(slot);
                CardOpeningWitness::new(
                    slot,
                    self.preimages_a[index].clone(),
                    self.preimages_b[index].clone(),
                )
            });
            Ok(ShowdownHandWitness::new(openings, subset_id, score))
        }
    }

    fn xonly_key(byte: u8) -> Result<[u8; 32], bitcoin::secp256k1::Error> {
        let secp = Secp256k1::new();
        let keypair = bitcoin_keypair(&secp, byte)?;
        Ok(keypair.x_only_public_key().0.serialize())
    }

    fn bitcoin_keypair(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        byte: u8,
    ) -> Result<Keypair, bitcoin::secp256k1::Error> {
        let secret = SecretKey::from_slice(&[byte; 32])?;
        Ok(Keypair::from_secret_key(secp, &secret))
    }

    fn lamport_key(
        chain_game_id: [u8; 32],
        _node_id: [u8; 32],
        purpose: LamportPurpose,
    ) -> Result<LamportPublicKey, bp52_lamport::LamportError> {
        lamport_key_for_context(chain_game_id, root_node_id(&chain_game_id), purpose)
    }

    fn lamport_key_for_context(
        chain_game_id: [u8; 32],
        context_node_id: [u8; 32],
        purpose: LamportPurpose,
    ) -> Result<LamportPublicKey, bp52_lamport::LamportError> {
        let pairs = (0..purpose.bit_width())
            .map(|index| {
                let left = [index + 1; 32];
                let right = [index + 101; 32];
                [Sha256::digest(left).into(), Sha256::digest(right).into()]
            })
            .collect();
        LamportPublicKey::from_parts(
            KeyContext::new(chain_game_id, context_node_id, purpose),
            pairs,
        )
    }

    fn deal() -> AcceptedDeal {
        AcceptedDeal {
            protocol_version: 1,
            game_id: [1_u8; 32],
            attempt: 0,
            hashes_a: core::array::from_fn(|index| [u8::try_from(index).unwrap_or_default(); 32]),
            hashes_b: core::array::from_fn(|index| {
                [u8::try_from(index + 20).unwrap_or_default(); 32]
            }),
            verification_transcript_root: [2_u8; 32],
            signature_a: [3_u8; 64],
            signature_b: [4_u8; 64],
        }
    }

    fn showdown_fixture(cards: [u8; 9]) -> ShowdownFixture {
        assert!(cards.into_iter().all(|card| card < 52));
        let preimages_a =
            core::array::from_fn(|index| vec![0x20 + u8::try_from(index).unwrap_or_default(); 16]);
        let preimages_b = core::array::from_fn(|index| {
            vec![0x60 + u8::try_from(index).unwrap_or_default(); 16 + usize::from(cards[index])]
        });
        let hashes_a = core::array::from_fn(|index| Sha256::digest(&preimages_a[index]).into());
        let hashes_b = core::array::from_fn(|index| Sha256::digest(&preimages_b[index]).into());
        ShowdownFixture {
            deal: AcceptedDeal {
                protocol_version: 1,
                game_id: [1_u8; 32],
                attempt: 0,
                hashes_a,
                hashes_b,
                verification_transcript_root: [2_u8; 32],
                signature_a: [3_u8; 64],
                signature_b: [4_u8; 64],
            },
            cards,
            preimages_a,
            preimages_b,
        }
    }

    #[test]
    fn bob_taptree_has_one_leaf_for_every_outcome_and_category()
    -> Result<(), Box<dyn std::error::Error>> {
        let chain_game_id = [0x71; 32];
        let node_id = [0x72; 32];
        let alice_node_id = [0x73; 32];
        let authorizers = [xonly_key(7)?, xonly_key(8)?];
        let alice_key = lamport_key(
            chain_game_id,
            alice_node_id,
            LamportPurpose::AliceScore24Bit,
        )?;
        let bob_key = lamport_key(chain_game_id, node_id, LamportPurpose::BobScore24Bit)?;
        let mut programs = Vec::new();
        for outcome in [
            ShowdownOutcome::AliceWin,
            ShowdownOutcome::BobWin,
            ShowdownOutcome::Split,
        ] {
            for category in SHOWDOWN_CATEGORIES {
                programs.push(LeafProgram::BobPayout(BobPayoutProgram::new_for_category(
                    &deal(),
                    chain_game_id,
                    node_id,
                    alice_node_id,
                    outcome,
                    alice_key.clone(),
                    bob_key.clone(),
                    authorizers,
                    category,
                )?));
            }
        }
        let state =
            CompiledTaprootState::compile(&Secp256k1::verification_only(), [0x74; 32], &programs)?;
        assert_eq!(state.leaves().len(), 27);
        for outcome in [
            ShowdownOutcome::AliceWin,
            ShowdownOutcome::BobWin,
            ShowdownOutcome::Split,
        ] {
            for category in SHOWDOWN_CATEGORIES {
                let leaf = state
                    .showdown_leaf(category, Some(outcome))
                    .ok_or("missing showdown leaf")?;
                assert_eq!(leaf.showdown_category(), Some(category));
                assert_eq!(leaf.showdown_outcome(), Some(outcome));
            }
        }
        assert!(state.showdown_leaf(HandCategory::Straight, None).is_none());
        Ok(())
    }

    fn fixture_with_alice_selected(selected: [u8; 5]) -> Result<ShowdownFixture, std::io::Error> {
        let mut cards = [0_u8; 9];
        let mut used = [false; 52];
        for (slot, card) in ALICE_SEVEN_SLOTS[..5].iter().zip(selected) {
            cards[usize::from(*slot)] = card;
            used[usize::from(card)] = true;
        }
        let mut remaining = (0_u8..52).filter(|card| !used[usize::from(*card)]);
        for slot in [1_usize, 3, 7, 8] {
            cards[slot] = remaining
                .next()
                .ok_or_else(|| std::io::Error::other("insufficient filler cards"))?;
        }
        Ok(showdown_fixture(cards))
    }

    const fn card(rank: u8, suit: u8) -> u8 {
        rank * 4 + suit
    }

    fn score_material(
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        score: u32,
    ) -> Result<(LamportPublicKey, AliceScoreCertificate), Box<dyn std::error::Error>> {
        let score = Score24::new(score)?;
        let bits = LamportMessage::AliceScore(score).bits_msb_first();
        let preimages = bits
            .into_iter()
            .enumerate()
            .map(|(index, bit)| {
                let index = u8::try_from(index).unwrap_or_default();
                [[index + 1; 32], [index + 101; 32]][usize::from(bit)]
            })
            .collect();
        let signature = LamportSignature::from_parts(LamportPurpose::AliceScore24Bit, preimages)?;
        Ok((
            lamport_key(chain_game_id, node_id, LamportPurpose::AliceScore24Bit)?,
            AliceScoreCertificate::from_parts(score, signature)?,
        ))
    }

    fn bob_score_material(
        chain_game_id: [u8; 32],
        node_id: [u8; 32],
        score: u32,
    ) -> Result<(LamportPublicKey, BobScoreCertificate), Box<dyn std::error::Error>> {
        let score = Score24::new(score)?;
        let bits = LamportMessage::BobScore(score).bits_msb_first();
        let preimages = bits
            .into_iter()
            .enumerate()
            .map(|(index, bit)| {
                let index = u8::try_from(index).unwrap_or_default();
                [[index + 1; 32], [index + 101; 32]][usize::from(bit)]
            })
            .collect();
        let signature = LamportSignature::from_parts(LamportPurpose::BobScore24Bit, preimages)?;
        Ok((
            lamport_key(chain_game_id, node_id, LamportPurpose::BobScore24Bit)?,
            BobScoreCertificate::from_parts(score, signature)?,
        ))
    }

    fn opening_elements(fixture: &ShowdownFixture, role: Role) -> Vec<Vec<u8>> {
        let slots = match role {
            Role::Alice => ALICE_SEVEN_SLOTS,
            Role::Bob => BOB_SEVEN_SLOTS,
        };
        let mut elements = Vec::with_capacity(14);
        for slot in slots {
            let index = usize::from(slot);
            elements.push(fixture.preimages_a[index].clone());
            elements.push(fixture.preimages_b[index].clone());
        }
        elements
    }

    fn supported_programs() -> Result<Vec<LeafProgram>, Box<dyn std::error::Error>> {
        let chain_game_id = [5_u8; 32];
        let node_id = [6_u8; 32];
        let authorizers = [xonly_key(7)?, xonly_key(8)?];
        let action = ActionProgram::new(chain_game_id, node_id, Action::Raise, authorizers)?;
        let reveal = RevealProgram::new(
            chain_game_id,
            node_id,
            ShareRevealPredicate::new(&deal(), RevealPattern::Flop(Role::Bob)),
            authorizers,
        )?;
        let timeout = TimeoutProgram::new(chain_game_id, node_id, 144, authorizers)?;
        Ok(vec![
            LeafProgram::Action(action),
            LeafProgram::Reveal(reveal),
            LeafProgram::Timeout(timeout),
        ])
    }

    #[test]
    fn action_program_is_bound_to_context_action_and_both_authorizers()
    -> Result<(), Box<dyn std::error::Error>> {
        let chain_game_id = [1_u8; 32];
        let node_id = [2_u8; 32];
        let secp = Secp256k1::new();
        let alice = bitcoin_keypair(&secp, 3)?;
        let bob = bitcoin_keypair(&secp, 4)?;
        let authorizers = [
            alice.x_only_public_key().0.serialize(),
            bob.x_only_public_key().0.serialize(),
        ];
        let check = LeafProgram::Action(ActionProgram::new(
            chain_game_id,
            node_id,
            Action::Check,
            authorizers,
        )?);
        let raise = LeafProgram::Action(ActionProgram::new(
            chain_game_id,
            node_id,
            Action::Raise,
            authorizers,
        )?);
        assert_ne!(check.predicate_id(), raise.predicate_id());
        assert_ne!(check.to_tapscript()?, raise.to_tapscript()?);
        assert_eq!(check.expected_witness_elements()?, 2);

        let alice_signature = sign_sighash_default(&secp, &alice, TEST_SIGHASH);
        let bob_signature = sign_sighash_default(&secp, &bob, TEST_SIGHASH);
        let elements = vec![
            alice_signature.to_bytes().to_vec(),
            bob_signature.to_bytes().to_vec(),
        ];
        assert_eq!(
            execute(&check.to_tapscript()?, elements.clone())?.0,
            vec![vec![1]]
        );

        let mut wrong_actor_signature = elements.clone();
        wrong_actor_signature[0][0] ^= 1;
        assert!(execute(&check.to_tapscript()?, wrong_actor_signature).is_err());

        let mut wrong_opponent_signature = elements.clone();
        wrong_opponent_signature[1][0] ^= 1;
        assert!(execute(&check.to_tapscript()?, wrong_opponent_signature).is_err());

        let mut non_default_sighash = elements;
        non_default_sighash[0].push(1);
        assert!(execute(&check.to_tapscript()?, non_default_sighash).is_err());

        let current_encoding = check.encode_program();
        assert!(current_encoding.starts_with(b"BP52BSP7"));
        let mut superseded_encoding = current_encoding;
        superseded_encoding[..8].copy_from_slice(b"BP52BSP6");
        let superseded_id = super::tagged_sha256(
            b"BP52/chain-predicate/v5/rank-major-card-id",
            &superseded_encoding,
        );
        assert_ne!(check.predicate_id(), superseded_id);

        assert!(matches!(
            ActionProgram::new([0_u8; 32], node_id, Action::Check, authorizers,),
            Err(BitcoinBackendError::ZeroIdentifier { .. })
        ));
        Ok(())
    }

    #[test]
    fn compact_action_script_uses_move_code_and_terminal_checksig()
    -> Result<(), Box<dyn std::error::Error>> {
        let program = supported_programs()?.remove(0);
        let script = program.to_tapscript()?;
        let bytes = script.as_bytes();

        assert_eq!(
            &bytes[..2],
            &[0x50 + Action::Raise.code(), super::OP_DROP.to_u8()]
        );
        assert_eq!(bytes.last(), Some(&super::OP_CHECKSIG.to_u8()));
        assert_ne!(bytes.first(), Some(&32_u8));
        assert!(!bytes.windows(4).any(|window| {
            window == [super::OP_SIZE.to_u8(), 1, 64, super::OP_EQUALVERIFY.to_u8()]
        }));
        assert_eq!(bytes.len(), 70);
        Ok(())
    }

    #[test]
    fn timeout_requires_both_default_signatures_in_canonical_role_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();
        let alice = bitcoin_keypair(&secp, 30)?;
        let bob = bitcoin_keypair(&secp, 31)?;
        let authorizers = [
            alice.x_only_public_key().0.serialize(),
            bob.x_only_public_key().0.serialize(),
        ];
        let timeout = LeafProgram::Timeout(TimeoutProgram::new(
            [1_u8; 32],
            [2_u8; 32],
            144,
            authorizers,
        )?);
        assert_eq!(timeout.expected_witness_elements()?, 2);

        let alice_signature = sign_sighash_default(&secp, &alice, TEST_SIGHASH);
        let bob_signature = sign_sighash_default(&secp, &bob, TEST_SIGHASH);
        let elements = assemble_timeout_witness_elements(alice_signature, bob_signature);
        assert_eq!(
            execute(&timeout.to_tapscript()?, elements.clone())?.0,
            vec![vec![1]]
        );

        let mut missing_opponent = elements.clone();
        missing_opponent[0][0] ^= 1;
        assert!(execute(&timeout.to_tapscript()?, missing_opponent).is_err());
        let mut wrong_beneficiary = elements.clone();
        wrong_beneficiary[1][0] ^= 1;
        assert!(execute(&timeout.to_tapscript()?, wrong_beneficiary).is_err());
        let mut reversed = elements.clone();
        reversed.swap(0, 1);
        assert!(execute(&timeout.to_tapscript()?, reversed).is_err());
        let mut explicit_sighash = elements;
        explicit_sighash[1].push(1);
        assert!(execute(&timeout.to_tapscript()?, explicit_sighash).is_err());
        Ok(())
    }

    #[test]
    fn timeout_opponent_preauthorization_rejects_beneficiary_output_redirect()
    -> Result<(), Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();
        let alice = bitcoin_keypair(&secp, 32)?;
        let bob = bitcoin_keypair(&secp, 33)?;
        let authorizers = [
            alice.x_only_public_key().0.serialize(),
            bob.x_only_public_key().0.serialize(),
        ];
        let program = LeafProgram::Timeout(TimeoutProgram::new(
            [3_u8; 32],
            [4_u8; 32],
            12,
            authorizers,
        )?);
        let predicate_id = program.predicate_id();
        let state = CompiledTaprootState::compile(&secp, [5_u8; 32], &[program])?;
        let leaf = state.leaf(predicate_id).ok_or("timeout leaf missing")?;
        let parent_output = TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: state.script_pubkey(),
        };
        let template = TransactionTemplate::timeout(
            Network::Regtest,
            OutPoint::new(Txid::from_byte_array([6_u8; 32]), 0),
            parent_output.clone(),
            vec![TxOut {
                value: Amount::from_sat(900),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
            100,
            12,
        )?;
        let original_digest = taproot_script_sighash_default(
            template.transaction(),
            0,
            std::slice::from_ref(&parent_output),
            leaf.script(),
        )?;
        let opponent_preauthorization = sign_sighash_default(&secp, &alice, original_digest);
        let original_beneficiary = sign_sighash_default(&secp, &bob, original_digest);
        let original_elements =
            assemble_timeout_witness_elements(opponent_preauthorization, original_beneficiary);
        assert_eq!(
            execute_with_sighash(leaf.script(), original_elements, original_digest)?.0,
            vec![vec![1]]
        );

        let mut redirected = template.transaction().clone();
        redirected.output[0].value = Amount::from_sat(800);
        let redirected_digest = taproot_script_sighash_default(
            &redirected,
            0,
            std::slice::from_ref(&parent_output),
            leaf.script(),
        )?;
        assert_ne!(redirected_digest, original_digest);
        let redirected_beneficiary = sign_sighash_default(&secp, &bob, redirected_digest);
        let attack_elements =
            assemble_timeout_witness_elements(opponent_preauthorization, redirected_beneficiary);
        assert!(execute_with_sighash(leaf.script(), attack_elements, redirected_digest).is_err());
        Ok(())
    }

    #[test]
    fn reveal_script_commits_exact_hashes_and_witness_count()
    -> Result<(), Box<dyn std::error::Error>> {
        let accepted = deal();
        let predicate = ShareRevealPredicate::new(&accepted, RevealPattern::Flop(Role::Alice));
        let expected_hashes = predicate.expected_hashes().to_vec();
        let program = LeafProgram::Reveal(RevealProgram::new(
            [8_u8; 32],
            [9_u8; 32],
            predicate,
            [xonly_key(10)?, xonly_key(11)?],
        )?);
        let script = program.to_tapscript()?;
        assert_eq!(program.expected_witness_elements()?, 5);
        for hash in expected_hashes {
            assert!(script.as_bytes().windows(32).any(|window| window == hash));
        }
        Ok(())
    }

    #[test]
    fn taproot_root_is_independent_of_input_program_order() -> Result<(), Box<dyn std::error::Error>>
    {
        let secp = Secp256k1::verification_only();
        let programs = supported_programs()?;
        let mut reversed = programs.clone();
        reversed.reverse();
        let state_digest = [0x5a_u8; 32];
        let first = CompiledTaprootState::compile(&secp, state_digest, &programs)?;
        let second = CompiledTaprootState::compile(&secp, state_digest, &reversed)?;
        assert_eq!(first.script_pubkey(), second.script_pubkey());
        assert_eq!(
            first
                .leaves()
                .iter()
                .map(super::CompiledTapLeaf::predicate_id)
                .collect::<Vec<_>>(),
            second
                .leaves()
                .iter()
                .map(super::CompiledTapLeaf::predicate_id)
                .collect::<Vec<_>>()
        );

        let leaf = &first.leaves()[0];
        let elements = vec![vec![1_u8; 64]; leaf.expected_witness_elements()];
        let witness = leaf.assemble_witness(&elements)?;
        assert_eq!(witness.len(), elements.len() + 2);
        Ok(())
    }

    #[test]
    fn hidden_state_commitment_is_unspendable_and_changes_output_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let secp = Secp256k1::verification_only();
        let programs = supported_programs()?;
        let digest_a = [0x61_u8; 32];
        let digest_b = [0x62_u8; 32];
        let state_a = CompiledTaprootState::compile(&secp, digest_a, &programs)?;
        let state_b = CompiledTaprootState::compile(&secp, digest_b, &programs)?;
        assert_eq!(state_a.logical_state_digest(), digest_a);
        assert_eq!(state_b.logical_state_digest(), digest_b);
        assert_ne!(state_a.script_pubkey(), state_b.script_pubkey());

        let commitment = super::state_commitment_script(digest_a);
        assert_eq!(
            commitment.as_bytes().first(),
            Some(&super::OP_RETURN.to_u8())
        );
        assert!(
            commitment
                .as_bytes()
                .windows(super::STATE_COMMITMENT_MAGIC.len())
                .any(|window| window == super::STATE_COMMITMENT_MAGIC)
        );
        assert!(
            commitment
                .as_bytes()
                .windows(32)
                .any(|window| window == digest_a)
        );
        assert!(
            state_a
                .spend_info()
                .script_map()
                .contains_key(&(commitment.clone(), bitcoin::taproot::LeafVersion::TapScript))
        );
        assert_eq!(state_a.leaves().len(), programs.len());
        assert_eq!(state_a.spend_info().script_map().len(), programs.len() + 1);
        assert!(
            state_a
                .leaves()
                .iter()
                .all(|leaf| leaf.script().as_bytes() != commitment.as_bytes())
        );
        assert!(execute(&commitment, Vec::new()).is_err());
        Ok(())
    }

    #[test]
    fn unspendable_commitment_is_deeper_than_normal_spend_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let secp = Secp256k1::verification_only();
        let chain_game_id = [0x65_u8; 32];
        let node_id = [0x66_u8; 32];
        let authorizers = [xonly_key(7)?, xonly_key(8)?];
        let programs = [
            Action::Fold,
            Action::Check,
            Action::Call,
            Action::Bet,
            Action::Raise,
        ]
        .into_iter()
        .map(|action| {
            ActionProgram::new(chain_game_id, node_id, action, authorizers).map(LeafProgram::Action)
        })
        .collect::<Result<Vec<_>, _>>()?;
        let digest = [0x67_u8; 32];
        let state = CompiledTaprootState::compile(&secp, digest, &programs)?;
        let commitment = super::state_commitment_script(digest);
        let commitment_length = state
            .spend_info()
            .control_block(&(commitment, bitcoin::taproot::LeafVersion::TapScript))
            .ok_or("missing commitment control block")?
            .serialize()
            .len();

        assert!(
            state
                .leaves()
                .iter()
                .all(|leaf| leaf.control_block().len() <= commitment_length)
        );
        assert!(
            state
                .leaves()
                .iter()
                .any(|leaf| leaf.control_block().len() < commitment_length)
        );
        Ok(())
    }

    #[test]
    fn duplicate_and_oversized_witness_inputs_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let secp = Secp256k1::verification_only();
        let program = supported_programs()?.remove(0);
        assert!(matches!(
            CompiledTaprootState::compile(&secp, [0x5b_u8; 32], &[program.clone(), program]),
            Err(BitcoinBackendError::DuplicatePredicateId)
        ));

        let state =
            CompiledTaprootState::compile(&secp, [0x5c_u8; 32], &supported_programs()?[..1])?;
        let leaf = &state.leaves()[0];
        assert!(matches!(
            leaf.assemble_witness(&[]),
            Err(BitcoinBackendError::WrongWitnessElementCount { .. })
        ));
        let mut elements = vec![vec![1_u8; 32]; leaf.expected_witness_elements()];
        elements[0] = vec![0_u8; 521];
        assert!(matches!(
            leaf.assemble_witness(&elements),
            Err(BitcoinBackendError::OversizedWitnessElement { actual: 521, .. })
        ));
        Ok(())
    }

    #[test]
    fn every_supported_program_id_is_context_bound() -> Result<(), Box<dyn std::error::Error>> {
        let accepted = deal();
        let keys = [xonly_key(7)?, xonly_key(8)?];
        let reveal_predicate =
            ShareRevealPredicate::new(&accepted, RevealPattern::Flop(Role::Alice));
        let reveal_a = LeafProgram::Reveal(RevealProgram::new(
            [10_u8; 32],
            [11_u8; 32],
            reveal_predicate.clone(),
            keys,
        )?);
        let reveal_b = LeafProgram::Reveal(RevealProgram::new(
            [10_u8; 32],
            [12_u8; 32],
            reveal_predicate,
            keys,
        )?);
        assert_ne!(reveal_a.predicate_id(), reveal_b.predicate_id());

        let timeout_a =
            LeafProgram::Timeout(TimeoutProgram::new([10_u8; 32], [11_u8; 32], 144, keys)?);
        let timeout_b =
            LeafProgram::Timeout(TimeoutProgram::new([13_u8; 32], [11_u8; 32], 144, keys)?);
        assert_ne!(timeout_a.predicate_id(), timeout_b.predicate_id());

        assert!(matches!(
            TimeoutProgram::new([0_u8; 32], [11_u8; 32], 144, keys),
            Err(BitcoinBackendError::ZeroIdentifier { .. })
        ));
        assert!(matches!(
            RevealProgram::new(
                [10_u8; 32],
                [0_u8; 32],
                ShareRevealPredicate::new(&accepted, RevealPattern::Turn(Role::Bob),),
                keys
            ),
            Err(BitcoinBackendError::ZeroIdentifier { .. })
        ));
        Ok(())
    }

    #[test]
    fn alice_showdown_script_executes_high_bit_score_and_rejects_mutations()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = showdown_fixture([0, 4, 8, 12, 16, 20, 24, 28, 32]);
        let chain_game_id = [12_u8; 32];
        let node_id = [13_u8; 32];
        let hand = fixture.hand(Role::Alice, 20)?;
        let (score_key, certificate) =
            score_material(chain_game_id, node_id, hand.claimed_score())?;

        let secp = Secp256k1::new();
        let alice_keypair = bitcoin_keypair(&secp, 14)?;
        let bob_keypair = bitcoin_keypair(&secp, 15)?;
        let authorizers = [
            alice_keypair.x_only_public_key().0.serialize(),
            bob_keypair.x_only_public_key().0.serialize(),
        ];
        let alice_signature = sign_sighash_default(&secp, &alice_keypair, TEST_SIGHASH);
        let bob_signature = sign_sighash_default(&secp, &bob_keypair, TEST_SIGHASH);
        let program = LeafProgram::AliceShowdown(AliceShowdownProgram::new(
            &fixture.deal,
            chain_game_id,
            node_id,
            score_key,
            authorizers,
        )?);
        let script = program.to_tapscript()?;
        let elements = assemble_alice_showdown_witness_elements(
            &fixture.deal,
            alice_signature,
            bob_signature,
            &hand,
            &certificate,
        )?;
        assert_eq!(elements.len(), 82);
        assert!(hand.claimed_score() & 0x0080_0000 != 0);
        assert_eq!(elements[0].len(), 4, "positive score needs a sign byte");
        assert_eq!(elements[0].last(), Some(&0));
        let (stack, maximum_stack) = execute(&script, elements.clone())?;
        assert_eq!(stack, vec![vec![1]]);
        assert!(maximum_stack <= 1_000);

        let mut explicit_sighash_all = elements.clone();
        explicit_sighash_all[49].push(1);
        assert!(execute(&script, explicit_sighash_all).is_err());

        let mut explicit_sighash_none = elements.clone();
        explicit_sighash_none[50].push(2);
        assert!(execute(&script, explicit_sighash_none).is_err());

        let mut wrong_score = elements.clone();
        wrong_score[0] = encode_script_num(i64::from(hand.claimed_score() - 1));
        assert!(execute(&script, wrong_score).is_err());

        let mut wrong_preimage = elements.clone();
        wrong_preimage[1][0] ^= 1;
        assert!(execute(&script, wrong_preimage).is_err());

        let mut wrong_public_bit = elements.clone();
        wrong_public_bit[2] = if wrong_public_bit[2].is_empty() {
            vec![1]
        } else {
            Vec::new()
        };
        assert!(execute(&script, wrong_public_bit).is_err());

        let mut wrong_signature = elements.clone();
        wrong_signature[49][0] ^= 1;
        assert!(execute(&script, wrong_signature).is_err());

        let mut wrong_eval_proof = elements.clone();
        wrong_eval_proof[51] = encode_script_num(7);
        assert!(execute(&script, wrong_eval_proof).is_err());

        let mut wrong_subset = elements.clone();
        wrong_subset[67] = encode_script_num(21);
        assert!(execute(&script, wrong_subset).is_err());

        let mut wrong_opening = elements;
        wrong_opening
            .last_mut()
            .ok_or_else(|| std::io::Error::other("missing opening"))?[0] ^= 1;
        assert!(execute(&script, wrong_opening).is_err());
        Ok(())
    }

    #[test]
    fn showdown_script_rejects_duplicate_unselected_cards() -> Result<(), Box<dyn std::error::Error>>
    {
        let normal = showdown_fixture([0, 4, 8, 12, 16, 20, 24, 28, 32]);
        // Alice subset zero omits positions five and six (deal slots 7 and 8).
        // Make exactly those two cards equal while retaining valid commitments.
        let duplicate = showdown_fixture([0, 4, 8, 12, 16, 20, 24, 28, 28]);
        let chain_game_id = [12_u8; 32];
        let node_id = [13_u8; 32];
        let normal_hand = normal.hand(Role::Alice, 0)?;
        let duplicate_hand = ShowdownHandWitness::new(
            ALICE_SEVEN_SLOTS.map(|slot| {
                let index = usize::from(slot);
                CardOpeningWitness::new(
                    slot,
                    duplicate.preimages_a[index].clone(),
                    duplicate.preimages_b[index].clone(),
                )
            }),
            0,
            normal_hand.claimed_score(),
        );
        let (score_key, certificate) =
            score_material(chain_game_id, node_id, normal_hand.claimed_score())?;
        let secp = Secp256k1::new();
        let alice_keypair = bitcoin_keypair(&secp, 14)?;
        let bob_keypair = bitcoin_keypair(&secp, 15)?;
        let alice_signature = sign_sighash_default(&secp, &alice_keypair, TEST_SIGHASH);
        let bob_signature = sign_sighash_default(&secp, &bob_keypair, TEST_SIGHASH);
        let program = LeafProgram::AliceShowdown(AliceShowdownProgram::new(
            &duplicate.deal,
            chain_game_id,
            node_id,
            score_key,
            [
                alice_keypair.x_only_public_key().0.serialize(),
                bob_keypair.x_only_public_key().0.serialize(),
            ],
        )?);
        assert!(
            assemble_alice_showdown_witness_elements(
                &duplicate.deal,
                alice_signature,
                bob_signature,
                &duplicate_hand,
                &certificate,
            )
            .is_err()
        );

        // Build the valid proof for the unchanged selected five, then replace
        // only the opening pairs with the duplicate fixture. This bypasses the
        // native assembler and proves the serialized script independently
        // rejects duplicates hidden outside the selected subset.
        let mut raw_elements = assemble_alice_showdown_witness_elements(
            &normal.deal,
            alice_signature,
            bob_signature,
            &normal_hand,
            &certificate,
        )?;
        raw_elements.truncate(raw_elements.len() - 14);
        raw_elements.extend(opening_elements(&duplicate, Role::Alice));
        assert!(execute(&program.to_tapscript()?, raw_elements).is_err());
        Ok(())
    }

    #[test]
    fn every_bob_outcome_script_executes_and_wrong_branch_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = showdown_fixture([0, 4, 8, 12, 16, 20, 24, 28, 32]);
        let chain_game_id = [12_u8; 32];
        let alice_node_id = [13_u8; 32];
        let secp = Secp256k1::new();
        let alice_keypair = bitcoin_keypair(&secp, 14)?;
        let bob_keypair = bitcoin_keypair(&secp, 15)?;
        let authorizers = [
            alice_keypair.x_only_public_key().0.serialize(),
            bob_keypair.x_only_public_key().0.serialize(),
        ];
        let alice_signature = sign_sighash_default(&secp, &alice_keypair, TEST_SIGHASH);
        let bob_signature = sign_sighash_default(&secp, &bob_keypair, TEST_SIGHASH);

        for (index, (outcome, alice_subset, bob_subset, wrong_outcome)) in [
            (ShowdownOutcome::AliceWin, 20, 0, ShowdownOutcome::BobWin),
            (ShowdownOutcome::BobWin, 0, 20, ShowdownOutcome::AliceWin),
            (ShowdownOutcome::Split, 20, 20, ShowdownOutcome::BobWin),
        ]
        .into_iter()
        .enumerate()
        {
            let alice_hand = fixture.hand(Role::Alice, alice_subset)?;
            let bob_hand = fixture.hand(Role::Bob, bob_subset)?;
            let (score_key, certificate) =
                score_material(chain_game_id, alice_node_id, alice_hand.claimed_score())?;
            let terminal_node_id = [16 + u8::try_from(index)?; 32];
            let (bob_score_key, bob_certificate) =
                bob_score_material(chain_game_id, terminal_node_id, bob_hand.claimed_score())?;
            let program = LeafProgram::BobPayout(BobPayoutProgram::new(
                &fixture.deal,
                chain_game_id,
                terminal_node_id,
                alice_node_id,
                outcome,
                score_key.clone(),
                bob_score_key.clone(),
                authorizers,
            )?);
            let elements = assemble_bob_payout_witness_elements(
                &fixture.deal,
                outcome,
                alice_signature,
                bob_signature,
                &bob_hand,
                &certificate,
                &bob_certificate,
            )?;
            assert_eq!(elements.len(), 131);
            let (stack, maximum_stack) = execute(&program.to_tapscript()?, elements.clone())?;
            assert_eq!(stack, vec![vec![1]]);
            assert!(maximum_stack <= 1_000);

            let wrong_program = LeafProgram::BobPayout(BobPayoutProgram::new(
                &fixture.deal,
                chain_game_id,
                terminal_node_id,
                alice_node_id,
                wrong_outcome,
                score_key,
                bob_score_key,
                authorizers,
            )?);
            assert!(execute(&wrong_program.to_tapscript()?, elements.clone()).is_err());

            if index == 0 {
                let mut wrong_score_b = elements.clone();
                wrong_score_b[49] = encode_script_num(i64::from(bob_hand.claimed_score() - 1));
                assert!(execute(&program.to_tapscript()?, wrong_score_b).is_err());

                let mut wrong_live_signature = elements.clone();
                wrong_live_signature[99][0] ^= 1;
                assert!(execute(&program.to_tapscript()?, wrong_live_signature).is_err());

                let mut wrong_eval_proof = elements.clone();
                wrong_eval_proof[100] = encode_script_num(4);
                assert!(execute(&program.to_tapscript()?, wrong_eval_proof).is_err());

                let mut wrong_bob_certificate = elements.clone();
                wrong_bob_certificate[50][0] ^= 1;
                assert!(execute(&program.to_tapscript()?, wrong_bob_certificate).is_err());

                let mut wrong_opening = elements;
                wrong_opening
                    .last_mut()
                    .ok_or_else(|| std::io::Error::other("missing opening"))?[0] ^= 1;
                assert!(execute(&program.to_tapscript()?, wrong_opening).is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn bob_score_certificate_blocks_weaker_valid_subset_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = showdown_fixture([0, 4, 8, 12, 16, 20, 24, 28, 32]);
        let chain_game_id = [42_u8; 32];
        let alice_node_id = [43_u8; 32];
        let bob_node_id = [44_u8; 32];
        let alice_hand = fixture.hand(Role::Alice, 20)?;
        let mut bob_hands = (0..21)
            .map(|subset| fixture.hand(Role::Bob, subset))
            .collect::<Result<Vec<_>, _>>()?;
        bob_hands.retain(|hand| hand.claimed_score() < alice_hand.claimed_score());
        bob_hands.sort_unstable_by_key(ShowdownHandWitness::claimed_score);
        let weaker_hand = bob_hands
            .first()
            .ok_or_else(|| std::io::Error::other("fixture lacks a weak Bob hand"))?;
        let authorized_hand = bob_hands
            .last()
            .ok_or_else(|| std::io::Error::other("fixture lacks an authorized Bob hand"))?;
        assert!(weaker_hand.claimed_score() < authorized_hand.claimed_score());

        let (alice_score_key, alice_certificate) =
            score_material(chain_game_id, alice_node_id, alice_hand.claimed_score())?;
        let (bob_score_key, bob_certificate) =
            bob_score_material(chain_game_id, bob_node_id, authorized_hand.claimed_score())?;
        let secp = Secp256k1::new();
        let alice_keypair = bitcoin_keypair(&secp, 45)?;
        let bob_keypair = bitcoin_keypair(&secp, 46)?;
        let alice_signature = sign_sighash_default(&secp, &alice_keypair, TEST_SIGHASH);
        let bob_signature = sign_sighash_default(&secp, &bob_keypair, TEST_SIGHASH);
        let program = LeafProgram::BobPayout(BobPayoutProgram::new(
            &fixture.deal,
            chain_game_id,
            bob_node_id,
            alice_node_id,
            ShowdownOutcome::AliceWin,
            alice_score_key,
            bob_score_key,
            [
                alice_keypair.x_only_public_key().0.serialize(),
                bob_keypair.x_only_public_key().0.serialize(),
            ],
        )?);
        let script = program.to_tapscript()?;
        let elements = assemble_bob_payout_witness_elements(
            &fixture.deal,
            ShowdownOutcome::AliceWin,
            alice_signature,
            bob_signature,
            authorized_hand,
            &alice_certificate,
            &bob_certificate,
        )?;
        assert_eq!(elements.len(), super::BOB_PAYOUT_WITNESS_ELEMENTS);
        assert!(script.len() <= super::MAX_CONSENSUS_SCRIPT_BYTES);
        let (_, maximum_stack) = execute(&script, elements.clone())?;
        assert!(maximum_stack <= 1_000);

        assert!(matches!(
            assemble_bob_payout_witness_elements(
                &fixture.deal,
                ShowdownOutcome::AliceWin,
                alice_signature,
                bob_signature,
                weaker_hand,
                &alice_certificate,
                &bob_certificate,
            ),
            Err(BitcoinBackendError::BobCertificateMismatch { .. })
        ));

        // Bypass the native assembler and substitute a fully valid but weaker
        // evaluator proof and subset while retaining Bob's authorized score.
        // The serialized script must independently reject the malleation.
        let verified_weaker = crate::verify_showdown_hand(&fixture.deal, Role::Bob, weaker_hand)?;
        let mut replaced = elements;
        replaced.truncate(2 * super::SCORE_CERTIFICATE_WITNESS_ELEMENTS + 2);
        super::append_hand_elements(&mut replaced, weaker_hand, verified_weaker.selected())?;
        assert_eq!(replaced.len(), super::BOB_PAYOUT_WITNESS_ELEMENTS);
        assert!(execute(&script, replaced).is_err());
        Ok(())
    }

    #[test]
    fn all_twenty_one_subset_branches_match_native_selection()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = showdown_fixture([0, 4, 8, 12, 16, 20, 24, 28, 32]);
        let chain_game_id = [12_u8; 32];
        let alice_node_id = [13_u8; 32];
        let score_key = lamport_key(
            chain_game_id,
            alice_node_id,
            LamportPurpose::AliceScore24Bit,
        )?;
        let secp = Secp256k1::new();
        let alice_keypair = bitcoin_keypair(&secp, 14)?;
        let bob_keypair = bitcoin_keypair(&secp, 15)?;
        let authorizers = [
            alice_keypair.x_only_public_key().0.serialize(),
            bob_keypair.x_only_public_key().0.serialize(),
        ];
        let alice_signature = sign_sighash_default(&secp, &alice_keypair, TEST_SIGHASH);
        let bob_signature = sign_sighash_default(&secp, &bob_keypair, TEST_SIGHASH);
        let alice_program = LeafProgram::AliceShowdown(AliceShowdownProgram::new(
            &fixture.deal,
            chain_game_id,
            alice_node_id,
            score_key.clone(),
            authorizers,
        )?);
        let bob_program = LeafProgram::BobPayout(BobPayoutProgram::new(
            &fixture.deal,
            chain_game_id,
            [16_u8; 32],
            alice_node_id,
            ShowdownOutcome::Split,
            score_key,
            lamport_key(chain_game_id, [16_u8; 32], LamportPurpose::BobScore24Bit)?,
            authorizers,
        )?);
        let alice_script = alice_program.to_tapscript()?;
        let bob_script = bob_program.to_tapscript()?;

        for subset_id in 0..21 {
            let alice_hand = fixture.hand(Role::Alice, subset_id)?;
            let (_, alice_certificate) =
                score_material(chain_game_id, alice_node_id, alice_hand.claimed_score())?;
            let alice_elements = assemble_alice_showdown_witness_elements(
                &fixture.deal,
                alice_signature,
                bob_signature,
                &alice_hand,
                &alice_certificate,
            )?;
            assert_eq!(execute(&alice_script, alice_elements)?.0, vec![vec![1]]);

            let bob_hand = fixture.hand(Role::Bob, subset_id)?;
            let (_, equal_certificate) =
                score_material(chain_game_id, alice_node_id, bob_hand.claimed_score())?;
            let (_, bob_certificate) =
                bob_score_material(chain_game_id, [16_u8; 32], bob_hand.claimed_score())?;
            let bob_elements = assemble_bob_payout_witness_elements(
                &fixture.deal,
                ShowdownOutcome::Split,
                alice_signature,
                bob_signature,
                &bob_hand,
                &equal_certificate,
                &bob_certificate,
            )?;
            assert_eq!(execute(&bob_script, bob_elements)?.0, vec![vec![1]]);
        }
        Ok(())
    }

    #[test]
    fn full_alice_leaf_executes_every_hand_category() -> Result<(), Box<dyn std::error::Error>> {
        let hands = [
            [
                card(12, 3),
                card(11, 3),
                card(10, 3),
                card(9, 3),
                card(8, 3),
            ],
            [card(9, 0), card(9, 1), card(9, 2), card(9, 3), card(12, 0)],
            [card(9, 0), card(9, 1), card(9, 2), card(4, 0), card(4, 1)],
            [card(12, 2), card(9, 2), card(7, 2), card(4, 2), card(1, 2)],
            [card(8, 0), card(7, 1), card(6, 2), card(5, 3), card(4, 0)],
            [card(9, 0), card(9, 1), card(9, 2), card(12, 0), card(4, 1)],
            [card(9, 0), card(9, 1), card(4, 2), card(4, 3), card(12, 0)],
            [card(9, 0), card(9, 1), card(12, 2), card(7, 3), card(3, 0)],
            [card(12, 0), card(10, 1), card(7, 2), card(4, 3), card(1, 0)],
            [card(12, 0), card(0, 1), card(1, 2), card(2, 3), card(3, 0)],
        ];
        let chain_game_id = [12_u8; 32];
        let alice_node_id = [13_u8; 32];
        let score_key = lamport_key(
            chain_game_id,
            alice_node_id,
            LamportPurpose::AliceScore24Bit,
        )?;
        let secp = Secp256k1::new();
        let alice_keypair = bitcoin_keypair(&secp, 14)?;
        let bob_keypair = bitcoin_keypair(&secp, 15)?;
        let authorizers = [
            alice_keypair.x_only_public_key().0.serialize(),
            bob_keypair.x_only_public_key().0.serialize(),
        ];
        let alice_signature = sign_sighash_default(&secp, &alice_keypair, TEST_SIGHASH);
        let bob_signature = sign_sighash_default(&secp, &bob_keypair, TEST_SIGHASH);

        for selected in hands {
            let fixture = fixture_with_alice_selected(selected)?;
            let hand = fixture.hand(Role::Alice, 0)?;
            let (_, certificate) =
                score_material(chain_game_id, alice_node_id, hand.claimed_score())?;
            let program = LeafProgram::AliceShowdown(AliceShowdownProgram::new(
                &fixture.deal,
                chain_game_id,
                alice_node_id,
                score_key.clone(),
                authorizers,
            )?);
            let elements = assemble_alice_showdown_witness_elements(
                &fixture.deal,
                alice_signature,
                bob_signature,
                &hand,
                &certificate,
            )?;
            assert_eq!(
                execute(&program.to_tapscript()?, elements)?.0,
                vec![vec![1]]
            );
        }
        Ok(())
    }

    #[test]
    fn showdown_programs_compile_as_complete_bounded_leaves()
    -> Result<(), Box<dyn std::error::Error>> {
        let accepted = deal();
        let chain_game_id = [12_u8; 32];
        let node_id = [13_u8; 32];
        let score_key = lamport_key(chain_game_id, node_id, LamportPurpose::AliceScore24Bit)?;
        let authorizers = [xonly_key(14)?, xonly_key(15)?];
        let alice = LeafProgram::AliceShowdown(AliceShowdownProgram::new(
            &accepted,
            chain_game_id,
            node_id,
            score_key.clone(),
            authorizers,
        )?);
        let bob = LeafProgram::BobPayout(BobPayoutProgram::new(
            &accepted,
            chain_game_id,
            [16_u8; 32],
            node_id,
            ShowdownOutcome::BobWin,
            score_key,
            lamport_key(chain_game_id, [16_u8; 32], LamportPurpose::BobScore24Bit)?,
            authorizers,
        )?);
        assert!(matches!(
            BobPayoutProgram::new(
                &accepted,
                chain_game_id,
                [16_u8; 32],
                [17_u8; 32],
                ShowdownOutcome::BobWin,
                lamport_key_for_context(chain_game_id, node_id, LamportPurpose::AliceScore24Bit,)?,
                lamport_key(chain_game_id, [16_u8; 32], LamportPurpose::BobScore24Bit,)?,
                authorizers,
            ),
            Err(BitcoinBackendError::Lamport(
                bp52_lamport::LamportError::WrongNode
            ))
        ));
        assert_ne!(alice.predicate_id(), bob.predicate_id());
        let alice_script = alice.to_tapscript()?;
        let bob_script = bob.to_tapscript()?;
        assert!(alice_script.len() <= super::MAX_CONSENSUS_SCRIPT_BYTES);
        assert!(bob_script.len() <= super::MAX_CONSENSUS_SCRIPT_BYTES);
        assert_eq!(alice.expected_witness_elements()?, 82);
        assert_eq!(bob.expected_witness_elements()?, 131);
        let secp = Secp256k1::verification_only();
        let state = CompiledTaprootState::compile(&secp, [0x5d_u8; 32], &[alice, bob])?;
        assert_eq!(state.leaves().len(), 2);
        Ok(())
    }
}
