//! Structured runtime witnesses and their strict bounded wire codec.

use bitcoin::script::read_scriptint_non_minimal;
use bp52_chain_bitcoin::{
    ALICE_SEVEN_SLOTS, AliceScoreCertificate, BOB_SEVEN_SLOTS, CardOpeningWitness,
    DEFAULT_SIGHASH_SIGNATURE_BYTES, DefaultSighashSignature, MAX_WITNESS_ELEMENT_BYTES,
    RevealPattern, ShowdownHandWitness, assemble_alice_showdown_witness_elements,
    assemble_bob_payout_witness_elements, assemble_timeout_witness_elements,
};
use bp52_chain_types::AcceptedDeal;
use bp52_chain_types::{
    Action, EdgeKind, NodeId, Phase, Role, ShowdownOutcome, Street, TimeoutKind,
};
use bp52_lamport::{BobScoreCertificate, LamportPurpose, LamportSignature, Score24};
use bp52_poker::{HandCategory, HandScore};

use crate::builders::validate_witness_semantics;
use crate::{ChainBackend, RuntimeError, ValidatedEdge};

const MAGIC: &[u8; 8] = b"BP52WIT4";
const ACTION_TAG: u8 = 0;
const REVEAL_TAG: u8 = 1;
const ALICE_SHOWDOWN_TAG: u8 = 2;
const BOB_PAYOUT_TAG: u8 = 3;
const TIMEOUT_TAG: u8 = 4;
const ADVANCE_TAG: u8 = 5;
const SIGNATURE_BYTES: usize = DEFAULT_SIGHASH_SIGNATURE_BYTES;
const LAMPORT_ELEMENT_BYTES: usize = 32;
const SCORE_SIGNATURE_ELEMENTS: usize = 24;
const SCORE_CERTIFICATE_STACK_ELEMENTS: usize = 1 + 2 * SCORE_SIGNATURE_ELEMENTS;
const ALICE_SHOWDOWN_STACK_ELEMENTS: usize = 82;
const BOB_PAYOUT_STACK_ELEMENTS: usize = 131;

/// Maximum canonical runtime-witness frame accepted by the decoder.
pub const MAX_ENCODED_WITNESS_BYTES: usize = 8_192;

/// Complete semantic witness for one fixed graph edge.
///
/// Each variant carries explicit game and endpoint bindings. The transaction
/// identifiers remain stable because this data is attached only as witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Witness {
    /// A witness-free logical progression authorized by both fixed signatures.
    Advance {
        /// Exact compiled game identifier.
        chain_game_id: [u8; 32],
        /// State output being spent.
        node_id: NodeId,
        /// Fixed child template entering `phase`.
        child_node_id: NodeId,
        /// Exact destination phase specialized into the edge.
        phase: Phase,
        /// Alice's fixed `SIGHASH_DEFAULT` preauthorization.
        alice_signature: DefaultSighashSignature,
        /// Bob's fixed `SIGHASH_DEFAULT` preauthorization.
        bob_signature: DefaultSighashSignature,
    },
    /// The opponent's preauthorization plus the actor's live authorization.
    Action {
        /// Exact compiled game identifier.
        chain_game_id: [u8; 32],
        /// State output being spent.
        node_id: NodeId,
        /// Specialized child template.
        child_node_id: NodeId,
        /// Fixed-limit action encoded by that child.
        action: Action,
        /// Alice's fixed or live `SIGHASH_DEFAULT` authorization.
        alice_signature: DefaultSighashSignature,
        /// Bob's fixed or live `SIGHASH_DEFAULT` authorization.
        bob_signature: DefaultSighashSignature,
    },
    /// Two preauthorizations plus committed share openings.
    Reveal {
        /// Exact compiled game identifier.
        chain_game_id: [u8; 32],
        /// State output being spent.
        node_id: NodeId,
        /// Specialized child template.
        child_node_id: NodeId,
        /// Fixed reveal phase and revealer.
        pattern: RevealPattern,
        /// Alice's fixed `SIGHASH_DEFAULT` preauthorization.
        alice_signature: DefaultSighashSignature,
        /// Bob's fixed `SIGHASH_DEFAULT` preauthorization.
        bob_signature: DefaultSighashSignature,
        /// Preimages in the pattern's fixed slot order.
        preimages: Vec<Vec<u8>>,
    },
    /// Alice's seven-card claim and one score certificate.
    AliceShowdown {
        /// Exact compiled game identifier.
        chain_game_id: [u8; 32],
        /// Alice-showdown state output being spent.
        node_id: NodeId,
        /// Bob-terminal child template.
        child_node_id: NodeId,
        /// Alice's fixed `SIGHASH_DEFAULT` preauthorization.
        alice_signature: DefaultSighashSignature,
        /// Bob's fixed `SIGHASH_DEFAULT` preauthorization.
        bob_signature: DefaultSighashSignature,
        /// Exact seven openings, unsigned subset, and score.
        hand: ShowdownHandWitness,
        /// Alice's score and 24-bit OTS signature.
        certificate: AliceScoreCertificate,
    },
    /// Bob's hand, both score certificates, and live payout authorization.
    BobPayout {
        /// Exact compiled game identifier.
        chain_game_id: [u8; 32],
        /// Bob-terminal state output being spent.
        node_id: NodeId,
        /// Selected branch-specific terminal child.
        child_node_id: NodeId,
        /// Alice-showdown node whose score key verifies the certificate.
        alice_showdown_node_id: NodeId,
        /// Outcome specialized into the terminal template.
        outcome: ShowdownOutcome,
        /// Alice's fixed `SIGHASH_DEFAULT` preauthorization.
        alice_signature: DefaultSighashSignature,
        /// Bob's live `SIGHASH_DEFAULT` authorization.
        bob_signature: DefaultSighashSignature,
        /// Bob's exact seven openings and unsigned subset; the score is certificate-bound below.
        hand: ShowdownHandWitness,
        /// Alice's certificate repeated from the parent witness.
        alice_certificate: AliceScoreCertificate,
        /// Bob's score and 24-bit OTS signature bound to this terminal node.
        bob_certificate: BobScoreCertificate,
    },
    /// Opponent preauthorization plus the beneficiary's live signature after CSV.
    Timeout {
        /// Exact compiled game identifier.
        chain_game_id: [u8; 32],
        /// Timed state output being spent.
        node_id: NodeId,
        /// Deterministic timeout settlement child.
        child_node_id: NodeId,
        /// Timeout class specialized into the edge.
        kind: TimeoutKind,
        /// Nondefaulting player authorized by the leaf.
        beneficiary: Role,
        /// Alice's fixed or live `SIGHASH_DEFAULT` authorization.
        alice_signature: DefaultSighashSignature,
        /// Bob's fixed or live `SIGHASH_DEFAULT` authorization.
        bob_signature: DefaultSighashSignature,
    },
}

impl Witness {
    /// Return the transaction signature carried for one participant.
    ///
    /// This accessor lets a public coordinator revalidate a CHAIN-authorized
    /// witness without retaining a second copy of the complete setup bundle.
    #[must_use]
    pub const fn bitcoin_signature(&self, role: Role) -> DefaultSighashSignature {
        let (alice, bob) = match self {
            Self::Advance {
                alice_signature,
                bob_signature,
                ..
            }
            | Self::Action {
                alice_signature,
                bob_signature,
                ..
            }
            | Self::Reveal {
                alice_signature,
                bob_signature,
                ..
            }
            | Self::AliceShowdown {
                alice_signature,
                bob_signature,
                ..
            }
            | Self::BobPayout {
                alice_signature,
                bob_signature,
                ..
            }
            | Self::Timeout {
                alice_signature,
                bob_signature,
                ..
            } => (*alice_signature, *bob_signature),
        };
        match role {
            Role::Alice => alice,
            Role::Bob => bob,
        }
    }

    /// Return the compiled game identifier.
    #[must_use]
    pub const fn chain_game_id(&self) -> [u8; 32] {
        match self {
            Self::Advance { chain_game_id, .. }
            | Self::Action { chain_game_id, .. }
            | Self::Reveal { chain_game_id, .. }
            | Self::AliceShowdown { chain_game_id, .. }
            | Self::BobPayout { chain_game_id, .. }
            | Self::Timeout { chain_game_id, .. } => *chain_game_id,
        }
    }

    /// Return the state output consumed by this witness.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        match self {
            Self::Advance { node_id, .. }
            | Self::Action { node_id, .. }
            | Self::Reveal { node_id, .. }
            | Self::AliceShowdown { node_id, .. }
            | Self::BobPayout { node_id, .. }
            | Self::Timeout { node_id, .. } => *node_id,
        }
    }

    /// Return the fixed child template selected by this witness.
    #[must_use]
    pub const fn child_node_id(&self) -> NodeId {
        match self {
            Self::Advance { child_node_id, .. }
            | Self::Action { child_node_id, .. }
            | Self::Reveal { child_node_id, .. }
            | Self::AliceShowdown { child_node_id, .. }
            | Self::BobPayout { child_node_id, .. }
            | Self::Timeout { child_node_id, .. } => *child_node_id,
        }
    }

    /// Return the exact logical edge kind selected by this witness.
    #[must_use]
    pub const fn edge_kind(&self) -> EdgeKind {
        match self {
            Self::Advance { phase, .. } => EdgeKind::Advance { phase: *phase },
            Self::Action { action, .. } => EdgeKind::Action(*action),
            Self::Reveal { pattern, .. } => reveal_edge_kind(*pattern),
            Self::AliceShowdown { .. } => EdgeKind::AliceShowdown,
            Self::BobPayout { outcome, .. } => EdgeKind::BobPayout(*outcome),
            Self::Timeout { kind, .. } => EdgeKind::Timeout(*kind),
        }
    }

    /// Return ordinary stack elements before tapscript and control block.
    ///
    /// Elements use the canonical Alice-then-Bob signature order, fixed slot
    /// order, and most-significant-first Lamport order.
    ///
    /// # Errors
    ///
    /// Rejects a showdown hand, score certificate, or outcome that cannot be
    /// represented by the authoritative consensus-program witness assembler.
    pub fn to_witness_elements(&self, deal: &AcceptedDeal) -> Result<Vec<Vec<u8>>, RuntimeError> {
        match self {
            Self::Advance {
                alice_signature,
                bob_signature,
                ..
            }
            | Self::Action {
                alice_signature,
                bob_signature,
                ..
            } => Ok(signature_pair(*alice_signature, *bob_signature)),
            Self::Reveal {
                alice_signature,
                bob_signature,
                preimages,
                ..
            } => {
                let mut elements = signature_pair(*alice_signature, *bob_signature);
                elements.extend(preimages.iter().cloned());
                Ok(elements)
            }
            Self::AliceShowdown {
                alice_signature,
                bob_signature,
                hand,
                certificate,
                ..
            } => Ok(assemble_alice_showdown_witness_elements(
                deal,
                *alice_signature,
                *bob_signature,
                hand,
                certificate,
            )?),
            Self::BobPayout {
                alice_signature,
                bob_signature,
                outcome,
                hand,
                alice_certificate,
                bob_certificate,
                ..
            } => Ok(assemble_bob_payout_witness_elements(
                deal,
                *outcome,
                *alice_signature,
                *bob_signature,
                hand,
                alice_certificate,
                bob_certificate,
            )?),
            Self::Timeout {
                alice_signature,
                bob_signature,
                ..
            } => Ok(assemble_timeout_witness_elements(
                *alice_signature,
                *bob_signature,
            )),
        }
    }

    /// Encode one canonical bounded runtime frame without truncating any
    /// caller-constructible field.
    ///
    /// # Errors
    ///
    /// Rejects zero identifiers, invalid reveal counts or preimage lengths,
    /// noncanonical showdown slots/subsets/scores, inconsistent Alice score
    /// fields, and frames exceeding [`MAX_ENCODED_WITNESS_BYTES`].
    #[allow(clippy::too_many_lines)]
    pub fn encode(&self) -> Result<Vec<u8>, RuntimeError> {
        validate_nonzero_id(self.chain_game_id(), "zero chain game identifier")?;
        validate_nonzero_id(self.node_id(), "zero parent node identifier")?;
        validate_nonzero_id(self.child_node_id(), "zero child node identifier")?;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(MAGIC);
        encoded.push(self.tag());
        encoded.extend_from_slice(&self.chain_game_id());
        encoded.extend_from_slice(&self.node_id());
        encoded.extend_from_slice(&self.child_node_id());
        match self {
            Self::Advance {
                phase,
                alice_signature,
                bob_signature,
                ..
            } => {
                encoded.push(phase.code());
                append_signature(&mut encoded, *alice_signature);
                append_signature(&mut encoded, *bob_signature);
            }
            Self::Action {
                action,
                alice_signature,
                bob_signature,
                ..
            } => {
                encoded.push(action.code());
                append_signature(&mut encoded, *alice_signature);
                append_signature(&mut encoded, *bob_signature);
            }
            Self::Reveal {
                pattern,
                alice_signature,
                bob_signature,
                preimages,
                ..
            } => {
                if preimages.len() != pattern.slots().len() {
                    return Err(codec_error("wrong reveal preimage count"));
                }
                encoded.push(pattern.code());
                append_signature(&mut encoded, *alice_signature);
                append_signature(&mut encoded, *bob_signature);
                encoded.push(
                    u8::try_from(preimages.len())
                        .map_err(|_| codec_error("reveal preimage count exceeds u8"))?,
                );
                for preimage in preimages {
                    append_preimage(&mut encoded, preimage)?;
                }
            }
            Self::AliceShowdown {
                alice_signature,
                bob_signature,
                hand,
                certificate,
                ..
            } => {
                validate_hand_slots(hand, bp52_chain_bitcoin::ALICE_SEVEN_SLOTS)?;
                if certificate.score_a().get() != hand.claimed_score() {
                    return Err(codec_error("Alice hand and certificate scores differ"));
                }
                append_signature(&mut encoded, *alice_signature);
                append_signature(&mut encoded, *bob_signature);
                append_hand(&mut encoded, hand)?;
                append_score(&mut encoded, certificate.score_a().get())?;
                append_raw_lamport(&mut encoded, certificate.lamport_signature());
            }
            Self::BobPayout {
                alice_showdown_node_id,
                outcome,
                alice_signature,
                bob_signature,
                hand,
                alice_certificate,
                bob_certificate,
                ..
            } => {
                validate_nonzero_id(
                    *alice_showdown_node_id,
                    "zero Alice showdown node identifier",
                )?;
                validate_hand_slots(hand, bp52_chain_bitcoin::BOB_SEVEN_SLOTS)?;
                encoded.extend_from_slice(alice_showdown_node_id);
                encoded.push(outcome.code());
                append_signature(&mut encoded, *alice_signature);
                append_signature(&mut encoded, *bob_signature);
                append_hand(&mut encoded, hand)?;
                append_score(&mut encoded, alice_certificate.score_a().get())?;
                append_raw_lamport(&mut encoded, alice_certificate.lamport_signature());
                if bob_certificate.score_b().get() != hand.claimed_score() {
                    return Err(codec_error("Bob hand and certificate scores differ"));
                }
                append_score(&mut encoded, bob_certificate.score_b().get())?;
                append_raw_lamport(&mut encoded, bob_certificate.lamport_signature());
            }
            Self::Timeout {
                kind,
                beneficiary,
                alice_signature,
                bob_signature,
                ..
            } => {
                encoded.push(kind.code());
                encoded.push(beneficiary.code());
                append_signature(&mut encoded, *alice_signature);
                append_signature(&mut encoded, *bob_signature);
            }
        }
        if encoded.len() > MAX_ENCODED_WITNESS_BYTES {
            return Err(RuntimeError::WitnessTooLarge {
                actual: encoded.len(),
                maximum: MAX_ENCODED_WITNESS_BYTES,
            });
        }
        Ok(encoded)
    }

    /// Decode one strict canonical bounded runtime frame.
    ///
    /// # Errors
    ///
    /// Rejects unknown tags/codes, invalid signature encodings, wrong fixed
    /// widths, bad preimage bounds, zero identifiers, truncation, and trailing
    /// bytes.
    pub fn decode(encoded: &[u8]) -> Result<Self, RuntimeError> {
        if encoded.len() > MAX_ENCODED_WITNESS_BYTES {
            return Err(RuntimeError::WitnessTooLarge {
                actual: encoded.len(),
                maximum: MAX_ENCODED_WITNESS_BYTES,
            });
        }
        let mut reader = Reader::new(encoded);
        if reader.array::<8>()? != *MAGIC {
            return Err(codec_error("wrong runtime witness magic"));
        }
        let tag = reader.byte()?;
        let chain_game_id = reader.nonzero_id("zero chain game identifier")?;
        let node_id = reader.nonzero_id("zero parent node identifier")?;
        let child_node_id = reader.nonzero_id("zero child node identifier")?;
        let witness = match tag {
            ACTION_TAG => decode_action(&mut reader, chain_game_id, node_id, child_node_id)?,
            REVEAL_TAG => decode_reveal(&mut reader, chain_game_id, node_id, child_node_id)?,
            ALICE_SHOWDOWN_TAG => {
                decode_alice_showdown(&mut reader, chain_game_id, node_id, child_node_id)?
            }
            BOB_PAYOUT_TAG => {
                decode_bob_payout(&mut reader, chain_game_id, node_id, child_node_id)?
            }
            TIMEOUT_TAG => decode_timeout(&mut reader, chain_game_id, node_id, child_node_id)?,
            ADVANCE_TAG => decode_advance(&mut reader, chain_game_id, node_id, child_node_id)?,
            _ => return Err(codec_error("unknown runtime witness tag")),
        };
        if !reader.is_finished() {
            return Err(codec_error("trailing runtime witness bytes"));
        }
        if witness.encode()? != encoded {
            return Err(codec_error("noncanonical runtime witness encoding"));
        }
        Ok(witness)
    }

    const fn tag(&self) -> u8 {
        match self {
            Self::Advance { .. } => ADVANCE_TAG,
            Self::Action { .. } => ACTION_TAG,
            Self::Reveal { .. } => REVEAL_TAG,
            Self::AliceShowdown { .. } => ALICE_SHOWDOWN_TAG,
            Self::BobPayout { .. } => BOB_PAYOUT_TAG,
            Self::Timeout { .. } => TIMEOUT_TAG,
        }
    }
}

/// Recover and fully validate semantic data from an exact confirmed
/// script-path witness.
///
/// Locally built witnesses use one canonical byte representation. Confirmed
/// peer witnesses may use consensus-equivalent, non-minimal Script-number
/// encodings for showdown score, evaluator, and subset fields. Recovery
/// therefore compares those numeric fields by value while requiring every
/// signature, Lamport preimage/bit, reveal/card preimage, tapscript, and
/// control block byte-for-byte.
pub(crate) fn recover_confirmed_witness(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    observed: &bitcoin::Witness,
) -> Result<Witness, RuntimeError> {
    let leaf = match edge.edge.kind {
        EdgeKind::AliceShowdown | EdgeKind::BobPayout(_) => [
            HandCategory::HighCard,
            HandCategory::OnePair,
            HandCategory::TwoPair,
            HandCategory::ThreeOfAKind,
            HandCategory::Straight,
            HandCategory::Flush,
            HandCategory::FullHouse,
            HandCategory::FourOfAKind,
            HandCategory::StraightFlush,
        ]
        .into_iter()
        .filter_map(|category| {
            graph.showdown_tap_leaf(edge.parent.node_id, edge.child.node_id, category)
        })
        .find(|leaf| {
            let stack: Vec<&[u8]> = observed.iter().collect();
            stack.len() == leaf.expected_witness_elements() + 2
                && stack[leaf.expected_witness_elements()] == leaf.script().as_bytes()
                && stack[leaf.expected_witness_elements() + 1] == leaf.control_block()
        })
        .ok_or(RuntimeError::InconsistentGraph {
            reason: "confirmed showdown uses no compiled category leaf",
        })?,
        _ => graph
            .tap_leaf(edge.parent.node_id, edge.child.node_id)
            .ok_or(RuntimeError::InconsistentGraph {
                reason: "confirmed edge has no compiled Taproot leaf",
            })?,
    };
    let ordinary_count = leaf.expected_witness_elements();
    let expected_count = ordinary_count
        .checked_add(2)
        .ok_or(codec_error("confirmed witness element count overflow"))?;
    if observed.len() != expected_count {
        return Err(codec_error("confirmed witness has wrong element count"));
    }
    let stack: Vec<&[u8]> = observed.iter().collect();
    if stack[ordinary_count] != leaf.script().as_bytes()
        || stack[ordinary_count + 1] != leaf.control_block()
    {
        return Err(codec_error(
            "confirmed witness has the wrong tapscript or control block",
        ));
    }
    if stack[..ordinary_count]
        .iter()
        .any(|element| element.len() > MAX_WITNESS_ELEMENT_BYTES)
    {
        return Err(codec_error(
            "confirmed ordinary witness element exceeds 520 bytes",
        ));
    }
    let ordinary = &stack[..ordinary_count];
    let recovered = match edge.edge.kind {
        EdgeKind::Advance { phase } => recover_advance(graph, edge, phase, ordinary)?,
        EdgeKind::Action(action) => recover_action(graph, edge, action, ordinary)?,
        EdgeKind::HoleCardReveal { revealer } => {
            let pattern = match revealer {
                Role::Alice => RevealPattern::DealBob,
                Role::Bob => RevealPattern::DealAlice,
            };
            recover_reveal(graph, edge, pattern, ordinary)?
        }
        EdgeKind::CommunityReveal { street, revealer } => {
            let pattern = match street {
                Street::Flop => RevealPattern::Flop(revealer),
                Street::Turn => RevealPattern::Turn(revealer),
                Street::River => RevealPattern::River(revealer),
                Street::Preflop => {
                    return Err(codec_error("preflop cannot be a community reveal"));
                }
            };
            recover_reveal(graph, edge, pattern, ordinary)?
        }
        EdgeKind::AliceShowdown => recover_alice_showdown(graph, edge, ordinary)?,
        EdgeKind::BobPayout(outcome) => recover_bob_payout(graph, edge, outcome, ordinary)?,
        EdgeKind::Timeout(kind) => recover_timeout(graph, edge, kind, ordinary)?,
    };

    let validated = validate_witness_semantics(graph, &recovered)?;
    if validated.parent.node_id != edge.parent.node_id
        || validated.child.node_id != edge.child.node_id
        || validated.edge.kind != edge.edge.kind
    {
        return Err(RuntimeError::InconsistentGraph {
            reason: "recovered witness resolves to another graph edge",
        });
    }
    let canonical = recovered.to_witness_elements(graph.accepted_deal())?;
    compare_confirmed_elements(edge.edge.kind, ordinary, &canonical)?;
    Ok(recovered)
}

fn recover_advance(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    phase: Phase,
    elements: &[&[u8]],
) -> Result<Witness, RuntimeError> {
    require_stack_len(elements, 2)?;
    Ok(Witness::Advance {
        chain_game_id: graph.chain_game_id(),
        node_id: edge.parent.node_id,
        child_node_id: edge.child.node_id,
        phase,
        alice_signature: bitcoin_signature_element(elements, 0)?,
        bob_signature: bitcoin_signature_element(elements, 1)?,
    })
}

fn recover_action(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    action: Action,
    elements: &[&[u8]],
) -> Result<Witness, RuntimeError> {
    require_stack_len(elements, 2)?;
    Ok(Witness::Action {
        chain_game_id: graph.chain_game_id(),
        node_id: edge.parent.node_id,
        child_node_id: edge.child.node_id,
        action,
        alice_signature: bitcoin_signature_element(elements, 0)?,
        bob_signature: bitcoin_signature_element(elements, 1)?,
    })
}

fn recover_reveal(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    pattern: RevealPattern,
    elements: &[&[u8]],
) -> Result<Witness, RuntimeError> {
    require_stack_len(elements, 2 + pattern.slots().len())?;
    let preimages = elements[2..]
        .iter()
        .map(|element| bounded_preimage(element))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Witness::Reveal {
        chain_game_id: graph.chain_game_id(),
        node_id: edge.parent.node_id,
        child_node_id: edge.child.node_id,
        pattern,
        alice_signature: bitcoin_signature_element(elements, 0)?,
        bob_signature: bitcoin_signature_element(elements, 1)?,
        preimages,
    })
}

fn recover_alice_showdown(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    elements: &[&[u8]],
) -> Result<Witness, RuntimeError> {
    require_stack_len(elements, ALICE_SHOWDOWN_STACK_ELEMENTS)?;
    let score = score_element(elements, 0)?;
    let certificate = recover_alice_score_certificate(elements, 0, score)?;
    let hand = recover_showdown_hand(elements, ALICE_SEVEN_SLOTS, 67, 68, score)?;
    Ok(Witness::AliceShowdown {
        chain_game_id: graph.chain_game_id(),
        node_id: edge.parent.node_id,
        child_node_id: edge.child.node_id,
        alice_signature: bitcoin_signature_element(elements, 49)?,
        bob_signature: bitcoin_signature_element(elements, 50)?,
        hand,
        certificate,
    })
}

fn recover_bob_payout(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    outcome: ShowdownOutcome,
    elements: &[&[u8]],
) -> Result<Witness, RuntimeError> {
    require_stack_len(elements, BOB_PAYOUT_STACK_ELEMENTS)?;
    let score_a = score_element(elements, 0)?;
    let score_b = score_element(elements, SCORE_CERTIFICATE_STACK_ELEMENTS)?;
    let alice_certificate = recover_alice_score_certificate(elements, 0, score_a)?;
    let bob_certificate =
        recover_bob_score_certificate(elements, SCORE_CERTIFICATE_STACK_ELEMENTS, score_b)?;
    let hand = recover_showdown_hand(elements, BOB_SEVEN_SLOTS, 116, 117, score_b)?;
    let alice_showdown_node_id =
        edge.parent
            .parent_node_id
            .ok_or(RuntimeError::InconsistentGraph {
                reason: "Bob payout parent has no Alice-showdown parent",
            })?;
    Ok(Witness::BobPayout {
        chain_game_id: graph.chain_game_id(),
        node_id: edge.parent.node_id,
        child_node_id: edge.child.node_id,
        alice_showdown_node_id,
        outcome,
        alice_signature: bitcoin_signature_element(elements, 98)?,
        bob_signature: bitcoin_signature_element(elements, 99)?,
        hand,
        alice_certificate,
        bob_certificate,
    })
}

fn recover_timeout(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    kind: TimeoutKind,
    elements: &[&[u8]],
) -> Result<Witness, RuntimeError> {
    require_stack_len(elements, 2)?;
    let timeout = edge.edge.timeout.ok_or(RuntimeError::InconsistentGraph {
        reason: "confirmed timeout edge has no timeout metadata",
    })?;
    if timeout.kind != kind {
        return Err(RuntimeError::InconsistentGraph {
            reason: "confirmed timeout kind differs from edge metadata",
        });
    }
    Ok(Witness::Timeout {
        chain_game_id: graph.chain_game_id(),
        node_id: edge.parent.node_id,
        child_node_id: edge.child.node_id,
        kind,
        beneficiary: timeout.beneficiary,
        alice_signature: bitcoin_signature_element(elements, 0)?,
        bob_signature: bitcoin_signature_element(elements, 1)?,
    })
}

fn recover_alice_score_certificate(
    elements: &[&[u8]],
    start: usize,
    score: u32,
) -> Result<AliceScoreCertificate, RuntimeError> {
    let mut preimages = Vec::with_capacity(SCORE_SIGNATURE_ELEMENTS);
    for index in 0..SCORE_SIGNATURE_ELEMENTS {
        preimages.push(fixed_element::<LAMPORT_ELEMENT_BYTES>(
            elements,
            start + 1 + 2 * index,
        )?);
    }
    Ok(AliceScoreCertificate::from_parts(
        Score24::new(score)?,
        LamportSignature::from_parts(LamportPurpose::AliceScore24Bit, preimages)?,
    )?)
}

fn recover_bob_score_certificate(
    elements: &[&[u8]],
    start: usize,
    score: u32,
) -> Result<BobScoreCertificate, RuntimeError> {
    let mut preimages = Vec::with_capacity(SCORE_SIGNATURE_ELEMENTS);
    for index in 0..SCORE_SIGNATURE_ELEMENTS {
        preimages.push(fixed_element::<LAMPORT_ELEMENT_BYTES>(
            elements,
            start + 1 + 2 * index,
        )?);
    }
    Ok(BobScoreCertificate::from_parts(
        Score24::new(score)?,
        LamportSignature::from_parts(LamportPurpose::BobScore24Bit, preimages)?,
    )?)
}

fn recover_showdown_hand(
    elements: &[&[u8]],
    slots: [u8; 7],
    subset_index: usize,
    opening_start: usize,
    score: u32,
) -> Result<ShowdownHandWitness, RuntimeError> {
    let subset = script_number_element(elements, subset_index)?;
    let subset_id = u8::try_from(subset)
        .ok()
        .filter(|subset| *subset < 21)
        .ok_or(codec_error("confirmed showdown subset is outside 0..20"))?;
    let mut openings = Vec::with_capacity(slots.len());
    for (position, slot) in slots.into_iter().enumerate() {
        let index = opening_start + 2 * position;
        openings.push(CardOpeningWitness::new(
            slot,
            bounded_preimage(elements[index])?,
            bounded_preimage(elements[index + 1])?,
        ));
    }
    let openings: [CardOpeningWitness; 7] = openings
        .try_into()
        .map_err(|_| codec_error("confirmed showdown opening count mismatch"))?;
    Ok(ShowdownHandWitness::new(openings, subset_id, score))
}

fn compare_confirmed_elements(
    kind: EdgeKind,
    observed: &[&[u8]],
    canonical: &[Vec<u8>],
) -> Result<(), RuntimeError> {
    if observed.len() != canonical.len() {
        return Err(codec_error("recovered witness element count changed"));
    }
    for (index, (observed, canonical)) in observed.iter().zip(canonical).enumerate() {
        let equal = if is_malleable_numeric_field(kind, index) {
            read_scriptint_non_minimal(observed).ok() == read_scriptint_non_minimal(canonical).ok()
        } else {
            *observed == canonical.as_slice()
        };
        if !equal {
            return Err(codec_error(
                "confirmed witness differs from recovered edge semantics",
            ));
        }
    }
    Ok(())
}

const fn is_malleable_numeric_field(kind: EdgeKind, index: usize) -> bool {
    match kind {
        EdgeKind::AliceShowdown => index == 0 || (index >= 51 && index <= 67),
        EdgeKind::BobPayout(_) => index == 0 || index == 49 || (index >= 100 && index <= 116),
        EdgeKind::Advance { .. }
        | EdgeKind::Action(_)
        | EdgeKind::HoleCardReveal { .. }
        | EdgeKind::CommunityReveal { .. }
        | EdgeKind::Timeout(_) => false,
    }
}

fn bitcoin_signature_element(
    elements: &[&[u8]],
    index: usize,
) -> Result<DefaultSighashSignature, RuntimeError> {
    Ok(DefaultSighashSignature::from_bytes(fixed_element::<
        SIGNATURE_BYTES,
    >(elements, index)?)?)
}

fn fixed_element<const N: usize>(
    elements: &[&[u8]],
    index: usize,
) -> Result<[u8; N], RuntimeError> {
    elements
        .get(index)
        .ok_or(codec_error("confirmed witness element is missing"))?
        .to_owned()
        .try_into()
        .map_err(|_| codec_error("confirmed witness element has wrong width"))
}

fn bounded_preimage(element: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    if !(16..=67).contains(&element.len()) {
        return Err(codec_error(
            "confirmed reveal preimage length is outside 16..=67",
        ));
    }
    Ok(element.to_vec())
}

fn score_element(elements: &[&[u8]], index: usize) -> Result<u32, RuntimeError> {
    let value = script_number_element(elements, index)?;
    let score = u32::try_from(value)
        .map_err(|_| codec_error("confirmed showdown score is negative or too large"))?;
    HandScore::try_from(score)?;
    Ok(score)
}

fn script_number_element(elements: &[&[u8]], index: usize) -> Result<i64, RuntimeError> {
    read_scriptint_non_minimal(
        elements
            .get(index)
            .ok_or(codec_error("confirmed numeric witness element is missing"))?,
    )
    .map_err(|_| codec_error("confirmed numeric witness element is invalid"))
}

fn require_stack_len(elements: &[&[u8]], expected: usize) -> Result<(), RuntimeError> {
    if elements.len() != expected {
        return Err(codec_error(
            "confirmed witness has wrong ordinary stack shape",
        ));
    }
    Ok(())
}

const fn reveal_edge_kind(pattern: RevealPattern) -> EdgeKind {
    match pattern {
        RevealPattern::DealAlice | RevealPattern::DealBob => EdgeKind::HoleCardReveal {
            revealer: pattern.revealer(),
        },
        RevealPattern::Flop(revealer) => EdgeKind::CommunityReveal {
            street: Street::Flop,
            revealer,
        },
        RevealPattern::Turn(revealer) => EdgeKind::CommunityReveal {
            street: Street::Turn,
            revealer,
        },
        RevealPattern::River(revealer) => EdgeKind::CommunityReveal {
            street: Street::River,
            revealer,
        },
    }
}

fn decode_action(
    reader: &mut Reader<'_>,
    chain_game_id: [u8; 32],
    node_id: NodeId,
    child_node_id: NodeId,
) -> Result<Witness, RuntimeError> {
    let action = decode_action_code(reader.byte()?)?;
    let alice_signature = reader.bitcoin_signature()?;
    let bob_signature = reader.bitcoin_signature()?;
    Ok(Witness::Action {
        chain_game_id,
        node_id,
        child_node_id,
        action,
        alice_signature,
        bob_signature,
    })
}

fn decode_advance(
    reader: &mut Reader<'_>,
    chain_game_id: [u8; 32],
    node_id: NodeId,
    child_node_id: NodeId,
) -> Result<Witness, RuntimeError> {
    let phase = decode_phase(reader.byte()?)?;
    let alice_signature = reader.bitcoin_signature()?;
    let bob_signature = reader.bitcoin_signature()?;
    Ok(Witness::Advance {
        chain_game_id,
        node_id,
        child_node_id,
        phase,
        alice_signature,
        bob_signature,
    })
}

fn decode_reveal(
    reader: &mut Reader<'_>,
    chain_game_id: [u8; 32],
    node_id: NodeId,
    child_node_id: NodeId,
) -> Result<Witness, RuntimeError> {
    let pattern = decode_reveal_pattern(reader.byte()?)?;
    let alice_signature = reader.bitcoin_signature()?;
    let bob_signature = reader.bitcoin_signature()?;
    let count = usize::from(reader.byte()?);
    if count != pattern.slots().len() {
        return Err(codec_error("wrong reveal preimage count"));
    }
    let mut preimages = Vec::with_capacity(count);
    for _ in 0..count {
        preimages.push(reader.preimage()?);
    }
    Ok(Witness::Reveal {
        chain_game_id,
        node_id,
        child_node_id,
        pattern,
        alice_signature,
        bob_signature,
        preimages,
    })
}

fn decode_alice_showdown(
    reader: &mut Reader<'_>,
    chain_game_id: [u8; 32],
    node_id: NodeId,
    child_node_id: NodeId,
) -> Result<Witness, RuntimeError> {
    let alice_signature = reader.bitcoin_signature()?;
    let bob_signature = reader.bitcoin_signature()?;
    let hand = reader.hand()?;
    validate_hand_slots(&hand, bp52_chain_bitcoin::ALICE_SEVEN_SLOTS)?;
    let certificate_score = reader.score()?;
    if certificate_score != hand.claimed_score() {
        return Err(codec_error("Alice hand and certificate scores differ"));
    }
    let signature = reader.lamport(LamportPurpose::AliceScore24Bit, SCORE_SIGNATURE_ELEMENTS)?;
    let certificate =
        AliceScoreCertificate::from_parts(Score24::new(certificate_score)?, signature)?;
    Ok(Witness::AliceShowdown {
        chain_game_id,
        node_id,
        child_node_id,
        alice_signature,
        bob_signature,
        hand,
        certificate,
    })
}

fn decode_bob_payout(
    reader: &mut Reader<'_>,
    chain_game_id: [u8; 32],
    node_id: NodeId,
    child_node_id: NodeId,
) -> Result<Witness, RuntimeError> {
    let alice_showdown_node_id = reader.nonzero_id("zero Alice showdown node identifier")?;
    let outcome = decode_outcome(reader.byte()?)?;
    let alice_signature = reader.bitcoin_signature()?;
    let bob_signature = reader.bitcoin_signature()?;
    let hand = reader.hand()?;
    validate_hand_slots(&hand, bp52_chain_bitcoin::BOB_SEVEN_SLOTS)?;
    let score_a = reader.score()?;
    let signature = reader.lamport(LamportPurpose::AliceScore24Bit, SCORE_SIGNATURE_ELEMENTS)?;
    let alice_certificate = AliceScoreCertificate::from_parts(Score24::new(score_a)?, signature)?;
    let score_b = reader.score()?;
    if score_b != hand.claimed_score() {
        return Err(codec_error("Bob hand and certificate scores differ"));
    }
    let signature = reader.lamport(LamportPurpose::BobScore24Bit, SCORE_SIGNATURE_ELEMENTS)?;
    let bob_certificate = BobScoreCertificate::from_parts(Score24::new(score_b)?, signature)?;
    Ok(Witness::BobPayout {
        chain_game_id,
        node_id,
        child_node_id,
        alice_showdown_node_id,
        outcome,
        alice_signature,
        bob_signature,
        hand,
        alice_certificate,
        bob_certificate,
    })
}

fn decode_timeout(
    reader: &mut Reader<'_>,
    chain_game_id: [u8; 32],
    node_id: NodeId,
    child_node_id: NodeId,
) -> Result<Witness, RuntimeError> {
    let kind = match reader.byte()? {
        0 => TimeoutKind::Action,
        1 => TimeoutKind::Reveal,
        2 => TimeoutKind::Showdown,
        _ => return Err(codec_error("invalid timeout code")),
    };
    let beneficiary = match reader.byte()? {
        0 => Role::Alice,
        1 => Role::Bob,
        _ => return Err(codec_error("invalid role code")),
    };
    let alice_signature = reader.bitcoin_signature()?;
    let bob_signature = reader.bitcoin_signature()?;
    Ok(Witness::Timeout {
        chain_game_id,
        node_id,
        child_node_id,
        kind,
        beneficiary,
        alice_signature,
        bob_signature,
    })
}

fn decode_action_code(code: u8) -> Result<Action, RuntimeError> {
    match code {
        0 => Ok(Action::Fold),
        1 => Ok(Action::Check),
        2 => Ok(Action::Call),
        3 => Ok(Action::Bet),
        4 => Ok(Action::Raise),
        _ => Err(codec_error("invalid three-bit action code")),
    }
}

fn decode_phase(code: u8) -> Result<Phase, RuntimeError> {
    match code {
        0 => Ok(Phase::DealAlice),
        1 => Ok(Phase::DealBob),
        2 => Ok(Phase::PreflopBetting),
        3 => Ok(Phase::FlopRevealFirst),
        4 => Ok(Phase::FlopRevealSecond),
        5 => Ok(Phase::FlopBetting),
        6 => Ok(Phase::TurnRevealFirst),
        7 => Ok(Phase::TurnRevealSecond),
        8 => Ok(Phase::TurnBetting),
        9 => Ok(Phase::RiverRevealFirst),
        10 => Ok(Phase::RiverRevealSecond),
        11 => Ok(Phase::RiverBetting),
        12 => Ok(Phase::AliceShowdown),
        13 => Ok(Phase::BobTerminal),
        _ => Err(codec_error("invalid advance phase code")),
    }
}

fn decode_reveal_pattern(code: u8) -> Result<RevealPattern, RuntimeError> {
    match code {
        0 => Ok(RevealPattern::DealAlice),
        1 => Ok(RevealPattern::DealBob),
        2 => Ok(RevealPattern::Flop(Role::Alice)),
        3 => Ok(RevealPattern::Flop(Role::Bob)),
        4 => Ok(RevealPattern::Turn(Role::Alice)),
        5 => Ok(RevealPattern::Turn(Role::Bob)),
        6 => Ok(RevealPattern::River(Role::Alice)),
        7 => Ok(RevealPattern::River(Role::Bob)),
        _ => Err(codec_error("invalid reveal pattern code")),
    }
}

fn decode_outcome(code: u8) -> Result<ShowdownOutcome, RuntimeError> {
    match code {
        0 => Ok(ShowdownOutcome::AliceWin),
        1 => Ok(ShowdownOutcome::BobWin),
        2 => Ok(ShowdownOutcome::Split),
        _ => Err(codec_error("invalid showdown outcome code")),
    }
}

fn signature_pair(alice: DefaultSighashSignature, bob: DefaultSighashSignature) -> Vec<Vec<u8>> {
    vec![alice.to_bytes().to_vec(), bob.to_bytes().to_vec()]
}

fn append_signature(encoded: &mut Vec<u8>, signature: DefaultSighashSignature) {
    encoded.extend_from_slice(signature.as_bytes());
}

fn append_raw_lamport(encoded: &mut Vec<u8>, signature: &LamportSignature) {
    for preimage in signature.preimages() {
        encoded.extend_from_slice(preimage);
    }
}

fn append_preimage(encoded: &mut Vec<u8>, preimage: &[u8]) -> Result<(), RuntimeError> {
    if !(16..=67).contains(&preimage.len()) {
        return Err(codec_error("preimage length is outside 16..=67"));
    }
    encoded
        .push(u8::try_from(preimage.len()).map_err(|_| codec_error("preimage length exceeds u8"))?);
    encoded.extend_from_slice(preimage);
    Ok(())
}

fn append_hand(encoded: &mut Vec<u8>, hand: &ShowdownHandWitness) -> Result<(), RuntimeError> {
    for opening in hand.openings() {
        encoded.push(opening.slot());
        append_preimage(encoded, opening.preimage_a())?;
        append_preimage(encoded, opening.preimage_b())?;
    }
    if hand.subset_id() >= 21 {
        return Err(codec_error("showdown subset is outside 0..20"));
    }
    encoded.push(hand.subset_id());
    append_score(encoded, hand.claimed_score())?;
    Ok(())
}

fn append_score(encoded: &mut Vec<u8>, score: u32) -> Result<(), RuntimeError> {
    HandScore::try_from(score)?;
    let bytes = score.to_be_bytes();
    if bytes[0] != 0 {
        return Err(codec_error("showdown score exceeds 24 bits"));
    }
    encoded.extend_from_slice(&bytes[1..]);
    Ok(())
}

fn validate_nonzero_id(identifier: [u8; 32], reason: &'static str) -> Result<(), RuntimeError> {
    if identifier.iter().all(|byte| *byte == 0) {
        Err(codec_error(reason))
    } else {
        Ok(())
    }
}

fn validate_hand_slots(hand: &ShowdownHandWitness, expected: [u8; 7]) -> Result<(), RuntimeError> {
    if hand
        .openings()
        .iter()
        .map(CardOpeningWitness::slot)
        .ne(expected)
    {
        return Err(codec_error("noncanonical showdown slot order"));
    }
    Ok(())
}

const fn codec_error(reason: &'static str) -> RuntimeError {
    RuntimeError::InvalidWitnessEncoding { reason }
}

struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn byte(&mut self) -> Result<u8, RuntimeError> {
        let value = self
            .input
            .get(self.position)
            .copied()
            .ok_or(codec_error("truncated runtime witness"))?;
        self.position += 1;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RuntimeError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(codec_error("runtime witness length overflow"))?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(codec_error("truncated runtime witness"))?;
        self.position = end;
        bytes
            .try_into()
            .map_err(|_| codec_error("fixed-width witness field mismatch"))
    }

    fn nonzero_id(&mut self, reason: &'static str) -> Result<[u8; 32], RuntimeError> {
        let identifier = self.array::<32>()?;
        if identifier.iter().all(|byte| *byte == 0) {
            Err(codec_error(reason))
        } else {
            Ok(identifier)
        }
    }

    fn bitcoin_signature(&mut self) -> Result<DefaultSighashSignature, RuntimeError> {
        Ok(DefaultSighashSignature::from_bytes(
            self.array::<SIGNATURE_BYTES>()?,
        )?)
    }

    fn lamport(
        &mut self,
        purpose: LamportPurpose,
        count: usize,
    ) -> Result<LamportSignature, RuntimeError> {
        let mut preimages = Vec::with_capacity(count);
        for _ in 0..count {
            preimages.push(self.array::<LAMPORT_ELEMENT_BYTES>()?);
        }
        Ok(LamportSignature::from_parts(purpose, preimages)?)
    }

    fn preimage(&mut self) -> Result<Vec<u8>, RuntimeError> {
        let length = usize::from(self.byte()?);
        if !(16..=67).contains(&length) {
            return Err(codec_error("preimage length is outside 16..=67"));
        }
        let end = self
            .position
            .checked_add(length)
            .ok_or(codec_error("runtime witness length overflow"))?;
        let preimage = self
            .input
            .get(self.position..end)
            .ok_or(codec_error("truncated runtime witness"))?
            .to_vec();
        self.position = end;
        Ok(preimage)
    }

    fn score(&mut self) -> Result<u32, RuntimeError> {
        let bytes = self.array::<3>()?;
        let score = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
        HandScore::try_from(score)?;
        Ok(score)
    }

    fn hand(&mut self) -> Result<ShowdownHandWitness, RuntimeError> {
        let mut openings = Vec::with_capacity(7);
        for _ in 0..7 {
            let slot = self.byte()?;
            if slot >= 9 {
                return Err(codec_error("showdown opening has invalid slot"));
            }
            openings.push(CardOpeningWitness::new(
                slot,
                self.preimage()?,
                self.preimage()?,
            ));
        }
        let subset_id = self.byte()?;
        if subset_id >= 21 {
            return Err(codec_error("showdown subset is outside 0..20"));
        }
        let claimed_score = self.score()?;
        let openings: [CardOpeningWitness; 7] = openings
            .try_into()
            .map_err(|_| codec_error("showdown opening count mismatch"))?;
        Ok(ShowdownHandWitness::new(openings, subset_id, claimed_score))
    }

    const fn is_finished(&self) -> bool {
        self.position == self.input.len()
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use bp52_chain_bitcoin::{
        AliceScoreCertificate, CardOpeningWitness, DefaultSighashSignature, ShowdownHandWitness,
        sign_sighash_default,
    };
    use bp52_chain_types::{Action, Phase, Role, ShowdownOutcome, TimeoutKind};
    use bp52_lamport::{BobScoreCertificate, LamportPurpose, LamportSignature, Score24};

    use super::{SIGNATURE_BYTES, Witness};
    use crate::RuntimeError;

    fn bitcoin_signature_with_secret(
        secret_byte: u8,
    ) -> Result<DefaultSighashSignature, RuntimeError> {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[secret_byte; 32]).map_err(|_| {
            RuntimeError::InvalidWitnessEncoding {
                reason: "test secret key",
            }
        })?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        Ok(sign_sighash_default(&secp, &keypair, [8; 32]))
    }

    fn bitcoin_signature() -> Result<DefaultSighashSignature, RuntimeError> {
        bitcoin_signature_with_secret(7)
    }

    fn lamport_signature(purpose: LamportPurpose) -> Result<LamportSignature, RuntimeError> {
        let count = usize::from(purpose.bit_width());
        Ok(LamportSignature::from_parts(
            purpose,
            (0..count)
                .map(|index| [u8::try_from(index).unwrap_or_default(); 32])
                .collect(),
        )?)
    }

    fn action_witness() -> Result<Witness, RuntimeError> {
        Ok(Witness::Action {
            chain_game_id: [1; 32],
            node_id: [2; 32],
            child_node_id: [3; 32],
            action: Action::Raise,
            alice_signature: bitcoin_signature()?,
            bob_signature: bitcoin_signature()?,
        })
    }

    #[test]
    fn advance_codec_round_trips_and_v4_rejects_v3() -> Result<(), RuntimeError> {
        let witness = Witness::Advance {
            chain_game_id: [1; 32],
            node_id: [2; 32],
            child_node_id: [3; 32],
            phase: Phase::FlopBetting,
            alice_signature: bitcoin_signature_with_secret(7)?,
            bob_signature: bitcoin_signature_with_secret(9)?,
        };
        let encoded = witness.encode()?;
        assert!(encoded.starts_with(b"BP52WIT4"));
        assert_eq!(Witness::decode(&encoded)?, witness);

        let mut obsolete_magic = encoded.clone();
        obsolete_magic[7] = b'3';
        assert!(matches!(
            Witness::decode(&obsolete_magic),
            Err(RuntimeError::InvalidWitnessEncoding { .. })
        ));

        let mut invalid_phase = encoded;
        invalid_phase[105] = 14;
        assert!(matches!(
            Witness::decode(&invalid_phase),
            Err(RuntimeError::InvalidWitnessEncoding { .. })
        ));
        Ok(())
    }

    #[test]
    fn strict_action_codec_round_trips_and_rejects_mutations() -> Result<(), RuntimeError> {
        let witness = action_witness()?;
        let encoded = witness.encode()?;
        assert_eq!(Witness::decode(&encoded)?, witness);

        let mut invalid_action = encoded.clone();
        invalid_action[105] = 0b111;
        assert!(matches!(
            Witness::decode(&invalid_action),
            Err(RuntimeError::InvalidWitnessEncoding { .. })
        ));

        let mut extended_signature = encoded.clone();
        extended_signature.insert(106 + SIGNATURE_BYTES, 2);
        assert!(matches!(
            Witness::decode(&extended_signature),
            Err(RuntimeError::InvalidWitnessEncoding { .. } | RuntimeError::Bitcoin(_))
        ));

        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            Witness::decode(&trailing),
            Err(RuntimeError::InvalidWitnessEncoding { .. })
        ));
        Ok(())
    }

    #[test]
    fn timeout_codec_requires_both_canonical_signatures_and_v4_magic() -> Result<(), RuntimeError> {
        let alice_signature = bitcoin_signature_with_secret(7)?;
        let bob_signature = bitcoin_signature_with_secret(9)?;
        let witness = Witness::Timeout {
            chain_game_id: [1; 32],
            node_id: [2; 32],
            child_node_id: [3; 32],
            kind: TimeoutKind::Action,
            beneficiary: Role::Bob,
            alice_signature,
            bob_signature,
        };
        let encoded = witness.encode()?;
        assert!(encoded.starts_with(b"BP52WIT4"));
        assert_eq!(
            &encoded[107..107 + SIGNATURE_BYTES],
            alice_signature.as_bytes()
        );
        assert_eq!(
            &encoded[107 + SIGNATURE_BYTES..107 + 2 * SIGNATURE_BYTES],
            bob_signature.as_bytes()
        );
        assert_eq!(Witness::decode(&encoded)?, witness);

        let mut old_magic = encoded.clone();
        old_magic[7] = b'3';
        assert!(matches!(
            Witness::decode(&old_magic),
            Err(RuntimeError::InvalidWitnessEncoding { .. })
        ));
        assert!(matches!(
            Witness::decode(&encoded[..encoded.len() - SIGNATURE_BYTES]),
            Err(RuntimeError::InvalidWitnessEncoding { .. })
        ));
        Ok(())
    }

    #[test]
    fn decoder_rejects_wrong_outcome_and_fixed_width_truncation() -> Result<(), RuntimeError> {
        let signature = bitcoin_signature()?;
        let hand = ShowdownHandWitness::new(
            bp52_chain_bitcoin::BOB_SEVEN_SLOTS
                .map(|slot| CardOpeningWitness::new(slot, vec![1; 16], vec![2; 16])),
            0,
            0x8c_0000,
        );
        let alice_certificate = AliceScoreCertificate::from_parts(
            Score24::new(0x8c_0000)?,
            lamport_signature(LamportPurpose::AliceScore24Bit)?,
        )?;
        let bob_certificate = BobScoreCertificate::from_parts(
            Score24::new(0x8c_0000)?,
            lamport_signature(LamportPurpose::BobScore24Bit)?,
        )?;
        let witness = Witness::BobPayout {
            chain_game_id: [1; 32],
            node_id: [2; 32],
            child_node_id: [3; 32],
            alice_showdown_node_id: [4; 32],
            outcome: ShowdownOutcome::Split,
            alice_signature: signature,
            bob_signature: signature,
            hand,
            alice_certificate,
            bob_certificate,
        };
        let encoded = witness.encode()?;
        assert_eq!(Witness::decode(&encoded)?, witness);
        let mut invalid_outcome = encoded.clone();
        invalid_outcome[137] = 3;
        assert!(matches!(
            Witness::decode(&invalid_outcome),
            Err(RuntimeError::InvalidWitnessEncoding { .. })
        ));
        assert!(matches!(
            Witness::decode(&encoded[..encoded.len() - 1]),
            Err(RuntimeError::InvalidWitnessEncoding { .. })
        ));
        Ok(())
    }

    #[test]
    fn reveal_codec_preserves_repeated_public_elements() -> Result<(), RuntimeError> {
        let signature = bitcoin_signature()?;
        let preimages = vec![vec![4; 16], vec![5; 17], vec![6; 18]];
        let witness = Witness::Reveal {
            chain_game_id: [1; 32],
            node_id: [2; 32],
            child_node_id: [3; 32],
            pattern: bp52_chain_bitcoin::RevealPattern::Flop(Role::Alice),
            alice_signature: signature,
            bob_signature: signature,
            preimages,
        };
        assert_eq!(Witness::decode(&witness.encode()?)?, witness);
        Ok(())
    }

    #[test]
    fn encoder_rejects_fields_that_cannot_round_trip_losslessly() -> Result<(), RuntimeError> {
        let mut zero_identifier = action_witness()?;
        if let Witness::Action { chain_game_id, .. } = &mut zero_identifier {
            *chain_game_id = [0; 32];
        }
        assert!(matches!(
            zero_identifier.encode(),
            Err(RuntimeError::InvalidWitnessEncoding { .. })
        ));

        let signature = bitcoin_signature()?;
        let oversized_preimage = Witness::Reveal {
            chain_game_id: [1; 32],
            node_id: [2; 32],
            child_node_id: [3; 32],
            pattern: bp52_chain_bitcoin::RevealPattern::Turn(Role::Bob),
            alice_signature: signature,
            bob_signature: signature,
            preimages: vec![vec![9; 256]],
        };
        assert!(matches!(
            oversized_preimage.encode(),
            Err(RuntimeError::InvalidWitnessEncoding { .. })
        ));

        let invalid_score = Witness::BobPayout {
            chain_game_id: [1; 32],
            node_id: [2; 32],
            child_node_id: [3; 32],
            alice_showdown_node_id: [4; 32],
            outcome: ShowdownOutcome::Split,
            alice_signature: signature,
            bob_signature: signature,
            hand: ShowdownHandWitness::new(
                bp52_chain_bitcoin::BOB_SEVEN_SLOTS
                    .map(|slot| CardOpeningWitness::new(slot, vec![1; 16], vec![2; 16])),
                0,
                u32::MAX,
            ),
            alice_certificate: AliceScoreCertificate::from_parts(
                Score24::new(0x8c_0000)?,
                lamport_signature(LamportPurpose::AliceScore24Bit)?,
            )?,
            bob_certificate: BobScoreCertificate::from_parts(
                Score24::new(0x8c_0000)?,
                lamport_signature(LamportPurpose::BobScore24Bit)?,
            )?,
        };
        assert!(matches!(
            invalid_score.encode(),
            Err(RuntimeError::Poker(_))
        ));
        Ok(())
    }
}
