//! Auditable Tapscript macro for the canonical BP52 five-card evaluator.
//!
//! Bitcoin Script has no division, modulo, sorting, or multiplication
//! opcodes. The evaluator therefore accepts bounded rank/suit decomposition
//! data as witness-only proof values and verifies every value against the five
//! reconstructed card identifiers. Production showdown leaves specialize the
//! positive check for one claimed category and do not prove that stronger
//! categories are absent. The proof cannot choose unsupported tie-breakers:
//! all score components remain constrained by the cards.

use bitcoin::ScriptBuf;
use bitcoin::blockdata::opcodes::all::{
    OP_ADD, OP_DROP, OP_DUP, OP_ELSE, OP_ENDIF, OP_FROMALTSTACK, OP_GREATERTHAN,
    OP_GREATERTHANOREQUAL, OP_IF, OP_LESSTHANOREQUAL, OP_NUMEQUAL, OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL, OP_PICK, OP_SUB, OP_TOALTSTACK, OP_VERIFY,
};
use bitcoin::blockdata::script::Builder;
use bp52_poker::{Card, HandCategory, HandScore, PokerError, eval5};

/// Number of elements emitted by [`Eval5ScriptWitness::to_witness_elements`].
pub const EVAL5_PROOF_ELEMENTS: usize = 16;

const LOCAL_ELEMENTS: usize = EVAL5_PROOF_ELEMENTS + 5;
const CATEGORY: usize = 0;
const COMPONENTS: [usize; 5] = [1, 2, 3, 4, 5];
const RANKS: [usize; 5] = [6, 8, 10, 12, 14];
const SUITS: [usize; 5] = [7, 9, 11, 13, 15];
const CARDS: [usize; 5] = [16, 17, 18, 19, 20];

/// Canonical witness-only decomposition for one selected five-card hand.
///
/// The emitted elements are ordered bottom-to-top as category, five score
/// rank components, then `(rank, suit)` for each selected card in order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Eval5ScriptWitness {
    score: HandScore,
    card_ranks: [u8; 5],
    card_suits: [u8; 5],
}

impl Eval5ScriptWitness {
    /// Derive the unique valid decomposition from five distinct card IDs.
    ///
    /// # Errors
    ///
    /// Returns the exact poker error for an invalid or duplicate card.
    pub fn from_cards(cards: [u8; 5]) -> Result<Self, PokerError> {
        let score = eval5(cards)?;
        Self::from_claimed_score(cards, score)
    }

    /// Derive card decomposition for an exact or weaker-category claim.
    ///
    /// Tie breakers must be exact when the categories match. A strictly
    /// stronger actual category may use the canonical score committed by the
    /// selected weaker category leaf.
    pub fn from_claimed_score(cards: [u8; 5], score: HandScore) -> Result<Self, PokerError> {
        let actual = eval5(cards)?;
        if actual != score && actual.category() <= score.category() {
            return Err(PokerError::ClaimedScoreMismatch {
                claimed_score: score.as_u32(),
                actual_score: actual.as_u32(),
            });
        }
        let decoded = [
            Card::try_from(cards[0])?,
            Card::try_from(cards[1])?,
            Card::try_from(cards[2])?,
            Card::try_from(cards[3])?,
            Card::try_from(cards[4])?,
        ];
        Ok(Self {
            score,
            card_ranks: decoded.map(Card::rank_index),
            card_suits: decoded.map(Card::suit_index),
        })
    }

    /// Return the canonical packed score proved by these elements.
    #[must_use]
    pub const fn score(self) -> HandScore {
        self.score
    }

    /// Encode the exact 16 minimally encoded Script-number elements.
    #[must_use]
    pub fn to_witness_elements(self) -> Vec<Vec<u8>> {
        let mut elements = Vec::with_capacity(EVAL5_PROOF_ELEMENTS);
        elements.push(encode_script_num(i64::from(self.score.category().as_u8())));
        elements.extend(
            self.score
                .rank_components()
                .into_iter()
                .map(|value| encode_script_num(i64::from(value))),
        );
        for (rank, suit) in self.card_ranks.into_iter().zip(self.card_suits) {
            elements.push(encode_script_num(i64::from(rank)));
            elements.push(encode_script_num(i64::from(suit)));
        }
        elements
    }
}

/// Build the standalone lower-bound evaluator macro for inspection and tests.
///
/// The initial stack must end in the 16 elements from
/// [`Eval5ScriptWitness::to_witness_elements`] followed by five selected card
/// IDs in the same order. On success all 21 elements are consumed and the
/// claimed packed score is left on top.
#[must_use]
pub fn eval5_tapscript() -> ScriptBuf {
    append_eval5(Builder::new()).into_script()
}

/// Build one category-specialized evaluator leaf.
///
/// This script proves only the positive facts required by `claimed_category`;
/// for example, straight, flush, and high-card leaves accept a straight flush.
/// The category element in the witness must equal the leaf's category.
#[must_use]
pub fn eval5_tapscript_for_category(claimed_category: HandCategory) -> ScriptBuf {
    append_eval5_for_category(Builder::new(), claimed_category).into_script()
}

/// Append the lower-bound five-card evaluator to an existing builder.
///
/// This macro preserves stack elements below its 21 inputs and any older
/// altstack elements. All arithmetic remains below Bitcoin Script's signed
/// 32-bit numeric limit.
pub(crate) fn append_eval5(mut builder: Builder) -> Builder {
    builder = append_eval5_prefix(builder);
    builder = append_category_checks(builder, 8);
    append_packed_score(builder)
}

/// Append one lower-bound, category-specialized five-card evaluator.
pub(crate) fn append_eval5_for_category(
    mut builder: Builder,
    claimed_category: HandCategory,
) -> Builder {
    builder = append_eval5_prefix(builder);
    builder = push_var(builder, CATEGORY)
        .push_int(i64::from(claimed_category.as_u8()))
        .push_opcode(OP_NUMEQUALVERIFY);
    builder = category_checks(builder, claimed_category.as_u8());
    append_packed_score(builder)
}

fn append_eval5_prefix(mut builder: Builder) -> Builder {
    for component in COMPONENTS {
        builder = require_range(builder, component, 0, 12);
    }
    for rank in RANKS {
        builder = require_range(builder, rank, 0, 12);
    }
    for suit in SUITS {
        builder = require_range(builder, suit, 0, 3);
    }

    for index in 0..5 {
        builder = push_var(builder, CARDS[index]);
        builder = push_var_offset(builder, SUITS[index], 1);
        builder = push_var_offset(builder, RANKS[index], 2);
        builder = multiply_top_by_4(builder)
            .push_opcode(OP_ADD)
            .push_opcode(OP_NUMEQUALVERIFY);
    }
    for (left_index, left) in CARDS.iter().copied().enumerate() {
        for right in CARDS.iter().copied().skip(left_index + 1) {
            builder = push_var(builder, left);
            builder = push_var_offset(builder, right, 1);
            builder = builder.push_opcode(OP_NUMNOTEQUAL).push_opcode(OP_VERIFY);
        }
    }
    builder
}

fn append_packed_score(mut builder: Builder) -> Builder {
    builder = push_var(builder, CATEGORY);
    for component in COMPONENTS {
        for _ in 0..4 {
            builder = builder.push_opcode(OP_DUP).push_opcode(OP_ADD);
        }
        builder = push_var_offset(builder, component, 1).push_opcode(OP_ADD);
    }

    builder = builder.push_opcode(OP_TOALTSTACK);
    for _ in 0..LOCAL_ELEMENTS {
        builder = builder.push_opcode(OP_DROP);
    }
    builder.push_opcode(OP_FROMALTSTACK)
}

fn category_checks(builder: Builder, category: u8) -> Builder {
    match category {
        8 => straight_flush_checks(builder),
        7 => four_kind_checks(builder),
        6 => full_house_checks(builder),
        5 => flush_checks(builder),
        4 => straight_checks(builder),
        3 => three_kind_checks(builder),
        2 => two_pair_checks(builder),
        1 => one_pair_checks(builder),
        0 => high_card_checks(builder),
        _ => builder.push_int(0).push_opcode(OP_VERIFY),
    }
}

/// Validate `(category, r1, ..., r5)` against [`HandScore`]'s canonical
/// layout, consume the six components, and leave their packed score.
pub(crate) fn append_canonical_score(mut builder: Builder) -> Builder {
    for component in 1..6 {
        builder = score_require_range(builder, component, 0, 12);
    }
    builder = append_score_category_checks(builder, 8);
    builder = score_push(builder, 0);
    for component in 1..6 {
        for _ in 0..4 {
            builder = builder.push_opcode(OP_DUP).push_opcode(OP_ADD);
        }
        builder = score_push_offset(builder, component, 1).push_opcode(OP_ADD);
    }
    builder = builder.push_opcode(OP_TOALTSTACK);
    for _ in 0..6 {
        builder = builder.push_opcode(OP_DROP);
    }
    builder.push_opcode(OP_FROMALTSTACK)
}

/// Encode one signed integer using Bitcoin Script's minimal signed-magnitude
/// little-endian representation.
///
/// This is the authoritative encoding for numeric showdown witness fields;
/// in particular, a positive 24-bit score with its high bit set requires a
/// fourth zero sign byte.
#[must_use]
pub fn encode_script_num(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let negative = value.is_negative();
    let mut absolute = value.unsigned_abs();
    let mut bytes = Vec::new();
    while absolute > 0 {
        bytes.push(absolute.to_le_bytes()[0]);
        absolute >>= 8;
    }
    if bytes.last().is_some_and(|last| last & 0x80 != 0) {
        bytes.push(if negative { 0x80 } else { 0 });
    } else if negative {
        let last_index = bytes.len() - 1;
        bytes[last_index] |= 0x80;
    }
    bytes
}

fn append_category_checks(mut builder: Builder, category: u8) -> Builder {
    builder = push_var(builder, CATEGORY)
        .push_int(i64::from(category))
        .push_opcode(OP_NUMEQUAL)
        .push_opcode(OP_IF);
    builder = category_checks(builder, category);
    builder = builder.push_opcode(OP_ELSE);
    if category == 0 {
        builder = builder.push_int(0).push_opcode(OP_VERIFY);
    } else {
        builder = append_category_checks(builder, category - 1);
    }
    builder.push_opcode(OP_ENDIF)
}

fn append_score_category_checks(mut builder: Builder, category: u8) -> Builder {
    builder = score_push(builder, 0)
        .push_int(i64::from(category))
        .push_opcode(OP_NUMEQUAL)
        .push_opcode(OP_IF);
    builder = match category {
        8 | 4 => score_straight_layout(builder),
        7 | 6 => score_double_rank_layout(builder),
        5 | 0 => score_distinct_layout(builder),
        3 => score_three_kind_layout(builder),
        2 => score_two_pair_layout(builder),
        1 => score_one_pair_layout(builder),
        _ => builder.push_int(0).push_opcode(OP_VERIFY),
    };
    builder = builder.push_opcode(OP_ELSE);
    if category == 0 {
        builder = builder.push_int(0).push_opcode(OP_VERIFY);
    } else {
        builder = append_score_category_checks(builder, category - 1);
    }
    builder.push_opcode(OP_ENDIF)
}

fn score_straight_layout(mut builder: Builder) -> Builder {
    builder = score_push(builder, 1)
        .push_int(3)
        .push_opcode(OP_GREATERTHANOREQUAL)
        .push_opcode(OP_VERIFY);
    score_require_zero_from(builder, 2)
}

fn score_double_rank_layout(mut builder: Builder) -> Builder {
    builder = score_require_distinct(builder, 1, 2);
    score_require_zero_from(builder, 3)
}

fn score_distinct_layout(builder: Builder) -> Builder {
    score_require_descending(builder, &[1, 2, 3, 4, 5])
}

fn score_three_kind_layout(mut builder: Builder) -> Builder {
    builder = score_require_descending(builder, &[2, 3]);
    builder = score_require_distinct(builder, 1, 2);
    builder = score_require_distinct(builder, 1, 3);
    score_require_zero_from(builder, 4)
}

fn score_two_pair_layout(mut builder: Builder) -> Builder {
    builder = score_require_descending(builder, &[1, 2]);
    builder = score_require_distinct(builder, 3, 1);
    builder = score_require_distinct(builder, 3, 2);
    score_require_zero_from(builder, 4)
}

fn score_one_pair_layout(mut builder: Builder) -> Builder {
    builder = score_require_descending(builder, &[2, 3, 4]);
    for kicker in 2..=4 {
        builder = score_require_distinct(builder, 1, kicker);
    }
    score_require_zero_from(builder, 5)
}

fn score_require_zero_from(mut builder: Builder, first: usize) -> Builder {
    for component in first..6 {
        builder = score_push(builder, component)
            .push_int(0)
            .push_opcode(OP_NUMEQUALVERIFY);
    }
    builder
}

fn score_require_descending(mut builder: Builder, components: &[usize]) -> Builder {
    for pair in components.windows(2) {
        builder = score_push(builder, pair[0]);
        builder = score_push_offset(builder, pair[1], 1)
            .push_opcode(OP_GREATERTHAN)
            .push_opcode(OP_VERIFY);
    }
    builder
}

fn score_require_distinct(builder: Builder, left: usize, right: usize) -> Builder {
    let builder = score_push(builder, left);
    score_push_offset(builder, right, 1)
        .push_opcode(OP_NUMNOTEQUAL)
        .push_opcode(OP_VERIFY)
}

fn score_require_range(builder: Builder, variable: usize, minimum: i64, maximum: i64) -> Builder {
    let builder = score_push(builder, variable)
        .push_int(minimum)
        .push_opcode(OP_GREATERTHANOREQUAL)
        .push_opcode(OP_VERIFY);
    score_push(builder, variable)
        .push_int(maximum)
        .push_opcode(OP_LESSTHANOREQUAL)
        .push_opcode(OP_VERIFY)
}

fn score_push(builder: Builder, variable: usize) -> Builder {
    score_push_offset(builder, variable, 0)
}

fn score_push_offset(builder: Builder, variable: usize, offset: usize) -> Builder {
    let depth = 5_usize.saturating_sub(variable).saturating_add(offset);
    builder
        .push_int(i64::try_from(depth).unwrap_or(i64::MAX))
        .push_opcode(OP_PICK)
}

fn straight_flush_checks(mut builder: Builder) -> Builder {
    builder = require_zero_components(builder, 1);
    builder = require_straight_ranks(builder);
    require_flush(builder)
}

fn four_kind_checks(mut builder: Builder) -> Builder {
    builder = require_zero_components(builder, 2);
    builder = require_rank_count(builder, Target::Variable(COMPONENTS[0]), 4);
    require_rank_count(builder, Target::Variable(COMPONENTS[1]), 1)
}

fn full_house_checks(mut builder: Builder) -> Builder {
    builder = require_zero_components(builder, 2);
    builder = require_rank_count(builder, Target::Variable(COMPONENTS[0]), 3);
    require_rank_count(builder, Target::Variable(COMPONENTS[1]), 2)
}

fn flush_checks(mut builder: Builder) -> Builder {
    builder = require_descending(builder, &COMPONENTS);
    builder = require_singleton_components(builder);
    require_flush(builder)
}

fn straight_checks(mut builder: Builder) -> Builder {
    builder = require_zero_components(builder, 1);
    require_straight_ranks(builder)
}

fn three_kind_checks(mut builder: Builder) -> Builder {
    builder = require_zero_components(builder, 3);
    builder = require_descending(builder, &COMPONENTS[1..3]);
    builder = require_rank_count(builder, Target::Variable(COMPONENTS[0]), 3);
    builder = require_rank_count(builder, Target::Variable(COMPONENTS[1]), 1);
    require_rank_count(builder, Target::Variable(COMPONENTS[2]), 1)
}

fn two_pair_checks(mut builder: Builder) -> Builder {
    builder = require_zero_components(builder, 3);
    builder = require_descending(builder, &COMPONENTS[..2]);
    builder = require_rank_count(builder, Target::Variable(COMPONENTS[0]), 2);
    builder = require_rank_count(builder, Target::Variable(COMPONENTS[1]), 2);
    require_rank_count(builder, Target::Variable(COMPONENTS[2]), 1)
}

fn one_pair_checks(mut builder: Builder) -> Builder {
    builder = require_zero_components(builder, 4);
    builder = require_descending(builder, &COMPONENTS[1..4]);
    builder = require_rank_count(builder, Target::Variable(COMPONENTS[0]), 2);
    for component in &COMPONENTS[1..4] {
        builder = require_rank_count(builder, Target::Variable(*component), 1);
    }
    builder
}

fn high_card_checks(mut builder: Builder) -> Builder {
    builder = require_descending(builder, &COMPONENTS);
    require_singleton_components(builder)
}

fn require_zero_components(mut builder: Builder, used: usize) -> Builder {
    for component in &COMPONENTS[used..] {
        builder = push_var(builder, *component)
            .push_int(0)
            .push_opcode(OP_NUMEQUALVERIFY);
    }
    builder
}

fn require_descending(mut builder: Builder, variables: &[usize]) -> Builder {
    for pair in variables.windows(2) {
        builder = push_var(builder, pair[0]);
        builder = push_var_offset(builder, pair[1], 1);
        builder = builder.push_opcode(OP_GREATERTHAN).push_opcode(OP_VERIFY);
    }
    builder
}

fn require_singleton_components(mut builder: Builder) -> Builder {
    for component in COMPONENTS {
        builder = require_rank_count(builder, Target::Variable(component), 1);
    }
    builder
}

fn require_straight_ranks(mut builder: Builder) -> Builder {
    builder = push_var(builder, COMPONENTS[0])
        .push_int(3)
        .push_opcode(OP_NUMEQUAL)
        .push_opcode(OP_IF);
    for rank in [12_i64, 3, 2, 1, 0] {
        builder = require_rank_count(builder, Target::Constant(rank), 1);
    }
    builder = builder.push_opcode(OP_ELSE);
    builder = push_var(builder, COMPONENTS[0])
        .push_int(4)
        .push_opcode(OP_GREATERTHANOREQUAL)
        .push_opcode(OP_VERIFY);
    for delta in 0..5 {
        builder = require_rank_count(builder, Target::VariableMinus(COMPONENTS[0], delta), 1);
    }
    builder.push_opcode(OP_ENDIF)
}

fn require_flush(mut builder: Builder) -> Builder {
    for suit in &SUITS[1..] {
        builder = push_var(builder, SUITS[0]);
        builder = push_var_offset(builder, *suit, 1);
        builder = builder.push_opcode(OP_NUMEQUALVERIFY);
    }
    builder
}

#[derive(Clone, Copy)]
enum Target {
    Variable(usize),
    VariableMinus(usize, i64),
    Constant(i64),
}

fn require_rank_count(mut builder: Builder, target: Target, expected: i64) -> Builder {
    for (index, rank) in RANKS.into_iter().enumerate() {
        let existing_count = usize::from(index != 0);
        builder = push_var_offset(builder, rank, existing_count);
        builder = push_target(builder, target, existing_count + 1).push_opcode(OP_NUMEQUAL);
        if index != 0 {
            builder = builder.push_opcode(OP_ADD);
        }
    }
    builder.push_int(expected).push_opcode(OP_NUMEQUALVERIFY)
}

fn push_target(builder: Builder, target: Target, offset: usize) -> Builder {
    match target {
        Target::Variable(variable) => push_var_offset(builder, variable, offset),
        Target::VariableMinus(variable, delta) => push_var_offset(builder, variable, offset)
            .push_int(delta)
            .push_opcode(OP_SUB),
        Target::Constant(value) => builder.push_int(value),
    }
}

fn require_range(builder: Builder, variable: usize, minimum: i64, maximum: i64) -> Builder {
    let builder = push_var(builder, variable)
        .push_int(minimum)
        .push_opcode(OP_GREATERTHANOREQUAL)
        .push_opcode(OP_VERIFY);
    push_var(builder, variable)
        .push_int(maximum)
        .push_opcode(OP_LESSTHANOREQUAL)
        .push_opcode(OP_VERIFY)
}

fn push_var(builder: Builder, variable: usize) -> Builder {
    push_var_offset(builder, variable, 0)
}

fn push_var_offset(builder: Builder, variable: usize, offset: usize) -> Builder {
    let depth = LOCAL_ELEMENTS
        .saturating_sub(1)
        .saturating_sub(variable)
        .saturating_add(offset);
    builder
        .push_int(i64::try_from(depth).unwrap_or(i64::MAX))
        .push_opcode(OP_PICK)
}

fn multiply_top_by_4(builder: Builder) -> Builder {
    builder
        .push_opcode(OP_DUP)
        .push_opcode(OP_ADD)
        .push_opcode(OP_DUP)
        .push_opcode(OP_ADD)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{error::Error, fmt};

    use bitcoin::blockdata::opcodes::all::{
        OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CSV, OP_EQUALVERIFY, OP_SHA256, OP_SIZE, OP_SWAP,
    };
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::opcodes::{Class, ClassifyContext};
    use bitcoin::secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
    use bp52_poker::{HandCategory, HandScore, evaluate_five_cards};
    use sha2::{Digest, Sha256};

    use super::{
        Eval5ScriptWitness, append_canonical_score, encode_script_num, eval5_tapscript,
        eval5_tapscript_for_category,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct InterpreterError(&'static str);

    pub(crate) const TEST_SIGHASH: [u8; 32] = [0x42; 32];

    impl fmt::Display for InterpreterError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl Error for InterpreterError {}

    fn card(rank: u8, suit: u8) -> u8 {
        rank * 4 + suit
    }

    fn evaluator_stack(cards: [u8; 5]) -> Result<Vec<Vec<u8>>, bp52_poker::PokerError> {
        let mut stack = Eval5ScriptWitness::from_cards(cards)?.to_witness_elements();
        stack.extend(
            cards
                .into_iter()
                .map(|value| encode_script_num(i64::from(value))),
        );
        Ok(stack)
    }

    // Deliberately independent and minimal: this interpreter implements only
    // the serialized opcodes emitted by `append_eval5`. It does not call any
    // poker classification code.
    pub(crate) fn execute(
        script: &bitcoin::Script,
        stack: Vec<Vec<u8>>,
    ) -> Result<(Vec<Vec<u8>>, usize), InterpreterError> {
        execute_with_sighash(script, stack, TEST_SIGHASH)
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_with_sighash(
        script: &bitcoin::Script,
        mut stack: Vec<Vec<u8>>,
        sighash: [u8; 32],
    ) -> Result<(Vec<Vec<u8>>, usize), InterpreterError> {
        let mut altstack = Vec::<Vec<u8>>::new();
        let mut conditions = Vec::<bool>::new();
        let mut maximum_stack = stack.len();

        for instruction in script.instructions_minimal() {
            let instruction = instruction.map_err(|_| InterpreterError("invalid script"))?;
            if let Instruction::Op(opcode) = instruction {
                if opcode == super::OP_IF {
                    let parent_active = conditions.iter().all(|active| *active);
                    let active = if parent_active {
                        let condition = pop(&mut stack)?;
                        if !condition.is_empty() && condition.as_slice() != [1] {
                            return Err(InterpreterError("non-minimal OP_IF condition"));
                        }
                        cast_to_bool(&condition)
                    } else {
                        false
                    };
                    conditions.push(parent_active && active);
                    continue;
                }
                if opcode == super::OP_ELSE {
                    let parent_active = conditions
                        .get(..conditions.len().saturating_sub(1))
                        .ok_or(InterpreterError("OP_ELSE without OP_IF"))?
                        .iter()
                        .all(|active| *active);
                    let current = conditions
                        .last_mut()
                        .ok_or(InterpreterError("OP_ELSE without OP_IF"))?;
                    *current = parent_active && !*current;
                    continue;
                }
                if opcode == super::OP_ENDIF {
                    conditions
                        .pop()
                        .ok_or(InterpreterError("OP_ENDIF without OP_IF"))?;
                    continue;
                }
            }

            if !conditions.iter().all(|active| *active) {
                continue;
            }
            if let Some(number) = instruction.script_num() {
                stack.push(encode_script_num(number));
                update_stack_limit(&stack, &altstack, &mut maximum_stack)?;
                continue;
            }

            match instruction {
                Instruction::PushBytes(bytes) => stack.push(bytes.as_bytes().to_vec()),
                Instruction::Op(opcode) if opcode == super::OP_DUP => {
                    stack.push(
                        stack
                            .last()
                            .ok_or(InterpreterError("OP_DUP stack underflow"))?
                            .clone(),
                    );
                }
                Instruction::Op(opcode) if opcode == OP_SIZE => {
                    let length = stack
                        .last()
                        .ok_or(InterpreterError("OP_SIZE stack underflow"))?
                        .len();
                    stack.push(encode_script_num(
                        i64::try_from(length)
                            .map_err(|_| InterpreterError("OP_SIZE numeric overflow"))?,
                    ));
                }
                Instruction::Op(opcode) if opcode == super::OP_PICK => {
                    let depth = pop_num(&mut stack)?;
                    let depth = usize::try_from(depth)
                        .map_err(|_| InterpreterError("negative OP_PICK depth"))?;
                    let index = stack
                        .len()
                        .checked_sub(depth.saturating_add(1))
                        .ok_or(InterpreterError("OP_PICK stack underflow"))?;
                    stack.push(stack[index].clone());
                }
                Instruction::Op(opcode) if opcode == super::OP_DROP => {
                    pop(&mut stack)?;
                }
                // Predicate tests execute timeout scripts after assuming the
                // transaction has reached the encoded relative height. CSV
                // inspects but does not consume its nonnegative stack value.
                Instruction::Op(opcode) if opcode == OP_CSV => {
                    let value = stack
                        .last()
                        .ok_or(InterpreterError("OP_CSV stack underflow"))?;
                    if decode_script_num(value)? < 0 {
                        return Err(InterpreterError("negative OP_CSV delay"));
                    }
                }
                Instruction::Op(opcode) if opcode == OP_SWAP => {
                    let length = stack.len();
                    if length < 2 {
                        return Err(InterpreterError("OP_SWAP stack underflow"));
                    }
                    stack.swap(length - 1, length - 2);
                }
                Instruction::Op(opcode) if opcode == super::OP_TOALTSTACK => {
                    altstack.push(pop(&mut stack)?);
                }
                Instruction::Op(opcode) if opcode == super::OP_FROMALTSTACK => {
                    stack.push(
                        altstack
                            .pop()
                            .ok_or(InterpreterError("OP_FROMALTSTACK underflow"))?,
                    );
                }
                Instruction::Op(opcode) if opcode == super::OP_ADD || opcode == super::OP_SUB => {
                    let right = pop_num(&mut stack)?;
                    let left = pop_num(&mut stack)?;
                    let value = if opcode == super::OP_ADD {
                        left.checked_add(right)
                    } else {
                        left.checked_sub(right)
                    }
                    .ok_or(InterpreterError("numeric overflow"))?;
                    stack.push(encode_script_num(value));
                }
                Instruction::Op(opcode)
                    if opcode == super::OP_NUMEQUAL
                        || opcode == super::OP_NUMNOTEQUAL
                        || opcode == super::OP_GREATERTHAN
                        || opcode == super::OP_GREATERTHANOREQUAL
                        || opcode == super::OP_LESSTHANOREQUAL =>
                {
                    let right = pop_num(&mut stack)?;
                    let left = pop_num(&mut stack)?;
                    let value = if opcode == super::OP_NUMEQUAL {
                        left == right
                    } else if opcode == super::OP_NUMNOTEQUAL {
                        left != right
                    } else if opcode == super::OP_GREATERTHAN {
                        left > right
                    } else if opcode == super::OP_GREATERTHANOREQUAL {
                        left >= right
                    } else {
                        left <= right
                    };
                    stack.push(encode_bool(value));
                }
                Instruction::Op(opcode) if opcode == super::OP_NUMEQUALVERIFY => {
                    let right = pop_num(&mut stack)?;
                    let left = pop_num(&mut stack)?;
                    if left != right {
                        return Err(InterpreterError("OP_NUMEQUALVERIFY failed"));
                    }
                }
                Instruction::Op(opcode) if opcode == OP_EQUALVERIFY => {
                    let right = pop(&mut stack)?;
                    let left = pop(&mut stack)?;
                    if left != right {
                        return Err(InterpreterError("OP_EQUALVERIFY failed"));
                    }
                }
                Instruction::Op(opcode) if opcode == OP_SHA256 => {
                    let value = pop(&mut stack)?;
                    stack.push(Sha256::digest(value).to_vec());
                }
                Instruction::Op(opcode) if opcode == OP_CHECKSIGVERIFY => {
                    let public_key = pop(&mut stack)?;
                    let signature = pop(&mut stack)?;
                    if signature.len() != 64 {
                        return Err(InterpreterError("non-SIGHASH_DEFAULT signature"));
                    }
                    let public_key = XOnlyPublicKey::from_slice(&public_key)
                        .map_err(|_| InterpreterError("invalid x-only public key"))?;
                    let signature = Signature::from_slice(&signature)
                        .map_err(|_| InterpreterError("invalid Schnorr signature"))?;
                    Secp256k1::verification_only()
                        .verify_schnorr(&signature, &Message::from_digest(sighash), &public_key)
                        .map_err(|_| InterpreterError("OP_CHECKSIGVERIFY failed"))?;
                }
                Instruction::Op(opcode) if opcode == OP_CHECKSIG => {
                    let public_key = pop(&mut stack)?;
                    let signature = pop(&mut stack)?;
                    let valid = XOnlyPublicKey::from_slice(&public_key)
                        .ok()
                        .zip(Signature::from_slice(&signature).ok())
                        .is_some_and(|(public_key, signature)| {
                            Secp256k1::verification_only()
                                .verify_schnorr(
                                    &signature,
                                    &Message::from_digest(sighash),
                                    &public_key,
                                )
                                .is_ok()
                        });
                    stack.push(encode_bool(valid));
                }
                Instruction::Op(opcode) if opcode == super::OP_VERIFY => {
                    if !cast_to_bool(&pop(&mut stack)?) {
                        return Err(InterpreterError("OP_VERIFY failed"));
                    }
                }
                Instruction::Op(_) => return Err(InterpreterError("unexpected opcode")),
            }
            update_stack_limit(&stack, &altstack, &mut maximum_stack)?;
        }
        if !conditions.is_empty() || !altstack.is_empty() {
            return Err(InterpreterError("unbalanced conditional or altstack"));
        }
        if !stack.last().is_some_and(|value| cast_to_bool(value)) {
            return Err(InterpreterError("false final stack value"));
        }
        Ok((stack, maximum_stack))
    }

    fn update_stack_limit(
        stack: &[Vec<u8>],
        altstack: &[Vec<u8>],
        maximum: &mut usize,
    ) -> Result<(), InterpreterError> {
        let combined = stack.len().saturating_add(altstack.len());
        *maximum = (*maximum).max(combined);
        if combined > 1_000 {
            return Err(InterpreterError("combined stack exceeds 1000 elements"));
        }
        if stack
            .iter()
            .chain(altstack)
            .any(|element| element.len() > 520)
        {
            return Err(InterpreterError("stack element exceeds 520 bytes"));
        }
        Ok(())
    }

    fn pop(stack: &mut Vec<Vec<u8>>) -> Result<Vec<u8>, InterpreterError> {
        stack.pop().ok_or(InterpreterError("stack underflow"))
    }

    fn pop_num(stack: &mut Vec<Vec<u8>>) -> Result<i64, InterpreterError> {
        decode_script_num(&pop(stack)?)
    }

    pub(crate) fn decode_script_num(bytes: &[u8]) -> Result<i64, InterpreterError> {
        if bytes.len() > 4 {
            return Err(InterpreterError("Script number exceeds four bytes"));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut magnitude = 0_u64;
        for (index, byte) in bytes.iter().copied().enumerate() {
            let shift = u32::try_from(index.saturating_mul(8))
                .map_err(|_| InterpreterError("numeric shift overflow"))?;
            magnitude |= u64::from(byte) << shift;
        }
        let sign_shift = u32::try_from((bytes.len() - 1).saturating_mul(8))
            .map_err(|_| InterpreterError("numeric sign overflow"))?;
        let sign_bit = 0x80_u64 << sign_shift;
        if magnitude & sign_bit == 0 {
            i64::try_from(magnitude).map_err(|_| InterpreterError("numeric overflow"))
        } else {
            let absolute = i64::try_from(magnitude & !sign_bit)
                .map_err(|_| InterpreterError("numeric overflow"))?;
            Ok(-absolute)
        }
    }

    fn encode_bool(value: bool) -> Vec<u8> {
        if value { vec![1] } else { Vec::new() }
    }

    fn cast_to_bool(bytes: &[u8]) -> bool {
        bytes
            .iter()
            .copied()
            .enumerate()
            .any(|(index, byte)| byte != 0 && !(index + 1 == bytes.len() && byte == 0x80))
    }

    #[test]
    fn every_category_executes_to_the_rust_score() -> Result<(), Box<dyn Error>> {
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
        let script = eval5_tapscript();
        let mut maximum = 0;
        for mut hand in hands {
            for _ in 0..5 {
                let (stack, observed) = execute(&script, evaluator_stack(hand)?)?;
                maximum = maximum.max(observed);
                assert_eq!(stack.len(), 1);
                assert_eq!(
                    decode_script_num(&stack[0])?,
                    i64::from(evaluate_five_cards(hand)?)
                );
                hand.rotate_left(1);
            }
        }
        assert!(maximum < 100);
        Ok(())
    }

    #[test]
    fn weaker_category_leaves_accept_a_straight_flush() -> Result<(), Box<dyn Error>> {
        let cards = [
            card(12, 3),
            card(11, 3),
            card(10, 3),
            card(9, 3),
            card(8, 3),
        ];
        let mut stack = evaluator_stack(cards)?;
        stack[0] = encode_script_num(i64::from(HandCategory::Straight.as_u8()));
        let script = eval5_tapscript_for_category(HandCategory::Straight);
        let (result, _) = execute(&script, stack)?;
        assert_eq!(result, vec![encode_script_num(0x4c_0000)]);

        for (category, expected_score) in [
            (HandCategory::Flush, 0x5c_ba98),
            (HandCategory::HighCard, 0x0c_ba98),
        ] {
            let score = HandScore::from_components(category, [12, 11, 10, 9, 8])?;
            let mut claimed_stack =
                Eval5ScriptWitness::from_claimed_score(cards, score)?.to_witness_elements();
            claimed_stack.extend(
                cards
                    .into_iter()
                    .map(|card| encode_script_num(i64::from(card))),
            );
            assert_eq!(
                execute(
                    &eval5_tapscript_for_category(category),
                    claimed_stack.clone()
                )?
                .0,
                vec![encode_script_num(expected_score)]
            );
            assert_eq!(
                execute(&eval5_tapscript(), claimed_stack)?.0,
                vec![encode_script_num(expected_score)]
            );
        }
        Ok(())
    }

    #[test]
    fn every_category_has_a_distinct_bounded_script() {
        let categories = [
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
        let scripts: Vec<_> = categories
            .map(eval5_tapscript_for_category)
            .into_iter()
            .collect();
        assert!(scripts.iter().all(|script| script.len() <= 10_000));
        let monolithic_size = eval5_tapscript().len();
        assert!(scripts.iter().all(|script| script.len() < monolithic_size));
        for (index, script) in scripts.iter().enumerate() {
            assert!(scripts.iter().skip(index + 1).all(|other| other != script));
        }
    }

    #[test]
    fn deterministic_hand_sample_matches_the_rust_oracle() -> Result<(), Box<dyn Error>> {
        let script = eval5_tapscript();
        let mut state = 0x8f3d_29a7_u64;
        for _ in 0..2_000 {
            let mut hand = [0_u8; 5];
            let mut used = [false; 52];
            for card_id in &mut hand {
                loop {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    let candidate = u8::try_from((state >> 32) % 52)?;
                    if !used[usize::from(candidate)] {
                        used[usize::from(candidate)] = true;
                        *card_id = candidate;
                        break;
                    }
                }
            }
            let (stack, _) = execute(&script, evaluator_stack(hand)?)?;
            assert_eq!(
                decode_script_num(&stack[0])?,
                i64::from(evaluate_five_cards(hand)?)
            );
        }
        Ok(())
    }

    #[test]
    fn every_proof_field_and_card_mutation_is_rejected() -> Result<(), Box<dyn Error>> {
        let script = eval5_tapscript();
        let hand = [card(12, 2), card(9, 2), card(7, 2), card(4, 2), card(1, 2)];
        let valid = evaluator_stack(hand)?;
        assert!(execute(&script, valid.clone()).is_ok());

        for index in 0..16 {
            let mut changed = valid.clone();
            let original = decode_script_num(&changed[index])?;
            changed[index] = encode_script_num(if original == 12 { 11 } else { original + 1 });
            assert!(execute(&script, changed).is_err(), "proof index {index}");
        }
        for index in 16..21 {
            let mut changed = valid.clone();
            let original = decode_script_num(&changed[index])?;
            changed[index] = encode_script_num((original + 1) % 52);
            assert!(execute(&script, changed).is_err(), "card index {index}");
        }

        let mut duplicate = valid;
        duplicate[20] = duplicate[19].clone();
        assert!(execute(&script, duplicate).is_err());
        Ok(())
    }

    #[test]
    fn serialized_evaluator_is_bounded_and_contains_no_success_opcode() {
        let script = eval5_tapscript();
        assert!(script.len() <= 10_000, "{} byte evaluator", script.len());
        assert!(
            script
                .instructions_minimal()
                .all(|instruction| instruction.is_ok())
        );
        assert!(script.instructions().all(|instruction| {
            !matches!(
                instruction,
                Ok(Instruction::Op(opcode))
                    if matches!(opcode.classify(ClassifyContext::TapScript), Class::SuccessOp)
            )
        }));
    }

    #[test]
    fn score_macro_matches_rust_lower_bound_layouts() -> Result<(), Box<dyn Error>> {
        let script =
            append_canonical_score(bitcoin::blockdata::script::Builder::new()).into_script();
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
        ];
        for hand in hands {
            let score = Eval5ScriptWitness::from_cards(hand)?.score();
            let mut components = vec![encode_script_num(i64::from(score.category().as_u8()))];
            components.extend(
                score
                    .rank_components()
                    .map(|rank| encode_script_num(i64::from(rank))),
            );
            let (stack, _) = execute(&script, components)?;
            assert_eq!(decode_script_num(&stack[0])?, i64::from(score.as_u32()));
        }

        let formerly_overqualified_flush = [5_i64, 12, 11, 10, 9, 8]
            .into_iter()
            .map(encode_script_num)
            .collect();
        assert_eq!(
            execute(&script, formerly_overqualified_flush)?.0,
            vec![encode_script_num(0x5c_ba98)]
        );

        for malformed in [
            [9_i64, 0, 0, 0, 0, 0],
            [8, 2, 0, 0, 0, 0],
            [7, 9, 9, 0, 0, 0],
            [1, 9, 12, 12, 3, 0],
        ] {
            let stack = malformed.into_iter().map(encode_script_num).collect();
            assert!(execute(&script, stack).is_err());
        }
        Ok(())
    }
}
