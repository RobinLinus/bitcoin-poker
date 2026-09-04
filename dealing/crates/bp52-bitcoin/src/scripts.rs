//! Taproot script-path templates for public card openings.

use bitcoin::blockdata::opcodes::all::{
    OP_ADD, OP_BOOLOR, OP_DUP, OP_EQUALVERIFY, OP_GREATERTHANOREQUAL, OP_LESSTHANOREQUAL,
    OP_NUMEQUAL, OP_SHA256, OP_SIZE, OP_SUB, OP_SWAP,
};
use bitcoin::blockdata::script::Builder;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{ScriptBuf, Witness};
use bp52_protocol::VerifiedAcceptedDeal;
use thiserror::Error;

use crate::opening::{DECK_SIZE, OpeningError, verify_card_opening};

/// Bitcoin's consensus stack-element size limit.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
/// BIP341's hash-derived x-only NUMS point, whose discrete logarithm is not
/// known. It prevents a known-key bypass of the card-opening script path.
pub const SCRIPT_PATH_NUMS_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Failure to construct or satisfy the fixed v1 card-opening leaf.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ScriptTemplateError {
    /// The card identifier was not in the fixed deck range.
    #[error("invalid claimed card {claimed_card}; expected 0..=51")]
    InvalidClaimedCard {
        /// The rejected identifier.
        claimed_card: u8,
    },
    /// The selected deal slot was outside the fixed nine-card range.
    #[error("invalid deal slot {slot}; expected 0..=8")]
    InvalidSlot {
        /// Rejected slot identifier.
        slot: u8,
    },
    /// The one-leaf Taproot tree could not be constructed.
    #[error("failed to construct the one-leaf Taproot tree")]
    TaprootConstruction,
    /// The expected tapscript was absent from its spend information.
    #[error("card-opening tapscript has no control block")]
    MissingControlBlock,
    /// A native opening check failed before witness construction.
    #[error(transparent)]
    InvalidOpening(#[from] OpeningError),
    /// A witness element would exceed Bitcoin's 520-byte consensus limit.
    #[error("witness element exceeds Bitcoin's 520-byte limit")]
    OversizedWitnessElement,
}

/// A one-leaf Taproot card-opening template.
///
/// The card identifier is committed in the tapscript. A script-path spend
/// supplies exactly Alice's and Bob's preimages, in that bottom-to-top order,
/// followed by the script and control block.
#[derive(Clone, Debug)]
pub struct CardOpeningTemplate {
    expected_hash_a: [u8; 32],
    expected_hash_b: [u8; 32],
    claimed_card: u8,
    script: ScriptBuf,
    spend_info: TaprootSpendInfo,
}

impl CardOpeningTemplate {
    /// Constructs a script-path-only template bound to one fully verified deal
    /// slot.
    ///
    /// The internal key is BIP341's hash-derived NUMS point. No corresponding
    /// secret key is known, so the intended spend policy is the committed
    /// card-opening leaf rather than a caller-controlled key path.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptTemplateError::InvalidSlot`] for a slot outside
    /// `0..=8`, [`ScriptTemplateError::InvalidClaimedCard`] for an identifier
    /// outside `0..=51`, or [`ScriptTemplateError::TaprootConstruction`] if
    /// the NUMS point or one-leaf tree cannot be constructed.
    pub fn from_verified_deal<C: Verification>(
        secp: &Secp256k1<C>,
        deal: &VerifiedAcceptedDeal,
        slot: u8,
        claimed_card: u8,
    ) -> Result<Self, ScriptTemplateError> {
        let index = usize::from(slot);
        let accepted = deal.as_deal();
        let expected_hash_a = accepted
            .hashes_a
            .get(index)
            .copied()
            .ok_or(ScriptTemplateError::InvalidSlot { slot })?;
        let expected_hash_b = accepted
            .hashes_b
            .get(index)
            .copied()
            .ok_or(ScriptTemplateError::InvalidSlot { slot })?;
        Self::new_script_path_only(secp, expected_hash_a, expected_hash_b, claimed_card)
    }

    fn new_script_path_only<C: Verification>(
        secp: &Secp256k1<C>,
        expected_hash_a: [u8; 32],
        expected_hash_b: [u8; 32],
        claimed_card: u8,
    ) -> Result<Self, ScriptTemplateError> {
        let internal_key = UntweakedPublicKey::from_slice(&SCRIPT_PATH_NUMS_KEY)
            .map_err(|_| ScriptTemplateError::TaprootConstruction)?;
        Self::build(
            secp,
            internal_key,
            expected_hash_a,
            expected_hash_b,
            claimed_card,
        )
    }

    /// Constructs a template with an explicitly caller-controlled key path.
    ///
    /// # Warning
    ///
    /// Whoever knows the discrete logarithm of `internal_key` can spend the
    /// resulting output without satisfying the card-opening tapscript. Use
    /// [`Self::from_verified_deal`] for the protocol's script-only policy.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptTemplateError::InvalidClaimedCard`] for an identifier
    /// outside `0..=51`, or [`ScriptTemplateError::TaprootConstruction`] if the
    /// one-leaf tree cannot be finalized.
    pub fn new_with_key_path_bypass<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        expected_hash_a: [u8; 32],
        expected_hash_b: [u8; 32],
        claimed_card: u8,
    ) -> Result<Self, ScriptTemplateError> {
        Self::build(
            secp,
            internal_key,
            expected_hash_a,
            expected_hash_b,
            claimed_card,
        )
    }

    fn build<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: UntweakedPublicKey,
        expected_hash_a: [u8; 32],
        expected_hash_b: [u8; 32],
        claimed_card: u8,
    ) -> Result<Self, ScriptTemplateError> {
        let script = card_opening_tapscript(&expected_hash_a, &expected_hash_b, claimed_card)?;
        let builder = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .map_err(|_| ScriptTemplateError::TaprootConstruction)?;
        let spend_info = builder
            .finalize(secp, internal_key)
            .map_err(|_| ScriptTemplateError::TaprootConstruction)?;

        Ok(Self {
            expected_hash_a,
            expected_hash_b,
            claimed_card,
            script,
            spend_info,
        })
    }

    /// Returns the committed tapscript leaf.
    #[must_use]
    pub fn script(&self) -> &ScriptBuf {
        &self.script
    }

    /// Returns the Taproot construction data, including the output key.
    #[must_use]
    pub const fn spend_info(&self) -> &TaprootSpendInfo {
        &self.spend_info
    }

    /// Returns the P2TR script pubkey that commits to this leaf.
    #[must_use]
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.spend_info.output_key())
    }

    /// Builds a checked script-path witness for the two preimages.
    ///
    /// # Errors
    ///
    /// Returns an opening error if either preimage has the wrong length/hash or
    /// produces a different card. It also rejects a missing control block or
    /// any witness element above Bitcoin's 520-byte limit.
    pub fn satisfy(
        &self,
        preimage_a: &[u8],
        preimage_b: &[u8],
    ) -> Result<Witness, ScriptTemplateError> {
        verify_card_opening(
            &self.expected_hash_a,
            preimage_a,
            &self.expected_hash_b,
            preimage_b,
            self.claimed_card,
        )?;

        let control_block = self
            .spend_info
            .control_block(&(self.script.clone(), LeafVersion::TapScript))
            .ok_or(ScriptTemplateError::MissingControlBlock)?;
        let control_bytes = control_block.serialize();

        if [
            preimage_a.len(),
            preimage_b.len(),
            self.script.len(),
            control_bytes.len(),
        ]
        .into_iter()
        .any(|len| len > MAX_SCRIPT_ELEMENT_SIZE)
        {
            return Err(ScriptTemplateError::OversizedWitnessElement);
        }

        Ok(Witness::from_slice(&[
            preimage_a,
            preimage_b,
            self.script.as_bytes(),
            control_bytes.as_slice(),
        ]))
    }
}

/// Builds the exact v1 two-share card-opening tapscript.
///
/// The script expects `preimage_a preimage_b` on the initial stack. For each
/// preimage it checks the inclusive length range and SHA-256 digest, subtracts
/// the base length, adds the two shares, and accepts iff the raw sum is either
/// `claimed_card` or `claimed_card + 52`. No modulo opcode is used.
///
/// # Errors
///
/// Returns [`ScriptTemplateError::InvalidClaimedCard`] when `claimed_card` is
/// outside the fixed v1 deck range.
pub fn card_opening_tapscript(
    expected_hash_a: &[u8; 32],
    expected_hash_b: &[u8; 32],
    claimed_card: u8,
) -> Result<ScriptBuf, ScriptTemplateError> {
    if claimed_card >= DECK_SIZE {
        return Err(ScriptTemplateError::InvalidClaimedCard { claimed_card });
    }

    // Bob's preimage is on top of the initial witness stack.
    let builder = append_share_check(Builder::new(), expected_hash_b).push_opcode(OP_SWAP);
    let raw_sum = append_share_check(builder, expected_hash_a).push_opcode(OP_ADD);
    let claimed = i64::from(claimed_card);

    Ok(raw_sum
        .push_opcode(OP_DUP)
        .push_int(claimed)
        .push_opcode(OP_NUMEQUAL)
        .push_opcode(OP_SWAP)
        .push_int(claimed + i64::from(DECK_SIZE))
        .push_opcode(OP_NUMEQUAL)
        .push_opcode(OP_BOOLOR)
        .into_script())
}

fn append_share_check(builder: Builder, expected_hash: &[u8; 32]) -> Builder {
    builder
        .push_opcode(OP_SIZE)
        .push_opcode(OP_DUP)
        .push_int(16)
        .push_opcode(OP_GREATERTHANOREQUAL)
        .push_verify()
        .push_opcode(OP_DUP)
        .push_int(67)
        .push_opcode(OP_LESSTHANOREQUAL)
        .push_verify()
        .push_int(16)
        .push_opcode(OP_SUB)
        .push_opcode(OP_SWAP)
        .push_opcode(OP_SHA256)
        .push_slice(expected_hash)
        .push_opcode(OP_EQUALVERIFY)
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fmt};

    use bitcoin::blockdata::opcodes::all::{
        OP_ADD, OP_BOOLOR, OP_DUP, OP_EQUALVERIFY, OP_GREATERTHANOREQUAL, OP_LESSTHANOREQUAL,
        OP_NUMEQUAL, OP_SHA256, OP_SIZE, OP_SUB, OP_SWAP, OP_VERIFY,
    };
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::key::UntweakedPublicKey;
    use bitcoin::opcodes::{Class, ClassifyContext};
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};

    use super::{
        CardOpeningTemplate, MAX_SCRIPT_ELEMENT_SIZE, SCRIPT_PATH_NUMS_KEY, ScriptTemplateError,
        card_opening_tapscript,
    };
    use crate::opening::{BASE_PREIMAGE_LENGTH, DECK_SIZE, MAX_PREIMAGE_LENGTH};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestInterpreterError(&'static str);

    impl fmt::Display for TestInterpreterError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl Error for TestInterpreterError {}

    fn hash(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn internal_key()
    -> Result<(Secp256k1<bitcoin::secp256k1::All>, UntweakedPublicKey), bitcoin::secp256k1::Error>
    {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[7_u8; 32])?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (key, _) = keypair.x_only_public_key();
        Ok((secp, key))
    }

    // This deliberately small interpreter implements only the opcodes emitted
    // by `card_opening_tapscript`. Its purpose is to test the actual serialized
    // stack program rather than duplicating the high-level opening predicate.
    fn execute_card_script(
        script: &bitcoin::Script,
        preimage_a: &[u8],
        preimage_b: &[u8],
    ) -> Result<bool, TestInterpreterError> {
        if [preimage_a.len(), preimage_b.len()]
            .into_iter()
            .any(|length| length > MAX_SCRIPT_ELEMENT_SIZE)
        {
            return Ok(false);
        }

        let mut stack = vec![preimage_a.to_vec(), preimage_b.to_vec()];
        for instruction in script.instructions_minimal() {
            let instruction = instruction.map_err(|_| TestInterpreterError("invalid script"))?;
            if let Some(number) = instruction.script_num() {
                stack.push(encode_script_num(number));
                continue;
            }

            match instruction {
                Instruction::PushBytes(bytes) => {
                    if bytes.len() > MAX_SCRIPT_ELEMENT_SIZE {
                        return Ok(false);
                    }
                    stack.push(bytes.as_bytes().to_vec());
                }
                Instruction::Op(opcode) if opcode == OP_SIZE => {
                    let length = stack
                        .last()
                        .ok_or(TestInterpreterError("OP_SIZE stack underflow"))?
                        .len();
                    let number = i64::try_from(length)
                        .map_err(|_| TestInterpreterError("OP_SIZE numeric overflow"))?;
                    stack.push(encode_script_num(number));
                }
                Instruction::Op(opcode) if opcode == OP_DUP => {
                    let top = stack
                        .last()
                        .ok_or(TestInterpreterError("OP_DUP stack underflow"))?
                        .clone();
                    stack.push(top);
                }
                Instruction::Op(opcode)
                    if opcode == OP_GREATERTHANOREQUAL || opcode == OP_LESSTHANOREQUAL =>
                {
                    let right = pop_script_num(&mut stack)?;
                    let left = pop_script_num(&mut stack)?;
                    let result = if opcode == OP_GREATERTHANOREQUAL {
                        left >= right
                    } else {
                        left <= right
                    };
                    stack.push(encode_bool(result));
                }
                Instruction::Op(opcode) if opcode == OP_VERIFY => {
                    if !cast_to_bool(&pop(&mut stack)?) {
                        return Ok(false);
                    }
                }
                Instruction::Op(opcode) if opcode == OP_SUB || opcode == OP_ADD => {
                    let right = pop_script_num(&mut stack)?;
                    let left = pop_script_num(&mut stack)?;
                    let result = if opcode == OP_SUB {
                        left.checked_sub(right)
                            .ok_or(TestInterpreterError("OP_SUB overflow"))?
                    } else {
                        left.checked_add(right)
                            .ok_or(TestInterpreterError("OP_ADD overflow"))?
                    };
                    stack.push(encode_script_num(result));
                }
                Instruction::Op(opcode) if opcode == OP_SWAP => {
                    let length = stack.len();
                    if length < 2 {
                        return Err(TestInterpreterError("OP_SWAP stack underflow"));
                    }
                    stack.swap(length - 1, length - 2);
                }
                Instruction::Op(opcode) if opcode == OP_SHA256 => {
                    let bytes = pop(&mut stack)?;
                    stack.push(Sha256::digest(bytes).to_vec());
                }
                Instruction::Op(opcode) if opcode == OP_EQUALVERIFY => {
                    let right = pop(&mut stack)?;
                    let left = pop(&mut stack)?;
                    if left != right {
                        return Ok(false);
                    }
                }
                Instruction::Op(opcode) if opcode == OP_NUMEQUAL => {
                    let right = pop_script_num(&mut stack)?;
                    let left = pop_script_num(&mut stack)?;
                    stack.push(encode_bool(left == right));
                }
                Instruction::Op(opcode) if opcode == OP_BOOLOR => {
                    let right = cast_to_bool(&pop(&mut stack)?);
                    let left = cast_to_bool(&pop(&mut stack)?);
                    stack.push(encode_bool(left || right));
                }
                Instruction::Op(_) => {
                    return Err(TestInterpreterError("unexpected opcode"));
                }
            }
        }

        Ok(stack.len() == 1 && cast_to_bool(&stack[0]))
    }

    fn pop(stack: &mut Vec<Vec<u8>>) -> Result<Vec<u8>, TestInterpreterError> {
        stack.pop().ok_or(TestInterpreterError("stack underflow"))
    }

    fn pop_script_num(stack: &mut Vec<Vec<u8>>) -> Result<i64, TestInterpreterError> {
        decode_script_num(&pop(stack)?)
    }

    fn decode_script_num(bytes: &[u8]) -> Result<i64, TestInterpreterError> {
        if bytes.len() > 4 {
            return Err(TestInterpreterError("script number exceeds four bytes"));
        }
        if bytes.is_empty() {
            return Ok(0);
        }

        let mut magnitude = 0_u64;
        for (index, byte) in bytes.iter().copied().enumerate() {
            let shift = u32::try_from(index * 8)
                .map_err(|_| TestInterpreterError("script number shift overflow"))?;
            magnitude |= u64::from(byte) << shift;
        }
        let sign_shift = u32::try_from((bytes.len() - 1) * 8)
            .map_err(|_| TestInterpreterError("script number sign overflow"))?;
        let sign_bit = 0x80_u64 << sign_shift;
        if magnitude & sign_bit == 0 {
            i64::try_from(magnitude)
                .map_err(|_| TestInterpreterError("positive script number overflow"))
        } else {
            let absolute = i64::try_from(magnitude & !sign_bit)
                .map_err(|_| TestInterpreterError("negative script number overflow"))?;
            Ok(-absolute)
        }
    }

    fn encode_script_num(value: i64) -> Vec<u8> {
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
    fn script_is_minimal_fixed_and_contains_no_success_opcode()
    -> Result<(), Box<dyn std::error::Error>> {
        let hash_a = [0x11_u8; 32];
        let hash_b = [0x22_u8; 32];
        let script = card_opening_tapscript(&hash_a, &hash_b, 51)?;

        assert!(script.instructions_minimal().all(|item| item.is_ok()));
        assert!(script.instructions().all(|item| {
            !matches!(
                item,
                Ok(Instruction::Op(opcode))
                    if matches!(opcode.classify(ClassifyContext::TapScript), Class::SuccessOp)
            )
        }));
        assert!(script.len() < MAX_SCRIPT_ELEMENT_SIZE);
        assert_eq!(
            card_opening_tapscript(&hash_a, &hash_b, DECK_SIZE),
            Err(ScriptTemplateError::InvalidClaimedCard {
                claimed_card: DECK_SIZE,
            })
        );
        Ok(())
    }

    #[test]
    fn serialized_script_matches_all_share_pairs_and_both_raw_sum_branches()
    -> Result<(), Box<dyn Error>> {
        let preimages: Vec<Vec<u8>> = (0_u8..DECK_SIZE)
            .map(|share| vec![share; BASE_PREIMAGE_LENGTH + usize::from(share)])
            .collect();
        let hashes: Vec<[u8; 32]> = preimages.iter().map(|preimage| hash(preimage)).collect();
        let mut seen_direct = [false; DECK_SIZE as usize];
        let mut seen_wrapped = [false; DECK_SIZE as usize];

        for a in 0_u8..DECK_SIZE {
            for b in 0_u8..DECK_SIZE {
                let raw_sum = u16::from(a) + u16::from(b);
                let card = u8::try_from(if raw_sum >= u16::from(DECK_SIZE) {
                    raw_sum - u16::from(DECK_SIZE)
                } else {
                    raw_sum
                })?;
                if raw_sum == u16::from(card) {
                    seen_direct[usize::from(card)] = true;
                } else {
                    seen_wrapped[usize::from(card)] = true;
                }

                let script =
                    card_opening_tapscript(&hashes[usize::from(a)], &hashes[usize::from(b)], card)?;
                assert!(execute_card_script(
                    &script,
                    &preimages[usize::from(a)],
                    &preimages[usize::from(b)]
                )?);

                let wrong_card = if card + 1 == DECK_SIZE { 0 } else { card + 1 };
                let wrong_script = card_opening_tapscript(
                    &hashes[usize::from(a)],
                    &hashes[usize::from(b)],
                    wrong_card,
                )?;
                assert!(!execute_card_script(
                    &wrong_script,
                    &preimages[usize::from(a)],
                    &preimages[usize::from(b)]
                )?);
            }
        }

        assert!(seen_direct.into_iter().all(core::convert::identity));
        // A wrapped raw sum of 103 is unreachable because both shares are at
        // most 51, so card 51 correctly has only the direct branch.
        assert!(
            seen_wrapped[..usize::from(DECK_SIZE - 1)]
                .iter()
                .all(|seen| *seen)
        );
        assert!(!seen_wrapped[usize::from(DECK_SIZE - 1)]);
        Ok(())
    }

    #[test]
    fn serialized_script_rejects_each_hash_and_length_failure() -> Result<(), Box<dyn Error>> {
        let preimage_a = vec![0x44_u8; BASE_PREIMAGE_LENGTH + 19];
        let preimage_b = vec![0x55_u8; BASE_PREIMAGE_LENGTH + 37];
        let card = 4;
        let script = card_opening_tapscript(&hash(&preimage_a), &hash(&preimage_b), card)?;
        assert!(execute_card_script(&script, &preimage_a, &preimage_b)?);

        let mut wrong_a = preimage_a.clone();
        wrong_a[0] ^= 1;
        assert!(!execute_card_script(&script, &wrong_a, &preimage_b)?);
        let mut wrong_b = preimage_b.clone();
        wrong_b[0] ^= 1;
        assert!(!execute_card_script(&script, &preimage_a, &wrong_b)?);

        for invalid_length in [
            BASE_PREIMAGE_LENGTH - 1,
            MAX_PREIMAGE_LENGTH + 1,
            MAX_SCRIPT_ELEMENT_SIZE + 1,
        ] {
            let invalid = vec![0x66_u8; invalid_length];
            assert!(!execute_card_script(&script, &invalid, &preimage_b)?);
            assert!(!execute_card_script(&script, &preimage_a, &invalid)?);
        }
        Ok(())
    }

    #[test]
    fn every_reachable_card_branch_builds_a_bounded_taproot_witness() -> Result<(), Box<dyn Error>>
    {
        let (secp, key) = internal_key()?;
        for card in 0_u8..DECK_SIZE {
            let branches = [
                Some((card, 0_u8)),
                (card < DECK_SIZE - 1).then_some((DECK_SIZE - 1, card + 1)),
            ];
            for (a, b) in branches.into_iter().flatten() {
                let preimage_a = vec![a; BASE_PREIMAGE_LENGTH + usize::from(a)];
                let preimage_b = vec![b; BASE_PREIMAGE_LENGTH + usize::from(b)];
                let template = CardOpeningTemplate::new_with_key_path_bypass(
                    &secp,
                    key,
                    hash(&preimage_a),
                    hash(&preimage_b),
                    card,
                )?;
                let witness = template.satisfy(&preimage_a, &preimage_b)?;
                assert_eq!(witness.len(), 4);
                assert!(
                    witness
                        .iter()
                        .all(|element| element.len() <= MAX_SCRIPT_ELEMENT_SIZE)
                );
                assert!(execute_card_script(
                    template.script(),
                    &preimage_a,
                    &preimage_b
                )?);
            }
        }
        Ok(())
    }

    #[test]
    fn template_commits_leaf_and_builds_bounded_witness() -> Result<(), Box<dyn std::error::Error>>
    {
        let preimage_a = vec![0xa5_u8; BASE_PREIMAGE_LENGTH + 51];
        let preimage_b = vec![0x5a_u8; BASE_PREIMAGE_LENGTH + 1];
        let (secp, key) = internal_key()?;
        let template = CardOpeningTemplate::new_with_key_path_bypass(
            &secp,
            key,
            hash(&preimage_a),
            hash(&preimage_b),
            0,
        )?;
        let witness = template.satisfy(&preimage_a, &preimage_b)?;

        assert!(template.script_pubkey().is_p2tr());
        assert_eq!(witness.len(), 4);
        assert!(
            witness
                .iter()
                .all(|element| element.len() <= MAX_SCRIPT_ELEMENT_SIZE)
        );
        let control = template
            .spend_info()
            .control_block(&(
                template.script().clone(),
                bitcoin::taproot::LeafVersion::TapScript,
            ))
            .ok_or_else(|| std::io::Error::other("missing one-leaf control block"))?;
        assert!(control.verify_taproot_commitment(
            &secp,
            template.spend_info().output_key().to_x_only_public_key(),
            template.script(),
        ));
        Ok(())
    }

    #[test]
    fn script_path_only_template_uses_the_fixed_nums_internal_key() -> Result<(), Box<dyn Error>> {
        let secp = Secp256k1::new();
        let preimage_a = vec![0x31_u8; BASE_PREIMAGE_LENGTH + 3];
        let preimage_b = vec![0x42_u8; BASE_PREIMAGE_LENGTH + 5];
        let template = CardOpeningTemplate::new_script_path_only(
            &secp,
            hash(&preimage_a),
            hash(&preimage_b),
            8,
        )?;
        assert_eq!(
            template.spend_info().internal_key().serialize(),
            SCRIPT_PATH_NUMS_KEY
        );
        assert!(template.satisfy(&preimage_a, &preimage_b).is_ok());
        Ok(())
    }

    #[test]
    fn witness_builder_rejects_a_wrong_card_or_hash() -> Result<(), Box<dyn std::error::Error>> {
        let preimage_a = vec![1_u8; BASE_PREIMAGE_LENGTH + 3];
        let preimage_b = vec![2_u8; BASE_PREIMAGE_LENGTH + 4];
        let (secp, key) = internal_key()?;
        let template = CardOpeningTemplate::new_with_key_path_bypass(
            &secp,
            key,
            hash(&preimage_a),
            hash(&preimage_b),
            7,
        )?;

        let mut wrong = preimage_a.clone();
        wrong[0] ^= 1;
        assert!(matches!(
            template.satisfy(&wrong, &preimage_b),
            Err(ScriptTemplateError::InvalidOpening(_))
        ));

        let wrong_card_template = CardOpeningTemplate::new_with_key_path_bypass(
            &secp,
            key,
            hash(&preimage_a),
            hash(&preimage_b),
            8,
        )?;
        assert!(matches!(
            wrong_card_template.satisfy(&preimage_a, &preimage_b),
            Err(ScriptTemplateError::InvalidOpening(
                crate::opening::OpeningError::CardMismatch { .. }
            ))
        ));
        Ok(())
    }
}
