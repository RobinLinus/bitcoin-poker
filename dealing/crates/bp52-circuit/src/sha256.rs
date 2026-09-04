//! Fixed-shape SHA-256 compression constraints.
//!
//! Words are arrays of 32 bits in most-significant-bit-first order.  A message
//! block is likewise the concatenation of its 64 bytes, with the high bit of
//! each byte first.  This representation makes the FIPS 180-4 big-endian word
//! parsing explicit at the gadget boundary.

use bp52_proof_backend::{ConstraintSystem, LinearCombination, R1CSError, Scalar};

use crate::boolean::Bit;

/// Version string committed into the circuit manifest.
pub const SHA256_COMPRESSION_GADGET_VERSION: &str = "bp52-sha256-compress-msb-v2-fused-round-add";

/// Number of Boolean bits in a SHA-256 word.
pub const WORD_BITS: usize = 32;
/// Number of bytes in one SHA-256 compression block.
pub const BLOCK_BYTES: usize = 64;
/// Number of Boolean bits in one SHA-256 compression block.
pub const BLOCK_BITS: usize = BLOCK_BYTES * 8;
/// Number of words in the SHA-256 chaining state.
pub const STATE_WORDS: usize = 8;
/// Number of expanded words in the SHA-256 message schedule.
pub const SCHEDULE_WORDS: usize = 64;

/// Multipliers used by [`compress`] excluding allocation of the input block.
///
/// This exact value is part of the fixed circuit shape.  It consists of 7,776
/// schedule multipliers, 18,816 round multipliers, and 264 feed-forward
/// multipliers.
pub const COMPRESSION_MULTIPLIERS: usize = 26_856;

/// Explicit linear constraints used by [`compress`], excluding input block
/// allocation and any constraints tying the output to a public digest.
pub const COMPRESSION_CONSTRAINTS: usize = 53_896;

/// A 32-bit SHA-256 word, stored most-significant bit first.
pub type Word = [Bit; WORD_BITS];
/// A 512-bit SHA-256 block, stored in FIPS byte and bit order.
pub type MessageBlock = [Bit; BLOCK_BITS];
/// The eight-word SHA-256 chaining state.
pub type CompressionState = [Word; STATE_WORDS];

/// FIPS 180-4 SHA-256 initial hash value.
pub const SHA256_IV: [u32; STATE_WORDS] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// FIPS 180-4 SHA-256 round constants.
pub const SHA256_ROUND_CONSTANTS: [u32; SCHEDULE_WORDS] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Allocates all 512 bits of a private message block.
///
/// `witness` is `Some` for the prover and `None` for the verifier.  Bits are
/// allocated in byte order and most-significant-bit-first within each byte.
///
/// # Errors
///
/// Returns [`R1CSError::MissingAssignment`] if prover-side synthesis is
/// requested without a block witness, or a gadget error if the fixed block
/// width cannot be constructed.
pub fn allocate_message_block<CS: ConstraintSystem>(
    cs: &mut CS,
    witness: Option<&[u8; BLOCK_BYTES]>,
) -> Result<MessageBlock, R1CSError> {
    let mut bits = Vec::with_capacity(BLOCK_BITS);
    for byte_index in 0..BLOCK_BYTES {
        for bit_index in 0..8 {
            let assignment = witness.map(|bytes| {
                let mask = 1_u8 << (7 - bit_index);
                bytes[byte_index] & mask != 0
            });
            bits.push(Bit::allocate(cs, assignment)?);
        }
    }
    bits.try_into()
        .map_err(|_| gadget_error("invalid SHA-256 block width"))
}

/// Returns a constant word in most-significant-bit-first order.
pub fn constant_word(value: u32) -> Word {
    core::array::from_fn(|index| Bit::constant(value & (1_u32 << (31 - index)) != 0))
}

/// Returns a constant SHA-256 chaining state.
pub fn constant_state(words: [u32; STATE_WORDS]) -> CompressionState {
    words.map(constant_word)
}

/// Returns the standard SHA-256 initial chaining state.
pub fn initial_state() -> CompressionState {
    constant_state(SHA256_IV)
}

/// Synthesizes one complete FIPS 180-4 SHA-256 compression invocation.
///
/// The same function is called with a Bulletproof [`bp52_proof_backend::Prover`]
/// and [`bp52_proof_backend::Verifier`], preventing prover/verifier circuit
/// drift.  The shape is independent of all assignments.
///
/// # Errors
///
/// Returns an R1CS allocation error if a required prover assignment is absent.
pub fn compress<CS: ConstraintSystem>(
    cs: &mut CS,
    input_state: &CompressionState,
    block: &MessageBlock,
) -> Result<CompressionState, R1CSError> {
    let mut schedule = Vec::with_capacity(SCHEDULE_WORDS);

    // FIPS 180-4 parses each group of four bytes as one big-endian word.
    for word_index in 0..16 {
        schedule.push(core::array::from_fn(|bit_index| {
            block[word_index * WORD_BITS + bit_index].clone()
        }));
    }
    for word_index in 16..SCHEDULE_WORDS {
        let sigma_zero = small_sigma_zero(cs, &schedule[word_index - 15]);
        let sigma_one = small_sigma_one(cs, &schedule[word_index - 2]);
        let expanded = add_words(
            cs,
            &[
                &schedule[word_index - 16],
                &sigma_zero,
                &schedule[word_index - 7],
                &sigma_one,
            ],
        )?;
        schedule.push(expanded);
    }

    let mut work_a = input_state[0].clone();
    let mut work_b = input_state[1].clone();
    let mut work_c = input_state[2].clone();
    let mut work_d = input_state[3].clone();
    let mut work_e = input_state[4].clone();
    let mut work_f = input_state[5].clone();
    let mut work_g = input_state[6].clone();
    let mut work_h = input_state[7].clone();

    for round in 0..SCHEDULE_WORDS {
        let sum_one = big_sigma_one(cs, &work_e);
        let choice = choice_word(cs, &work_e, &work_f, &work_g);
        let round_constant = constant_word(SHA256_ROUND_CONSTANTS[round]);
        let sum_zero = big_sigma_zero(cs, &work_a);
        let majority = majority_word(cs, &work_a, &work_b, &work_c);

        // FIPS defines T1 and T2 as intermediate words and then sets
        // e' = d + T1 and a' = T1 + T2 modulo 2^32.  Expanding those sums
        // directly is the same integer relation, while avoiding two
        // unnecessary 32-bit decompositions per round.  Both expanded sums
        // remain below 2^35, so `add_words` cannot wrap in the scalar field.
        let next_e = add_words(
            cs,
            &[
                &work_d,
                &work_h,
                &sum_one,
                &choice,
                &round_constant,
                &schedule[round],
            ],
        )?;
        let next_a = add_words(
            cs,
            &[
                &work_h,
                &sum_one,
                &choice,
                &round_constant,
                &schedule[round],
                &sum_zero,
                &majority,
            ],
        )?;
        work_h = work_g;
        work_g = work_f;
        work_f = work_e;
        work_e = next_e;
        work_d = work_c;
        work_c = work_b;
        work_b = work_a;
        work_a = next_a;
    }

    let working = [
        work_a, work_b, work_c, work_d, work_e, work_f, work_g, work_h,
    ];
    let mut output = Vec::with_capacity(STATE_WORDS);
    for index in 0..STATE_WORDS {
        output.push(add_words(cs, &[&input_state[index], &working[index]])?);
    }
    output
        .try_into()
        .map_err(|_| gadget_error("invalid SHA-256 state width"))
}

/// Constrains a compression output to equal a public 32-byte digest.
pub fn constrain_digest<CS: ConstraintSystem>(
    cs: &mut CS,
    state: &CompressionState,
    digest: &[u8; 32],
) {
    for (word_index, word) in state.iter().enumerate() {
        for (bit_index, bit) in word.iter().enumerate() {
            let digest_bit_index = word_index * WORD_BITS + bit_index;
            let byte = digest[digest_bit_index / 8];
            let expected = byte & (1_u8 << (7 - digest_bit_index % 8)) != 0;
            cs.constrain(bit.linear_combination() - Scalar::from(u64::from(expected)));
        }
    }
}

/// Reconstructs an assigned SHA-256 state as 32 big-endian bytes.
///
/// Returns `None` for verifier-side synthesis, where assignments are absent.
#[must_use]
pub fn assigned_state_bytes(state: &CompressionState) -> Option<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    for (word_index, word) in state.iter().enumerate() {
        let value = assigned_word(word)?;
        let encoded = value.to_be_bytes();
        bytes[word_index * 4..word_index * 4 + 4].copy_from_slice(&encoded);
    }
    Some(bytes)
}

fn small_sigma_zero<CS: ConstraintSystem>(cs: &mut CS, word: &Word) -> Word {
    xor3_words(
        cs,
        &rotate_right(word, 7),
        &rotate_right(word, 18),
        &shift_right(word, 3),
    )
}

fn small_sigma_one<CS: ConstraintSystem>(cs: &mut CS, word: &Word) -> Word {
    xor3_words(
        cs,
        &rotate_right(word, 17),
        &rotate_right(word, 19),
        &shift_right(word, 10),
    )
}

fn big_sigma_zero<CS: ConstraintSystem>(cs: &mut CS, word: &Word) -> Word {
    xor3_words(
        cs,
        &rotate_right(word, 2),
        &rotate_right(word, 13),
        &rotate_right(word, 22),
    )
}

fn big_sigma_one<CS: ConstraintSystem>(cs: &mut CS, word: &Word) -> Word {
    xor3_words(
        cs,
        &rotate_right(word, 6),
        &rotate_right(word, 11),
        &rotate_right(word, 25),
    )
}

fn rotate_right(word: &Word, amount: usize) -> Word {
    core::array::from_fn(|index| word[(index + WORD_BITS - amount) % WORD_BITS].clone())
}

fn shift_right(word: &Word, amount: usize) -> Word {
    core::array::from_fn(|index| {
        if index < amount {
            Bit::constant(false)
        } else {
            word[index - amount].clone()
        }
    })
}

fn xor3_words<CS: ConstraintSystem>(cs: &mut CS, left: &Word, middle: &Word, right: &Word) -> Word {
    core::array::from_fn(|index| left[index].xor3(cs, &middle[index], &right[index]))
}

fn choice_word<CS: ConstraintSystem>(
    cs: &mut CS,
    selector: &Word,
    when_true: &Word,
    when_false: &Word,
) -> Word {
    core::array::from_fn(|index| selector[index].choice(cs, &when_true[index], &when_false[index]))
}

fn majority_word<CS: ConstraintSystem>(
    cs: &mut CS,
    first: &Word,
    second: &Word,
    third: &Word,
) -> Word {
    core::array::from_fn(|index| first[index].majority(cs, &second[index], &third[index]))
}

/// Adds two or more 32-bit words modulo `2^32`.
///
/// Every result bit and every carry bit is Boolean-constrained.  The linear
/// equation
///
/// `sum(inputs) = result + 2^32 * carry`
///
/// then uniquely fixes the result and carry: all represented values are below
/// `2^35`, far below the scalar-field modulus, so the equation cannot wrap in
/// the field.
fn add_words<CS: ConstraintSystem>(cs: &mut CS, words: &[&Word]) -> Result<Word, R1CSError> {
    if !(2..=7).contains(&words.len()) {
        return Err(gadget_error("SHA-256 addition arity must be in 2..=7"));
    }

    let total_assignment = words.iter().try_fold(0_u64, |total, word| {
        assigned_word(word).map(|value| total + u64::from(value))
    });
    let result_assignment =
        total_assignment.and_then(|total| u32::try_from(total & u64::from(u32::MAX)).ok());
    let carry_assignment = total_assignment.map(|total| total >> 32);

    let result = allocate_word(cs, result_assignment)?;
    let carry_width = carry_width(words.len());
    let mut carry = Vec::with_capacity(carry_width);
    for index in 0..carry_width {
        let assignment = carry_assignment.map(|value| value & (1_u64 << index) != 0);
        carry.push(Bit::allocate(cs, assignment)?);
    }

    let mut relation = LinearCombination::from(Scalar::ZERO);
    for word in words {
        relation = relation + unsigned_word_linear_combination(word);
    }
    relation = relation - unsigned_word_linear_combination(&result);
    for (index, bit) in carry.iter().enumerate() {
        let coefficient = Scalar::from((1_u64 << 32) * (1_u64 << index));
        relation = relation - bit.linear_combination() * coefficient;
    }
    cs.constrain(relation);

    Ok(result)
}

fn allocate_word<CS: ConstraintSystem>(
    cs: &mut CS,
    assignment: Option<u32>,
) -> Result<Word, R1CSError> {
    let mut bits = Vec::with_capacity(WORD_BITS);
    for index in 0..WORD_BITS {
        let bit_assignment = assignment.map(|value| value & (1_u32 << (31 - index)) != 0);
        bits.push(Bit::allocate(cs, bit_assignment)?);
    }
    bits.try_into()
        .map_err(|_| gadget_error("invalid SHA-256 word width"))
}

fn assigned_word(word: &Word) -> Option<u32> {
    let mut value = 0_u32;
    for (index, bit) in word.iter().enumerate() {
        if bit.assignment()? {
            value |= 1_u32 << (31 - index);
        }
    }
    Some(value)
}

fn unsigned_word_linear_combination(word: &Word) -> LinearCombination {
    word.iter().enumerate().fold(
        LinearCombination::from(Scalar::ZERO),
        |sum, (index, bit)| sum + bit.linear_combination() * Scalar::from(1_u64 << (31 - index)),
    )
}

fn carry_width(arity: usize) -> usize {
    // The quotient of adding `arity` 32-bit values is at most `arity - 1`.
    let maximum_carry = arity - 1;
    let mut width = 0_usize;
    let mut represented_values = 1_usize;
    while represented_values <= maximum_carry {
        width += 1;
        represented_values <<= 1;
    }
    width
}

fn gadget_error(description: &str) -> R1CSError {
    R1CSError::GadgetError {
        description: description.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use bp52_group::ProtocolGenerators;
    use bp52_proof_backend::{BackendParameters, ConstraintSystem, Prover, Transcript, Verifier};
    use sha2::{Digest, Sha256};

    use super::{
        BLOCK_BYTES, COMPRESSION_CONSTRAINTS, COMPRESSION_MULTIPLIERS, allocate_message_block,
        assigned_state_bytes, compress, constrain_digest, initial_state,
    };

    const BLOCK_ALLOCATION_MULTIPLIERS: usize = 512;
    const BLOCK_ALLOCATION_CONSTRAINTS: usize = 1_024;
    const DIGEST_CONSTRAINTS: usize = 256;

    #[test]
    fn compression_matches_fips_abc_vector_and_exact_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        differential_case(b"abc")
    }

    #[test]
    fn compression_matches_fips_empty_vector_and_exact_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        differential_case(b"")
    }

    #[test]
    #[ignore = "full 27,368-multiplier Bulletproof is intentionally expensive"]
    fn full_compression_relation_proves_and_verifies() -> Result<(), Box<dyn std::error::Error>> {
        let message = b"abc";
        let block_bytes = one_block_padding(message)?;
        let expected: [u8; 32] = Sha256::digest(message).into();
        let generators = ProtocolGenerators::derive()?;
        let parameters = BackendParameters::new(32_768, &generators)?;

        let mut prover = Prover::new(
            parameters.pedersen(),
            Transcript::new(b"BP52/sha256-full-proof-test/v1"),
        );
        let block = allocate_message_block(&mut prover, Some(&block_bytes))?;
        let output = compress(&mut prover, &initial_state(), &block)?;
        constrain_digest(&mut prover, &output, &expected);
        let proof = prover.prove(parameters.bulletproof())?;

        let mut verifier = Verifier::new(Transcript::new(b"BP52/sha256-full-proof-test/v1"));
        let block = allocate_message_block(&mut verifier, None)?;
        let output = compress(&mut verifier, &initial_state(), &block)?;
        constrain_digest(&mut verifier, &output, &expected);
        verifier.verify(&proof, parameters.pedersen(), parameters.bulletproof())?;
        Ok(())
    }

    fn differential_case(message: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let block_bytes = one_block_padding(message)?;
        let expected: [u8; 32] = Sha256::digest(message).into();
        let generators = ProtocolGenerators::derive()?;
        let parameters = BackendParameters::new(32_768, &generators)?;

        let mut prover = Prover::new(
            parameters.pedersen(),
            Transcript::new(b"BP52/sha256-differential-test/v1"),
        );
        let block = allocate_message_block(&mut prover, Some(&block_bytes))?;
        let output = compress(&mut prover, &initial_state(), &block)?;
        assert_eq!(assigned_state_bytes(&output), Some(expected));
        constrain_digest(&mut prover, &output, &expected);
        let prover_metrics = prover.metrics();
        assert_eq!(
            prover_metrics.multipliers,
            BLOCK_ALLOCATION_MULTIPLIERS + COMPRESSION_MULTIPLIERS
        );
        assert_eq!(
            prover_metrics.constraints,
            BLOCK_ALLOCATION_CONSTRAINTS + COMPRESSION_CONSTRAINTS + DIGEST_CONSTRAINTS
        );

        let mut verifier = Verifier::new(Transcript::new(b"BP52/sha256-differential-test/v1"));
        let block = allocate_message_block(&mut verifier, None)?;
        let output = compress(&mut verifier, &initial_state(), &block)?;
        constrain_digest(&mut verifier, &output, &expected);
        let verifier_metrics = verifier.metrics();
        assert_eq!(verifier_metrics.multipliers, prover_metrics.multipliers);
        assert_eq!(verifier_metrics.constraints, prover_metrics.constraints);
        Ok(())
    }

    fn one_block_padding(message: &[u8]) -> Result<[u8; BLOCK_BYTES], Box<dyn std::error::Error>> {
        if message.len() > 55 {
            return Err(std::io::Error::other("message does not fit one SHA-256 block").into());
        }
        let mut block = [0_u8; BLOCK_BYTES];
        block[..message.len()].copy_from_slice(message);
        block[message.len()] = 0x80;
        let bit_length = u64::try_from(message.len())? * 8;
        block[56..].copy_from_slice(&bit_length.to_be_bytes());
        Ok(block)
    }
}
