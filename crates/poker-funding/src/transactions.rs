//! Transactions.

use super::{
    DisplayTxid, FundingError, InputTemplate, LOCK_TIME_ZERO, OutputTemplate, SIGHASH_ALL_U32,
    VERSION_TWO, double_sha256,
};

pub(super) fn serialize_transaction(
    inputs: &[InputTemplate],
    outputs: &[OutputTemplate],
    witnesses: Option<&[Vec<Vec<u8>>]>,
) -> Result<Vec<u8>, FundingError> {
    if inputs.is_empty() || outputs.is_empty() {
        return Err(FundingError::ConstructionInvariant);
    }
    if witnesses.is_some_and(|stacks| stacks.len() != inputs.len()) {
        return Err(FundingError::ConstructionInvariant);
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&VERSION_TWO.to_le_bytes());
    if witnesses.is_some() {
        encoded.extend_from_slice(&[0, 1]);
    }
    encode_compact_size(inputs.len(), &mut encoded)?;
    for input in inputs {
        input.outpoint.encode(&mut encoded);
        encoded.push(0);
        encoded.extend_from_slice(&input.sequence.to_le_bytes());
    }
    encode_compact_size(outputs.len(), &mut encoded)?;
    for output in outputs {
        encode_output(output, &mut encoded)?;
    }
    if let Some(stacks) = witnesses {
        for stack in stacks {
            encode_compact_size(stack.len(), &mut encoded)?;
            for element in stack {
                encode_compact_size(element.len(), &mut encoded)?;
                encoded.extend_from_slice(element);
            }
        }
    }
    encoded.extend_from_slice(&LOCK_TIME_ZERO.to_le_bytes());
    Ok(encoded)
}

pub(super) fn encode_output(
    output: &OutputTemplate,
    encoded: &mut Vec<u8>,
) -> Result<(), FundingError> {
    encoded.extend_from_slice(&output.value_sat.to_le_bytes());
    encode_compact_size(output.script_pubkey.len(), encoded)?;
    encoded.extend_from_slice(&output.script_pubkey);
    Ok(())
}

pub(super) fn encode_compact_size(value: usize, encoded: &mut Vec<u8>) -> Result<(), FundingError> {
    let value = u64::try_from(value).map_err(|_| FundingError::ConstructionInvariant)?;
    match value {
        0..=0xfc => {
            encoded.push(u8::try_from(value).map_err(|_| FundingError::ConstructionInvariant)?);
        }
        0xfd..=0xffff => {
            encoded.push(0xfd);
            encoded.extend_from_slice(
                &u16::try_from(value)
                    .map_err(|_| FundingError::ConstructionInvariant)?
                    .to_le_bytes(),
            );
        }
        0x1_0000..=0xffff_ffff => {
            encoded.push(0xfe);
            encoded.extend_from_slice(
                &u32::try_from(value)
                    .map_err(|_| FundingError::ConstructionInvariant)?
                    .to_le_bytes(),
            );
        }
        _ => {
            encoded.push(0xff);
            encoded.extend_from_slice(&value.to_le_bytes());
        }
    }
    Ok(())
}

pub(super) fn bip143_sighash(
    inputs: &[InputTemplate],
    outputs: &[OutputTemplate],
    input_index: usize,
    witness_script: &[u8],
    value_sat: u64,
) -> Result<[u8; 32], FundingError> {
    let input = inputs
        .get(input_index)
        .ok_or(FundingError::ConstructionInvariant)?;
    let mut previous_outputs = Vec::with_capacity(inputs.len() * 36);
    let mut sequences = Vec::with_capacity(inputs.len() * 4);
    for candidate in inputs {
        candidate.outpoint.encode(&mut previous_outputs);
        sequences.extend_from_slice(&candidate.sequence.to_le_bytes());
    }
    let mut serialized_outputs = Vec::new();
    for output in outputs {
        encode_output(output, &mut serialized_outputs)?;
    }

    let mut preimage = Vec::new();
    preimage.extend_from_slice(&VERSION_TWO.to_le_bytes());
    preimage.extend_from_slice(&double_sha256(&previous_outputs));
    preimage.extend_from_slice(&double_sha256(&sequences));
    input.outpoint.encode(&mut preimage);
    encode_compact_size(witness_script.len(), &mut preimage)?;
    preimage.extend_from_slice(witness_script);
    preimage.extend_from_slice(&value_sat.to_le_bytes());
    preimage.extend_from_slice(&input.sequence.to_le_bytes());
    preimage.extend_from_slice(&double_sha256(&serialized_outputs));
    preimage.extend_from_slice(&LOCK_TIME_ZERO.to_le_bytes());
    preimage.extend_from_slice(&SIGHASH_ALL_U32.to_le_bytes());
    Ok(double_sha256(&preimage))
}

pub(super) fn transaction_id(unsigned_transaction: &[u8]) -> DisplayTxid {
    DisplayTxid::from_consensus_digest(double_sha256(unsigned_transaction))
}
