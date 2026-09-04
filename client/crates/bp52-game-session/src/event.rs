//! Canonical session events and the tamper-evident local journal record.

use bp52_chain_types::Role;
use bp52_client_ports::{BlockRef, MAX_RAW_OBJECT_BYTES, OutPointRef};
use bp52_codec::{CodecError, Reader, Writer};

use crate::codec::{read_role, record_digest, write_role};

/// Largest single public exchange artifact accepted by the coordinator.
///
/// This accommodates one signed runtime transaction receipt. Bulk Lamport and
/// preauthorization vectors never cross into the GAME journal.
pub const MAX_EVENT_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;

/// A confirmed origin UTXO fact produced by an authenticated chain adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedOrigin {
    /// Exact configured chain profile.
    pub profile_id: [u8; 32],
    /// Confirmed origin outpoint.
    pub outpoint: OutPointRef,
    /// Origin value.
    pub value_sat: u64,
    /// Exact origin scriptPubKey.
    pub script_pubkey: Vec<u8>,
    /// Checked txid of the creating transaction.
    pub creating_txid: [u8; 32],
    /// Complete creating transaction.
    pub creating_transaction: Vec<u8>,
    /// Block containing the origin.
    pub confirmed_in: BlockRef,
    /// Best-chain tip accompanying the fact.
    pub observed_tip: BlockRef,
}

/// A best-chain fact produced by an authenticated chain adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TipFact {
    /// Exact configured chain profile.
    pub profile_id: [u8; 32],
    /// Observed best-chain block.
    pub block: BlockRef,
}

/// A confirmed spend fact produced by an authenticated chain adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainSpend {
    /// Exact configured chain profile.
    pub profile_id: [u8; 32],
    /// Outpoint the reported transaction consumed.
    pub spent_outpoint: OutPointRef,
    /// Checked transaction identifier.
    pub spending_txid: [u8; 32],
    /// Complete witness-bearing transaction.
    pub spending_transaction: Vec<u8>,
    /// Input index consuming `spent_outpoint`.
    pub input_index: u32,
    /// Block containing the spend.
    pub confirmed_in: BlockRef,
    /// Best-chain tip accompanying the fact.
    pub observed_tip: BlockRef,
}

/// Every input accepted by the deterministic session reducer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionEvent {
    /// The exact shared origin became sufficiently confirmed.
    OriginConfirmed(ConfirmedOrigin),
    /// One canonical signed DEAL envelope.
    DealEnvelope(Vec<u8>),
    /// Opaque identity-signed result from the local disposable DEAL verifier.
    DealVerificationAttested(Vec<u8>),
    /// One role's signature on the verifier-derived accepted-deal body.
    AcceptedDealSignature {
        /// Signing participant.
        role: Role,
        /// BIP340 signature bytes.
        signature: [u8; 64],
    },
    /// One identity authorized a fresh DEAL attempt after a verifier-proven
    /// collision/degenerate transcript.
    DealRetrySignature {
        /// Exact next attempt number.
        next_attempt: u32,
        /// Signing participant.
        role: Role,
        /// BIP340 approval signature.
        signature: [u8; 64],
    },
    /// One identity signature over the deterministic chain descriptor.
    DescriptorSignature {
        /// Signing participant.
        role: Role,
        /// Canonical descriptor bytes.
        descriptor: Vec<u8>,
        /// BIP340 signature bytes.
        signature: [u8; 64],
    },
    /// Compact local CHAIN receipt for complete graph/setup verification.
    GraphPrepared(Vec<u8>),
    /// Fully signed origin-to-gameplay-root transaction.
    ActivationAuthorized(Vec<u8>),
    /// New authenticated best-chain tip.
    TipObserved(TipFact),
    /// Compact local CHAIN receipt for one authorized runtime transaction.
    RuntimeAuthorized(Vec<u8>),
    /// Confirmed activation or gameplay child spend.
    SpendConfirmed(ChainSpend),
    /// Compact local CHAIN receipt for a verified confirmed state transition.
    StateConfirmed(Vec<u8>),
}

impl SessionEvent {
    /// Encode this event with exact widths and bounded byte vectors.
    ///
    /// # Errors
    ///
    /// Returns a codec error for oversized public artifacts.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut writer = Writer::new();
        match self {
            Self::OriginConfirmed(fact) => {
                writer.write_u8(0);
                encode_origin(&mut writer, fact)?;
            }
            Self::DealEnvelope(bytes) => {
                writer.write_u8(1);
                write_artifact(&mut writer, bytes)?;
            }
            Self::DealVerificationAttested(bytes) => encode_artifact(2, &mut writer, bytes)?,
            Self::AcceptedDealSignature { role, signature } => {
                writer.write_u8(3);
                write_role(&mut writer, *role);
                writer.write_bytes(signature);
            }
            Self::DealRetrySignature {
                next_attempt,
                role,
                signature,
            } => {
                writer.write_u8(4);
                writer.write_u32(*next_attempt);
                write_role(&mut writer, *role);
                writer.write_bytes(signature);
            }
            Self::DescriptorSignature {
                role,
                descriptor,
                signature,
            } => {
                writer.write_u8(5);
                write_role(&mut writer, *role);
                write_artifact(&mut writer, descriptor)?;
                writer.write_bytes(signature);
            }
            Self::GraphPrepared(bytes) => encode_artifact(6, &mut writer, bytes)?,
            Self::ActivationAuthorized(bytes) => encode_raw_transaction(7, &mut writer, bytes)?,
            Self::TipObserved(fact) => {
                writer.write_u8(8);
                writer.write_bytes(&fact.profile_id);
                encode_block(&mut writer, fact.block);
            }
            Self::RuntimeAuthorized(bytes) => encode_artifact(9, &mut writer, bytes)?,
            Self::SpendConfirmed(fact) => {
                writer.write_u8(10);
                encode_spend(&mut writer, fact)?;
            }
            Self::StateConfirmed(bytes) => encode_artifact(11, &mut writer, bytes)?,
        }
        Ok(writer.into_bytes())
    }

    /// Strictly decode one complete canonical event.
    ///
    /// # Errors
    ///
    /// Returns a codec error for unknown tags, noncanonical roles, lengths,
    /// truncation, or trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(bytes);
        let value = match reader.read_u8()? {
            0 => Self::OriginConfirmed(decode_origin(&mut reader)?),
            1 => Self::DealEnvelope(read_artifact(&mut reader)?),
            2 => Self::DealVerificationAttested(read_artifact(&mut reader)?),
            3 => Self::AcceptedDealSignature {
                role: read_role(&mut reader)?,
                signature: reader.read_array()?,
            },
            4 => Self::DealRetrySignature {
                next_attempt: reader.read_u32()?,
                role: read_role(&mut reader)?,
                signature: reader.read_array()?,
            },
            5 => Self::DescriptorSignature {
                role: read_role(&mut reader)?,
                descriptor: read_artifact(&mut reader)?,
                signature: reader.read_array()?,
            },
            6 => Self::GraphPrepared(read_artifact(&mut reader)?),
            7 => Self::ActivationAuthorized(read_raw_transaction(&mut reader)?),
            8 => Self::TipObserved(TipFact {
                profile_id: reader.read_array()?,
                block: decode_block(&mut reader)?,
            }),
            9 => Self::RuntimeAuthorized(read_artifact(&mut reader)?),
            10 => Self::SpendConfirmed(decode_spend(&mut reader)?),
            11 => Self::StateConfirmed(read_artifact(&mut reader)?),
            _ => return Err(CodecError::NonCanonical),
        };
        reader.finish()?;
        Ok(value)
    }
}

/// One accepted event in the canonical hash-chained journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRecord {
    /// Zero-based contiguous journal sequence.
    pub sequence: u64,
    /// Digest of the preceding record, or zero for the first record.
    pub previous_hash: [u8; 32],
    /// Canonical event.
    pub event: SessionEvent,
    /// Digest over the config binding, sequence, predecessor, and event bytes.
    pub record_hash: [u8; 32],
}

impl EventRecord {
    pub(crate) fn new(
        config_hash: [u8; 32],
        sequence: u64,
        previous_hash: [u8; 32],
        event: SessionEvent,
    ) -> Result<Self, CodecError> {
        let event_bytes = event.encode()?;
        let record_hash = record_digest(config_hash, sequence, previous_hash, &event_bytes)?;
        Ok(Self {
            sequence,
            previous_hash,
            event,
            record_hash,
        })
    }

    pub(crate) fn encode_into(&self, writer: &mut Writer) -> Result<(), CodecError> {
        writer.write_u64(self.sequence);
        writer.write_bytes(&self.previous_hash);
        writer.write_byte_vector(&self.event.encode()?)?;
        writer.write_bytes(&self.record_hash);
        Ok(())
    }

    pub(crate) fn decode_from(
        reader: &mut Reader<'_>,
        config_hash: [u8; 32],
    ) -> Result<Self, CodecError> {
        let sequence = reader.read_u64()?;
        let previous_hash = reader.read_array()?;
        let event_bytes = reader.read_byte_vector(MAX_EVENT_ARTIFACT_BYTES + 256)?;
        let event = SessionEvent::decode(&event_bytes)?;
        let record_hash = reader.read_array()?;
        if record_hash != record_digest(config_hash, sequence, previous_hash, &event_bytes)? {
            return Err(CodecError::NonCanonical);
        }
        Ok(Self {
            sequence,
            previous_hash,
            event,
            record_hash,
        })
    }
}

fn write_artifact(writer: &mut Writer, bytes: &[u8]) -> Result<(), CodecError> {
    if bytes.len() > MAX_EVENT_ARTIFACT_BYTES {
        return Err(CodecError::LengthLimitExceeded);
    }
    writer.write_byte_vector(bytes)
}

fn read_artifact(reader: &mut Reader<'_>) -> Result<Vec<u8>, CodecError> {
    reader.read_byte_vector(MAX_EVENT_ARTIFACT_BYTES)
}

fn encode_artifact(tag: u8, writer: &mut Writer, bytes: &[u8]) -> Result<(), CodecError> {
    writer.write_u8(tag);
    write_artifact(writer, bytes)
}

fn encode_raw_transaction(tag: u8, writer: &mut Writer, bytes: &[u8]) -> Result<(), CodecError> {
    if bytes.is_empty() || bytes.len() > MAX_RAW_OBJECT_BYTES {
        return Err(CodecError::LengthLimitExceeded);
    }
    writer.write_u8(tag);
    writer.write_byte_vector(bytes)
}

fn read_raw_transaction(reader: &mut Reader<'_>) -> Result<Vec<u8>, CodecError> {
    let bytes = reader.read_byte_vector(MAX_RAW_OBJECT_BYTES)?;
    if bytes.is_empty() {
        return Err(CodecError::NonCanonical);
    }
    Ok(bytes)
}

fn encode_outpoint(writer: &mut Writer, outpoint: OutPointRef) {
    writer.write_bytes(&outpoint.txid);
    writer.write_u32(outpoint.vout);
}

fn decode_outpoint(reader: &mut Reader<'_>) -> Result<OutPointRef, CodecError> {
    Ok(OutPointRef {
        txid: reader.read_array()?,
        vout: reader.read_u32()?,
    })
}

fn encode_block(writer: &mut Writer, block: BlockRef) {
    writer.write_u32(block.height);
    writer.write_bytes(&block.hash);
}

fn decode_block(reader: &mut Reader<'_>) -> Result<BlockRef, CodecError> {
    Ok(BlockRef {
        height: reader.read_u32()?,
        hash: reader.read_array()?,
    })
}

fn encode_origin(writer: &mut Writer, fact: &ConfirmedOrigin) -> Result<(), CodecError> {
    writer.write_bytes(&fact.profile_id);
    encode_outpoint(writer, fact.outpoint);
    writer.write_u64(fact.value_sat);
    write_artifact(writer, &fact.script_pubkey)?;
    writer.write_bytes(&fact.creating_txid);
    if fact.creating_transaction.is_empty()
        || fact.creating_transaction.len() > MAX_RAW_OBJECT_BYTES
    {
        return Err(CodecError::LengthLimitExceeded);
    }
    writer.write_byte_vector(&fact.creating_transaction)?;
    encode_block(writer, fact.confirmed_in);
    encode_block(writer, fact.observed_tip);
    Ok(())
}

fn decode_origin(reader: &mut Reader<'_>) -> Result<ConfirmedOrigin, CodecError> {
    let fact = ConfirmedOrigin {
        profile_id: reader.read_array()?,
        outpoint: decode_outpoint(reader)?,
        value_sat: reader.read_u64()?,
        script_pubkey: read_artifact(reader)?,
        creating_txid: reader.read_array()?,
        creating_transaction: read_raw_transaction(reader)?,
        confirmed_in: decode_block(reader)?,
        observed_tip: decode_block(reader)?,
    };
    Ok(fact)
}

fn encode_spend(writer: &mut Writer, fact: &ChainSpend) -> Result<(), CodecError> {
    writer.write_bytes(&fact.profile_id);
    encode_outpoint(writer, fact.spent_outpoint);
    writer.write_bytes(&fact.spending_txid);
    if fact.spending_transaction.is_empty()
        || fact.spending_transaction.len() > MAX_RAW_OBJECT_BYTES
    {
        return Err(CodecError::LengthLimitExceeded);
    }
    writer.write_byte_vector(&fact.spending_transaction)?;
    writer.write_u32(fact.input_index);
    encode_block(writer, fact.confirmed_in);
    encode_block(writer, fact.observed_tip);
    Ok(())
}

fn decode_spend(reader: &mut Reader<'_>) -> Result<ChainSpend, CodecError> {
    Ok(ChainSpend {
        profile_id: reader.read_array()?,
        spent_outpoint: decode_outpoint(reader)?,
        spending_txid: reader.read_array()?,
        spending_transaction: read_raw_transaction(reader)?,
        input_index: reader.read_u32()?,
        confirmed_in: decode_block(reader)?,
        observed_tip: decode_block(reader)?,
    })
}

#[cfg(test)]
mod tests {
    use bp52_chain_types::Role;
    use bp52_client_ports::{BlockRef, OutPointRef};
    use bp52_codec::CodecError;

    use super::{ChainSpend, ConfirmedOrigin, SessionEvent, TipFact};

    fn block(height: u32, marker: u8) -> BlockRef {
        BlockRef {
            height,
            hash: [marker; 32],
        }
    }

    fn outpoint(marker: u8, vout: u32) -> OutPointRef {
        OutPointRef {
            txid: [marker; 32],
            vout,
        }
    }

    #[test]
    fn every_event_variant_round_trips_strictly() -> Result<(), CodecError> {
        let origin = ConfirmedOrigin {
            profile_id: [1; 32],
            outpoint: outpoint(2, 3),
            value_sat: 9_999,
            script_pubkey: vec![0, 32, 4],
            creating_txid: [2; 32],
            creating_transaction: vec![5],
            confirmed_in: block(6, 7),
            observed_tip: block(8, 9),
        };
        let spend = ChainSpend {
            profile_id: [10; 32],
            spent_outpoint: outpoint(11, 12),
            spending_txid: [13; 32],
            spending_transaction: vec![14],
            input_index: 0,
            confirmed_in: block(15, 16),
            observed_tip: block(17, 18),
        };
        let events = vec![
            SessionEvent::OriginConfirmed(origin),
            SessionEvent::DealEnvelope(vec![1, 2]),
            SessionEvent::DealVerificationAttested(vec![2, 3]),
            SessionEvent::AcceptedDealSignature {
                role: Role::Alice,
                signature: [3; 64],
            },
            SessionEvent::DealRetrySignature {
                next_attempt: 4,
                role: Role::Alice,
                signature: [5; 64],
            },
            SessionEvent::DescriptorSignature {
                role: Role::Bob,
                descriptor: vec![7, 8],
                signature: [9; 64],
            },
            SessionEvent::GraphPrepared(vec![10]),
            SessionEvent::ActivationAuthorized(vec![16]),
            SessionEvent::TipObserved(TipFact {
                profile_id: [17; 32],
                block: block(18, 19),
            }),
            SessionEvent::RuntimeAuthorized(vec![20]),
            SessionEvent::SpendConfirmed(spend),
            SessionEvent::StateConfirmed(vec![21]),
        ];

        for event in events {
            let encoded = event.encode()?;
            assert_eq!(SessionEvent::decode(&encoded)?, event);
            let mut trailing = encoded;
            trailing.push(0);
            assert_eq!(
                SessionEvent::decode(&trailing),
                Err(CodecError::TrailingBytes)
            );
        }
        Ok(())
    }
}
