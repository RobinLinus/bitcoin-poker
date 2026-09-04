//! Typed codecs for each body in the canonical attempt schedule.

use bp52_codec::{CodecError, Decode, Encode, Reader, Writer};
use bp52_group::PublicKeyShare;
use bp52_sigma::schnorr::KeyProof;
use bp52_uniqueness::{PartialDecryptionBatch, ScaleRound};

use crate::messages::{PayloadType, PlayerBundle};

/// A fixed 32-byte commit-flight body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitmentPayload {
    /// Tagged commitment digest.
    pub commitment: [u8; 32],
}

impl Encode for CommitmentPayload {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.commitment.encode(writer)
    }
}

impl Decode for CommitmentPayload {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            commitment: Decode::decode(reader)?,
        })
    }
}

/// Opening of one per-attempt threshold public-key share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyOpenPayload {
    /// Fresh hiding nonce committed in the preceding flight.
    pub nonce: [u8; 32],
    /// Canonical nonidentity Ristretto public-key share.
    pub public_key: PublicKeyShare,
}

impl Encode for KeyOpenPayload {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.nonce.encode(writer)?;
        self.public_key.to_bytes().encode(writer)
    }
}

impl Decode for KeyOpenPayload {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        let nonce = Decode::decode(reader)?;
        let public_key = PublicKeyShare::from_bytes(Decode::decode(reader)?)
            .map_err(|_| CodecError::NonCanonical)?;
        Ok(Self { nonce, public_key })
    }
}

/// Opening of one committed player bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleOpenPayload {
    /// Fresh hiding nonce committed with the canonical bundle bytes.
    pub nonce: [u8; 32],
    /// Complete nine-slot bundle and both independent proof systems.
    pub bundle: PlayerBundle,
}

impl Encode for BundleOpenPayload {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.nonce.encode(writer)?;
        self.bundle.encode(writer)
    }
}

impl Decode for BundleOpenPayload {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            nonce: Decode::decode(reader)?,
            bundle: PlayerBundle::decode(reader)?,
        })
    }
}

/// Opening of one committed partial-decryption batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecryptOpenPayload {
    /// Fresh hiding nonce committed with the canonical batch bytes.
    pub nonce: [u8; 32],
    /// All 108 partial decryptions and their same-key proof.
    pub batch: PartialDecryptionBatch,
}

impl Encode for DecryptOpenPayload {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.nonce.encode(writer)?;
        self.batch.encode(writer)
    }
}

impl Decode for DecryptOpenPayload {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            nonce: Decode::decode(reader)?,
            batch: PartialDecryptionBatch::decode(reader)?,
        })
    }
}

/// One fully typed v1 envelope body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolPayload {
    /// Commitment to a hidden key share.
    KeyCommit(CommitmentPayload),
    /// Key-share commitment opening.
    KeyOpen(KeyOpenPayload),
    /// Threshold-key Schnorr proof of possession.
    KeyProof(KeyProof),
    /// Commitment to a hidden player bundle.
    BundleCommit(CommitmentPayload),
    /// Player-bundle commitment opening.
    BundleOpen(Box<BundleOpenPayload>),
    /// First 108-entry scale round.
    BlindFirst(Box<ScaleRound>),
    /// Second 108-entry scale round.
    BlindSecond(Box<ScaleRound>),
    /// Commitment to a hidden partial-decryption batch.
    DecryptCommit(CommitmentPayload),
    /// Partial-decryption commitment opening.
    DecryptOpen(Box<DecryptOpenPayload>),
}

impl ProtocolPayload {
    /// Returns the only payload identifier valid for this body.
    #[must_use]
    pub const fn payload_type(&self) -> PayloadType {
        match self {
            Self::KeyCommit(_) => PayloadType::KeyCommit,
            Self::KeyOpen(_) => PayloadType::KeyOpen,
            Self::KeyProof(_) => PayloadType::KeyProof,
            Self::BundleCommit(_) => PayloadType::BundleCommit,
            Self::BundleOpen(_) => PayloadType::BundleOpen,
            Self::BlindFirst(_) => PayloadType::BlindFirst,
            Self::BlindSecond(_) => PayloadType::BlindSecond,
            Self::DecryptCommit(_) => PayloadType::DecryptCommit,
            Self::DecryptOpen(_) => PayloadType::DecryptOpen,
        }
    }

    /// Encodes the body without the envelope's outer length prefix.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] if an embedded object is not canonically
    /// encodable under the fixed v1 profile.
    pub fn encode_body(&self) -> Result<Vec<u8>, CodecError> {
        match self {
            Self::KeyCommit(body) | Self::BundleCommit(body) | Self::DecryptCommit(body) => {
                body.encode_to_vec()
            }
            Self::KeyOpen(body) => body.encode_to_vec(),
            Self::KeyProof(body) => body.encode_to_vec(),
            Self::BundleOpen(body) => body.encode_to_vec(),
            Self::BlindFirst(body) | Self::BlindSecond(body) => body.encode_to_vec(),
            Self::DecryptOpen(body) => body.encode_to_vec(),
        }
    }

    /// Strictly decodes a body selected by its authenticated envelope type.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError`] for incomplete, oversized, noncanonical, or
    /// trailing input. The selected type determines all fixed collection and
    /// proof sizes before any nested allocation.
    pub fn decode_exact(payload_type: PayloadType, bytes: &[u8]) -> Result<Self, CodecError> {
        match payload_type {
            PayloadType::KeyCommit => CommitmentPayload::decode_exact(bytes).map(Self::KeyCommit),
            PayloadType::KeyOpen => KeyOpenPayload::decode_exact(bytes).map(Self::KeyOpen),
            PayloadType::KeyProof => KeyProof::decode_exact(bytes).map(Self::KeyProof),
            PayloadType::BundleCommit => {
                CommitmentPayload::decode_exact(bytes).map(Self::BundleCommit)
            }
            PayloadType::BundleOpen => BundleOpenPayload::decode_exact(bytes)
                .map(Box::new)
                .map(Self::BundleOpen),
            PayloadType::BlindFirst => ScaleRound::decode_exact(bytes)
                .map(Box::new)
                .map(Self::BlindFirst),
            PayloadType::BlindSecond => ScaleRound::decode_exact(bytes)
                .map(Box::new)
                .map(Self::BlindSecond),
            PayloadType::DecryptCommit => {
                CommitmentPayload::decode_exact(bytes).map(Self::DecryptCommit)
            }
            PayloadType::DecryptOpen => DecryptOpenPayload::decode_exact(bytes)
                .map(Box::new)
                .map(Self::DecryptOpen),
        }
    }
}

#[cfg(test)]
mod tests {
    use bp52_codec::{CodecError, Decode};
    use bp52_group::{ProtocolGenerators, PublicKeyShare};
    use curve25519_dalek::Scalar;

    use super::{CommitmentPayload, KeyOpenPayload, ProtocolPayload};
    use crate::messages::PayloadType;

    #[test]
    fn commitment_and_key_open_bodies_round_trip_strictly() -> Result<(), Box<dyn std::error::Error>>
    {
        let commitment = ProtocolPayload::KeyCommit(CommitmentPayload {
            commitment: [7_u8; 32],
        });
        let commitment_bytes = commitment.encode_body()?;
        assert_eq!(
            ProtocolPayload::decode_exact(PayloadType::KeyCommit, &commitment_bytes)?,
            commitment
        );
        assert_eq!(
            ProtocolPayload::decode_exact(PayloadType::BundleCommit, &commitment_bytes)?,
            ProtocolPayload::BundleCommit(CommitmentPayload {
                commitment: [7_u8; 32],
            })
        );

        let generators = ProtocolGenerators::derive()?;
        let public_key = PublicKeyShare::new(Scalar::from(9_u64) * generators.blinding())?;
        let opening = ProtocolPayload::KeyOpen(KeyOpenPayload {
            nonce: [8_u8; 32],
            public_key,
        });
        let opening_bytes = opening.encode_body()?;
        assert_eq!(
            ProtocolPayload::decode_exact(PayloadType::KeyOpen, &opening_bytes)?,
            opening
        );

        let mut trailing = opening_bytes;
        trailing.push(0);
        assert_eq!(
            KeyOpenPayload::decode_exact(&trailing),
            Err(CodecError::TrailingBytes)
        );
        Ok(())
    }

    #[test]
    fn key_open_rejects_identity_and_wrong_length() {
        let identity = [0_u8; 64];
        assert_eq!(
            ProtocolPayload::decode_exact(PayloadType::KeyOpen, &identity),
            Err(CodecError::NonCanonical)
        );
        assert!(matches!(
            ProtocolPayload::decode_exact(PayloadType::KeyCommit, &[0_u8; 31]),
            Err(CodecError::UnexpectedEof)
        ));
    }
}
