//! Canonical, bounded public-key and signature encodings.

use crate::{
    AliceScoreCertificate, BobScoreCertificate, HASH_SIZE, KeyContext, LamportError,
    LamportPublicKey, LamportPurpose, LamportSignature, SCORE_BIT_WIDTH, Score24,
};

const PUBLIC_KEY_MAGIC: &[u8; 8] = b"BP52OTK1";
const SIGNATURE_MAGIC: &[u8; 8] = b"BP52OTS1";
const ALICE_SCORE_CERTIFICATE_MAGIC: &[u8; 8] = b"BP52ASC1";
const BOB_SCORE_CERTIFICATE_MAGIC: &[u8; 8] = b"BP52BSC1";

impl LamportPublicKey {
    /// Encodes public key material canonically.
    ///
    /// Layout: magic, game ID, node ID, purpose, width, then two 32-byte
    /// hashes for every bit in most-significant-first order.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let pair_bytes = self.public_hash_pairs().len() * 2 * HASH_SIZE;
        let mut encoded = Vec::with_capacity(8 + 32 + 32 + 2 + pair_bytes);
        encoded.extend_from_slice(PUBLIC_KEY_MAGIC);
        encoded.extend_from_slice(&self.context().chain_game_id);
        encoded.extend_from_slice(&self.context().node_id);
        encoded.push(self.context().purpose as u8);
        encoded.push(self.context().purpose.bit_width());
        for pair in self.public_hash_pairs() {
            encoded.extend_from_slice(&pair[0]);
            encoded.extend_from_slice(&pair[1]);
        }
        encoded
    }

    /// Decodes one canonical public key and rejects trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, truncated, wrong-width, or trailing
    /// input.
    pub fn decode(encoded: &[u8]) -> Result<Self, LamportError> {
        let mut reader = Reader::new(encoded, "Lamport public key");
        reader.expect_magic(PUBLIC_KEY_MAGIC)?;
        let chain_game_id = reader.take_array()?;
        let node_id = reader.take_array()?;
        let purpose = LamportPurpose::try_from(reader.take_u8()?)?;
        let width = reader.take_u8()?;
        if width != purpose.bit_width() {
            return Err(LamportError::InvalidBitWidth {
                expected: purpose.bit_width(),
                actual: width,
            });
        }
        let mut pairs = Vec::with_capacity(usize::from(width));
        for _ in 0..width {
            pairs.push([reader.take_array()?, reader.take_array()?]);
        }
        reader.finish()?;
        Self::from_parts(KeyContext::new(chain_game_id, node_id, purpose), pairs)
    }
}

impl LamportSignature {
    /// Encodes a public signature frame canonically.
    ///
    /// This transport encoding is distinct from the Bitcoin witness stack,
    /// whose elements are returned by [`Self::preimages`].
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded =
            Vec::with_capacity(8 + 2 + self.preimages().len().saturating_mul(HASH_SIZE));
        encoded.extend_from_slice(SIGNATURE_MAGIC);
        encoded.push(self.purpose() as u8);
        encoded.push(self.purpose().bit_width());
        for preimage in self.preimages() {
            encoded.extend_from_slice(preimage);
        }
        encoded
    }

    /// Decodes one canonical public signature and rejects trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, truncated, wrong-width, or trailing
    /// input.
    pub fn decode(encoded: &[u8]) -> Result<Self, LamportError> {
        let mut reader = Reader::new(encoded, "Lamport signature");
        reader.expect_magic(SIGNATURE_MAGIC)?;
        let purpose = LamportPurpose::try_from(reader.take_u8()?)?;
        let width = reader.take_u8()?;
        if width != purpose.bit_width() {
            return Err(LamportError::InvalidBitWidth {
                expected: purpose.bit_width(),
                actual: width,
            });
        }
        let mut preimages = Vec::with_capacity(usize::from(width));
        for _ in 0..width {
            preimages.push(reader.take_array()?);
        }
        reader.finish()?;
        Self::from_parts(purpose, preimages)
    }
}

impl AliceScoreCertificate {
    /// Encodes the repeated public certificate as score plus 24 preimages.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(
            ALICE_SCORE_CERTIFICATE_MAGIC.len()
                + 3
                + usize::from(SCORE_BIT_WIDTH).saturating_mul(HASH_SIZE),
        );
        encoded.extend_from_slice(ALICE_SCORE_CERTIFICATE_MAGIC);
        encoded.extend_from_slice(&self.score_a().to_be_bytes());
        for preimage in self.lamport_signature().preimages() {
            encoded.extend_from_slice(preimage);
        }
        encoded
    }

    /// Decodes one fixed-width score certificate and rejects trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid score, truncation, or trailing data.
    pub fn decode(encoded: &[u8]) -> Result<Self, LamportError> {
        let mut reader = Reader::new(encoded, "Alice score certificate");
        reader.expect_magic(ALICE_SCORE_CERTIFICATE_MAGIC)?;
        let score_bytes: [u8; 3] = reader.take_array()?;
        let score = Score24::new(u32::from_be_bytes([
            0,
            score_bytes[0],
            score_bytes[1],
            score_bytes[2],
        ]))?;
        let mut preimages = Vec::with_capacity(usize::from(SCORE_BIT_WIDTH));
        for _ in 0..SCORE_BIT_WIDTH {
            preimages.push(reader.take_array()?);
        }
        reader.finish()?;
        Self::from_parts(
            score,
            LamportSignature::from_parts(LamportPurpose::AliceScore24Bit, preimages)?,
        )
    }
}

impl BobScoreCertificate {
    /// Encodes Bob's public certificate as score plus 24 preimages.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(
            BOB_SCORE_CERTIFICATE_MAGIC.len()
                + 3
                + usize::from(SCORE_BIT_WIDTH).saturating_mul(HASH_SIZE),
        );
        encoded.extend_from_slice(BOB_SCORE_CERTIFICATE_MAGIC);
        encoded.extend_from_slice(&self.score_b().to_be_bytes());
        for preimage in self.lamport_signature().preimages() {
            encoded.extend_from_slice(preimage);
        }
        encoded
    }

    /// Decodes one fixed-width Bob score certificate and rejects trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid score, truncation, or trailing data.
    pub fn decode(encoded: &[u8]) -> Result<Self, LamportError> {
        let mut reader = Reader::new(encoded, "Bob score certificate");
        reader.expect_magic(BOB_SCORE_CERTIFICATE_MAGIC)?;
        let score_bytes: [u8; 3] = reader.take_array()?;
        let score = Score24::new(u32::from_be_bytes([
            0,
            score_bytes[0],
            score_bytes[1],
            score_bytes[2],
        ]))?;
        let mut preimages = Vec::with_capacity(usize::from(SCORE_BIT_WIDTH));
        for _ in 0..SCORE_BIT_WIDTH {
            preimages.push(reader.take_array()?);
        }
        reader.finish()?;
        Self::from_parts(
            score,
            LamportSignature::from_parts(LamportPurpose::BobScore24Bit, preimages)?,
        )
    }
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
    kind: &'static str,
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8], kind: &'static str) -> Self {
        Self {
            bytes,
            offset: 0,
            kind,
        }
    }

    pub(crate) fn expect_magic(&mut self, expected: &[u8]) -> Result<(), LamportError> {
        let found = self.take(expected.len())?;
        if found != expected {
            return Err(LamportError::InvalidEncodingPrefix { kind: self.kind });
        }
        Ok(())
    }

    pub(crate) fn take_u8(&mut self) -> Result<u8, LamportError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn take_u32(&mut self) -> Result<u32, LamportError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    pub(crate) fn take_array<const SIZE: usize>(&mut self) -> Result<[u8; SIZE], LamportError> {
        let mut output = [0_u8; SIZE];
        output.copy_from_slice(self.take(SIZE)?);
        Ok(output)
    }

    pub(crate) fn finish(self) -> Result<(), LamportError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(LamportError::TrailingData { kind: self.kind })
        }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], LamportError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(LamportError::TruncatedEncoding { kind: self.kind })?;
        let output = self
            .bytes
            .get(self.offset..end)
            .ok_or(LamportError::TruncatedEncoding { kind: self.kind })?;
        self.offset = end;
        Ok(output)
    }
}
