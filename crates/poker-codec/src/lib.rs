#![forbid(unsafe_code)]
#![doc = "Canonical bounded wire encoding for shared poker protocols."]

use core::fmt;

/// Protocol encoding and decoding errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CodecError {
    /// The input ended before the declared value was complete.
    #[error("unexpected end of input")]
    UnexpectedEof,
    /// A length prefix exceeds the caller-provided bound.
    #[error("length exceeds the protocol maximum")]
    LengthLimitExceeded,
    /// Bytes remain after decoding a complete top-level value.
    #[error("trailing bytes")]
    TrailingBytes,
    /// A value has a structurally invalid or noncanonical encoding.
    #[error("noncanonical encoding")]
    NonCanonical,
    /// The encoded size cannot be represented by the v1 `u32` length prefix.
    #[error("encoded length overflows u32")]
    LengthOverflow,
}

/// A canonical encoder backed by a byte vector.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    /// Creates an empty encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Creates an encoder with a preallocated capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Appends one byte.
    pub fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Appends a little-endian `u16`.
    pub fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a little-endian `u32`.
    pub fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a little-endian `u64`.
    pub fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends bytes without a length prefix.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    /// Appends a v1 byte vector (`u32` length followed by bytes).
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::LengthOverflow`] when `bytes` cannot be represented
    /// by the v1 `u32` length prefix.
    pub fn write_byte_vector(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        let len = u32::try_from(bytes.len()).map_err(|_| CodecError::LengthOverflow)?;
        self.write_u32(len);
        self.write_bytes(bytes);
        Ok(())
    }

    /// Returns the completed canonical encoding.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Borrows the encoding accumulated so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Writer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Writer")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// A bounded reader for canonical v1 encodings.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Creates a reader over a complete message.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    /// Returns the number of unread bytes.
    #[must_use]
    pub const fn remaining_len(&self) -> usize {
        self.remaining.len()
    }

    /// Reads exactly `len` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::UnexpectedEof`] if fewer than `len` bytes remain.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        if len > self.remaining.len() {
            return Err(CodecError::UnexpectedEof);
        }
        let (value, rest) = self.remaining.split_at(len);
        self.remaining = rest;
        Ok(value)
    }

    /// Reads a fixed-size byte array.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::UnexpectedEof`] if fewer than `N` bytes remain.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let bytes = self.read_bytes(N)?;
        bytes.try_into().map_err(|_| CodecError::UnexpectedEof)
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::UnexpectedEof`] when no byte remains.
    pub fn read_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.read_array::<1>()?[0])
    }

    /// Reads a little-endian `u16`.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::UnexpectedEof`] when fewer than two bytes remain.
    pub fn read_u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    /// Reads a little-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::UnexpectedEof`] when fewer than four bytes remain.
    pub fn read_u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    /// Reads a little-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::UnexpectedEof`] when fewer than eight bytes remain.
    pub fn read_u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    /// Reads a `u32`-length-prefixed vector after enforcing `max_len`.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::LengthLimitExceeded`] before allocating when the
    /// declared length exceeds `max_len`, or [`CodecError::UnexpectedEof`] when
    /// the declared bytes are not present.
    pub fn read_byte_vector(&mut self, max_len: usize) -> Result<Vec<u8>, CodecError> {
        let len = usize::try_from(self.read_u32()?).map_err(|_| CodecError::LengthOverflow)?;
        if len > max_len {
            return Err(CodecError::LengthLimitExceeded);
        }
        Ok(self.read_bytes(len)?.to_vec())
    }

    /// Succeeds only if the complete top-level input was consumed.
    ///
    /// # Errors
    ///
    /// Returns [`CodecError::TrailingBytes`] when unread input remains.
    pub fn finish(self) -> Result<(), CodecError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

/// A value with one canonical v1 encoding.
pub trait Encode {
    /// Appends this value to `writer`.
    ///
    /// # Errors
    ///
    /// Returns a [`CodecError`] if this value has no valid v1 encoding or an
    /// embedded length cannot be represented.
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError>;

    /// Encodes this value into a new byte vector.
    ///
    /// # Errors
    ///
    /// Propagates any error from [`Encode::encode`].
    fn encode_to_vec(&self) -> Result<Vec<u8>, CodecError> {
        let mut writer = Writer::new();
        self.encode(&mut writer)?;
        Ok(writer.into_bytes())
    }
}

/// A value decodable from the canonical v1 encoding.
pub trait Decode: Sized {
    /// Reads this value from `reader`.
    ///
    /// # Errors
    ///
    /// Returns a [`CodecError`] for incomplete, oversized, or noncanonical input.
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError>;

    /// Decodes one complete top-level value and rejects trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`CodecError`] for incomplete, oversized, noncanonical, or
    /// trailing input.
    fn decode_exact(bytes: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(bytes);
        let value = Self::decode(&mut reader)?;
        reader.finish()?;
        Ok(value)
    }
}

macro_rules! impl_integer_codec {
    ($integer:ty, $write:ident, $read:ident) => {
        impl Encode for $integer {
            fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
                writer.$write(*self);
                Ok(())
            }
        }

        impl Decode for $integer {
            fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
                reader.$read()
            }
        }
    };
}

impl_integer_codec!(u8, write_u8, read_u8);
impl_integer_codec!(u16, write_u16, read_u16);
impl_integer_codec!(u32, write_u32, read_u32);
impl_integer_codec!(u64, write_u64, read_u64);

impl<const N: usize> Encode for [u8; N] {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        writer.write_bytes(self);
        Ok(())
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        reader.read_array()
    }
}

#[cfg(test)]
mod tests {
    use super::{CodecError, Decode, Encode, Reader, Writer};

    #[derive(Debug, Eq, PartialEq)]
    struct TestFrame {
        tag: u8,
        sequence: u64,
        payload: Vec<u8>,
    }

    impl Encode for TestFrame {
        fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
            self.tag.encode(writer)?;
            self.sequence.encode(writer)?;
            writer.write_byte_vector(&self.payload)
        }
    }

    impl Decode for TestFrame {
        fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
            Ok(Self {
                tag: u8::decode(reader)?,
                sequence: u64::decode(reader)?,
                payload: reader.read_byte_vector(64)?,
            })
        }
    }

    #[test]
    fn integer_encoding_is_little_endian() {
        let mut writer = Writer::new();
        writer.write_u8(0x12);
        writer.write_u16(0x3456);
        writer.write_u32(0x789a_bcde);
        writer.write_u64(0x0123_4567_89ab_cdef);
        assert_eq!(
            writer.as_bytes(),
            &[
                0x12, 0x56, 0x34, 0xde, 0xbc, 0x9a, 0x78, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23,
                0x01,
            ]
        );
    }

    #[test]
    fn byte_vector_round_trip_and_bound() -> Result<(), CodecError> {
        let mut writer = Writer::new();
        writer.write_byte_vector(b"bp52")?;
        let bytes = writer.into_bytes();

        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.read_byte_vector(4)?, b"bp52");
        reader.finish()?;

        let mut reader = Reader::new(&bytes);
        assert_eq!(
            reader.read_byte_vector(3),
            Err(CodecError::LengthLimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn exact_decode_rejects_trailing_bytes() {
        assert_eq!(
            u16::decode_exact(&[1, 0, 0]),
            Err(CodecError::TrailingBytes)
        );
    }

    #[test]
    fn fixed_array_round_trip() -> Result<(), CodecError> {
        let original = [42_u8; 32];
        let encoded = original.encode_to_vec()?;
        assert_eq!(<[u8; 32]>::decode_exact(&encoded)?, original);
        Ok(())
    }

    #[test]
    fn reader_does_not_advance_on_short_fixed_read() {
        let mut reader = Reader::new(&[1, 2, 3]);
        assert_eq!(reader.read_array::<4>(), Err(CodecError::UnexpectedEof));
        assert_eq!(reader.remaining_len(), 3);
    }

    #[test]
    fn every_truncation_and_extension_of_a_frame_is_rejected() -> Result<(), CodecError> {
        let frame = TestFrame {
            tag: 9,
            sequence: 0x0123_4567_89ab_cdef,
            payload: (0_u8..64).collect(),
        };
        let encoded = frame.encode_to_vec()?;
        assert_eq!(TestFrame::decode_exact(&encoded)?, frame);

        for end in 0..encoded.len() {
            assert!(TestFrame::decode_exact(&encoded[..end]).is_err());
        }
        for byte in u8::MIN..=u8::MAX {
            let mut extended = encoded.clone();
            extended.push(byte);
            assert_eq!(
                TestFrame::decode_exact(&extended),
                Err(CodecError::TrailingBytes)
            );
        }
        Ok(())
    }

    #[test]
    fn hostile_lengths_fail_before_allocation_or_slicing() {
        let maximum_length = u32::MAX.to_le_bytes();
        let mut reader = Reader::new(&maximum_length);
        assert_eq!(
            reader.read_byte_vector(1_024),
            Err(CodecError::LengthLimitExceeded)
        );
        assert_eq!(reader.remaining_len(), 0);

        let bytes = [1_u8, 2, 3];
        let mut reader = Reader::new(&bytes);
        assert_eq!(
            reader.read_bytes(usize::MAX),
            Err(CodecError::UnexpectedEof)
        );
        assert_eq!(reader.remaining_len(), bytes.len());
    }
}
