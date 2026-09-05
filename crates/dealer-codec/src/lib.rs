#![forbid(unsafe_code)]
//! Strict canonical wire primitives for DLOG52-DEAL-v1.

use thiserror::Error;

/// A type with one canonical wire representation.
pub trait Encode {
    /// Append the canonical encoding to `out`.
    fn encode(&self, out: &mut Vec<u8>);

    /// Return the canonical encoding.
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

/// Canonical decoding failures.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum CodecError {
    /// Input ended before the declared object was complete.
    #[error("truncated input")]
    Truncated,
    /// A length cannot be represented or exceeds the caller's limit.
    #[error("invalid or excessive length")]
    Length,
    /// Bytes remain after a top-level object.
    #[error("trailing bytes")]
    Trailing,
    /// An enum or boolean discriminant is unknown.
    #[error("invalid discriminant")]
    Discriminant,
}

/// Bounds-checking reader which never allocates from an unchecked wire length.
pub struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    /// Construct a reader.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }

    /// Read exactly `n` bytes.
    ///
    /// # Errors
    ///
    /// Rejects truncated input, excessive lengths, or noncanonical encoding.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.offset.checked_add(n).ok_or(CodecError::Length)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(CodecError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    /// Read one byte.
    ///
    /// # Errors
    ///
    /// Rejects truncated input, excessive lengths, or noncanonical encoding.
    pub fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    /// Read a little-endian `u16`.
    ///
    /// # Errors
    ///
    /// Rejects truncated input, excessive lengths, or noncanonical encoding.
    pub fn u16(&mut self) -> Result<u16, CodecError> {
        let mut b = [0_u8; 2];
        b.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(b))
    }

    /// Read a little-endian `u32`.
    ///
    /// # Errors
    ///
    /// Rejects truncated input, excessive lengths, or noncanonical encoding.
    pub fn u32(&mut self) -> Result<u32, CodecError> {
        let mut b = [0_u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(b))
    }

    /// Read a fixed-size array.
    ///
    /// # Errors
    ///
    /// Rejects truncated input, excessive lengths, or noncanonical encoding.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let mut out = [0_u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// Read a length-prefixed byte string, enforcing `max` before allocation.
    ///
    /// # Errors
    ///
    /// Rejects truncated input, excessive lengths, or noncanonical encoding.
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8], CodecError> {
        let len = usize::try_from(self.u32()?).map_err(|_| CodecError::Length)?;
        if len > max {
            return Err(CodecError::Length);
        }
        self.take(len)
    }

    /// Require full consumption.
    ///
    /// # Errors
    ///
    /// Rejects truncated input, excessive lengths, or noncanonical encoding.
    pub fn finish(self) -> Result<(), CodecError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(CodecError::Trailing)
        }
    }
}

/// Append a little-endian `u16`.
pub fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}
/// Append a little-endian `u32`.
pub fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
/// Append a checked length-prefixed byte string.
pub fn put_bytes(out: &mut Vec<u8>, value: &[u8]) {
    let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
    debug_assert_eq!(usize::try_from(len).ok(), Some(value.len()));
    put_u32(out, len);
    out.extend_from_slice(value);
}
/// Append an ASCII string using the `Bytes` codec.
///
/// # Panics
///
/// Panics if the string is not ASCII.
pub fn put_ascii(out: &mut Vec<u8>, value: &str) {
    assert!(value.is_ascii(), "protocol strings are ASCII");
    put_bytes(out, value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endian_and_bounded_bytes() {
        let mut encoded = Vec::new();
        put_u16(&mut encoded, 0x1234);
        put_u32(&mut encoded, 3);
        encoded.extend_from_slice(b"abc");
        let mut r = Reader::new(&encoded);
        assert_eq!(r.u16(), Ok(0x1234));
        assert_eq!(r.bytes(3), Ok(&b"abc"[..]));
        assert_eq!(r.finish(), Ok(()));
    }

    #[test]
    fn rejects_trailing_and_oversized() {
        assert_eq!(Reader::new(&[1]).finish(), Err(CodecError::Trailing));
        let bytes = [4, 0, 0, 0, 1, 2, 3, 4];
        assert_eq!(Reader::new(&bytes).bytes(3), Err(CodecError::Length));
    }
}
