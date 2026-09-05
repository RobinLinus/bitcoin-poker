//! Shared poker roles and reveal order.

/// Canonical player role for the chain protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum Role {
    /// Lexicographically smaller long-term x-only identity key.
    Alice = 0,
    /// Lexicographically larger long-term x-only identity key.
    Bob = 1,
}

impl Role {
    /// Returns the other fixed participant.
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::Alice => Self::Bob,
            Self::Bob => Self::Alice,
        }
    }

    /// Returns the fixed wire discriminant.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }
}
