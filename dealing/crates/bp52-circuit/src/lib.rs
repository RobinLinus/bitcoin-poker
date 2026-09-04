#![forbid(unsafe_code)]
#![doc = "Fixed-shape Bulletproof R1CS relation for BP52 hash preimages."]

/// Boolean constraint helpers.
pub mod boolean;
/// Nine-slot hash-length relation.
pub mod hash_length;
/// FIPS SHA-256 compression constraints.
pub mod sha256;
