#![forbid(unsafe_code)]
#![doc = "Version-pinned Bulletproof R1CS adapter for BP52-DEAL-v1."]

use bp52_group::ProtocolGenerators;
use bulletproofs::{BulletproofGens, PedersenGens};

/// Pinned constraint-system interface used by the circuit crate.
pub use bulletproofs::r1cs::{
    ConstraintSystem, LinearCombination, Metrics, Prover, R1CSError, R1CSProof, Variable, Verifier,
};
/// Canonical Ristretto point types shared with circuit composition.
pub use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
/// Scalar type shared by the pinned backend and the rest of BP52.
pub use curve25519_dalek::scalar::Scalar;
/// Merlin transcript type used by the pinned backend.
pub use merlin::Transcript;

/// Identifier included in the v1 circuit manifest.
pub const BACKEND_IDENTIFIER: &str =
    "zkcrypto/bulletproofs@04bce4e66013ff857ed462fd4206210544101461+bp52-hardening-2";

/// The source version declared by the pinned backend.
pub const BACKEND_SOURCE_VERSION: &str = "5.0.1+bp52-hardening-2";

/// BP52 always produces a single-party proof.
pub const PARTY_CAPACITY: usize = 1;

/// Errors at the isolated R1CS-backend boundary.
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// Generator capacity was zero or not a power of two.
    #[error("invalid Bulletproof generator capacity")]
    InvalidGeneratorCapacity,
    /// A proof did not have the exact manifest-derived length.
    #[error("unexpected R1CS proof length")]
    UnexpectedProofLength,
    /// The backend rejected a proof encoding or proof operation.
    #[error("Bulletproof R1CS backend error: {0}")]
    R1cs(#[from] bulletproofs::r1cs::R1CSError),
    /// Decoding and re-encoding did not reproduce the exact input bytes.
    #[error("noncanonical R1CS proof encoding")]
    NonCanonicalProof,
}

/// Locally constructed, deterministic Bulletproof parameters.
pub struct BackendParameters {
    pedersen: PedersenGens,
    bulletproof: BulletproofGens,
    generator_capacity: usize,
}

impl BackendParameters {
    /// Constructs fixed-base parameters for an exact power-of-two capacity.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::InvalidGeneratorCapacity`] unless the capacity
    /// is a nonzero power of two.
    pub fn new(
        generator_capacity: usize,
        generators: &ProtocolGenerators,
    ) -> Result<Self, BackendError> {
        if generator_capacity == 0 || !generator_capacity.is_power_of_two() {
            return Err(BackendError::InvalidGeneratorCapacity);
        }

        // The field order is security critical: values use M, blindings use G.
        let pedersen = PedersenGens {
            B: generators.message(),
            B_blinding: generators.blinding(),
        };
        let bulletproof = BulletproofGens::new(generator_capacity, PARTY_CAPACITY);
        Ok(Self {
            pedersen,
            bulletproof,
            generator_capacity,
        })
    }

    /// Returns the fixed Pedersen generators used to register commitments.
    #[must_use]
    pub const fn pedersen(&self) -> &PedersenGens {
        &self.pedersen
    }

    /// Returns the deterministic vector generators.
    #[must_use]
    pub const fn bulletproof(&self) -> &BulletproofGens {
        &self.bulletproof
    }

    /// Returns the allocated multiplication capacity.
    #[must_use]
    pub const fn generator_capacity(&self) -> usize {
        self.generator_capacity
    }
}

/// Returns `next_power_of_two(n_mul)`, rejecting zero and overflow.
///
/// # Errors
///
/// Returns [`BackendError::InvalidGeneratorCapacity`] for zero or when the
/// next power of two cannot be represented by `usize`.
pub fn required_generator_capacity(multiplier_count: usize) -> Result<usize, BackendError> {
    if multiplier_count == 0 {
        return Err(BackendError::InvalidGeneratorCapacity);
    }
    multiplier_count
        .checked_next_power_of_two()
        .ok_or(BackendError::InvalidGeneratorCapacity)
}

/// Exact serialized size of a one-phase proof for `multiplier_count` gates.
///
/// BP52's fixed SHA-256 relation does not use randomized constraints. The
/// pinned backend encodes one version byte, thirteen fixed 32-byte elements,
/// and two 32-byte elements per inner-product round.
///
/// # Errors
///
/// Returns [`BackendError`] when the multiplier count or calculated byte size
/// is zero, invalid, or overflows.
pub fn expected_one_phase_proof_len(multiplier_count: usize) -> Result<usize, BackendError> {
    let padded = required_generator_capacity(multiplier_count)?;
    let rounds =
        usize::try_from(padded.ilog2()).map_err(|_| BackendError::InvalidGeneratorCapacity)?;
    (13_usize
        .checked_add(
            rounds
                .checked_mul(2)
                .ok_or(BackendError::UnexpectedProofLength)?,
        )
        .and_then(|elements| elements.checked_mul(32))
        .and_then(|bytes| bytes.checked_add(1)))
    .ok_or(BackendError::UnexpectedProofLength)
}

/// Parses a proof only if it has the exact manifest-derived, canonical bytes.
///
/// # Errors
///
/// Returns [`BackendError::UnexpectedProofLength`] for the wrong byte length,
/// or a backend/canonicality error for an invalid encoding.
pub fn parse_exact_proof(bytes: &[u8], expected_len: usize) -> Result<R1CSProof, BackendError> {
    if bytes.len() != expected_len {
        return Err(BackendError::UnexpectedProofLength);
    }
    let proof = R1CSProof::from_bytes(bytes)?;
    if proof.to_bytes() != bytes {
        return Err(BackendError::NonCanonicalProof);
    }
    Ok(proof)
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use bp52_group::ProtocolGenerators;
    use bulletproofs::r1cs::{ConstraintSystem, Prover, Verifier};
    use curve25519_dalek::Scalar;
    use merlin::Transcript;

    use super::{
        BACKEND_IDENTIFIER, BackendError, BackendParameters, expected_one_phase_proof_len,
        parse_exact_proof,
    };

    const SPIKE_MULTIPLIERS: usize = 9;

    #[test]
    fn fixed_backend_revision_is_manifest_safe() {
        assert_eq!(
            BACKEND_IDENTIFIER,
            "zkcrypto/bulletproofs@04bce4e66013ff857ed462fd4206210544101461+bp52-hardening-2"
        );
    }

    #[test]
    fn custom_generators_match_bp52_commitment_formula() {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| panic!("{error}"));
        let parameters =
            BackendParameters::new(16, &generators).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            parameters.pedersen().commit(Scalar::ONE, Scalar::ZERO),
            generators.message()
        );
        assert_eq!(
            parameters.pedersen().commit(Scalar::ZERO, Scalar::ONE),
            generators.blinding()
        );
    }

    #[test]
    fn nine_external_commitments_prove_and_verify_on_stable() {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| panic!("{error}"));
        let parameters =
            BackendParameters::new(16, &generators).unwrap_or_else(|error| panic!("{error}"));

        let prover_transcript = Transcript::new(b"BP52/backend-compatibility-spike/v1");
        let mut prover = Prover::new(parameters.pedersen(), prover_transcript);
        let mut commitments = Vec::with_capacity(SPIKE_MULTIPLIERS);
        let mut committed_variables = Vec::with_capacity(SPIKE_MULTIPLIERS);
        for index in 0..SPIKE_MULTIPLIERS {
            let value =
                Scalar::from(u64::try_from(index).unwrap_or_else(|error| panic!("{error}")));
            let blinding =
                Scalar::from(u64::try_from(index + 100).unwrap_or_else(|error| panic!("{error}")));
            let (commitment, variable) = prover.commit(value, blinding);
            assert_eq!(
                commitment,
                parameters.pedersen().commit(value, blinding).compress()
            );
            commitments.push(commitment);
            committed_variables.push(variable);
        }
        for variable in committed_variables {
            let (_, _, product) = prover.multiply(variable.into(), Scalar::ONE.into());
            prover.constrain(product - variable);
        }
        let proof = prover
            .prove(parameters.bulletproof())
            .unwrap_or_else(|error| panic!("{error}"));
        let proof_bytes = proof.to_bytes();
        let expected_len = expected_one_phase_proof_len(SPIKE_MULTIPLIERS)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(proof_bytes.len(), expected_len);
        let proof =
            parse_exact_proof(&proof_bytes, expected_len).unwrap_or_else(|error| panic!("{error}"));

        let verifier_transcript = Transcript::new(b"BP52/backend-compatibility-spike/v1");
        let mut verifier = Verifier::new(verifier_transcript);
        let mut committed_variables = Vec::with_capacity(SPIKE_MULTIPLIERS);
        for commitment in commitments {
            committed_variables.push(verifier.commit(commitment));
        }
        for variable in committed_variables {
            let (_, _, product) = verifier.multiply(variable.into(), Scalar::ONE.into());
            verifier.constrain(product - variable);
        }
        verifier
            .verify(&proof, parameters.pedersen(), parameters.bulletproof())
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn proof_parser_rejects_wrong_length_before_backend_parse() {
        assert!(matches!(
            parse_exact_proof(&[0_u8; 32], 33),
            Err(BackendError::UnexpectedProofLength)
        ));
    }
}
