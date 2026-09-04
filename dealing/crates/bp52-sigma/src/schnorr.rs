//! Threshold-key proof of possession.

use bp52_codec::{CodecError, Decode, Encode, Reader, Writer};
use bp52_group::{ProtocolGenerators, PublicKeyShare, SecretKeyShare, decode_point, decode_scalar};
use merlin::Transcript;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{SigmaError, append_point, challenge_scalar, random_nonzero, witness_rng};

/// Exact serialized size of a v1 threshold-key proof.
pub const KEY_PROOF_SIZE: usize = 64;

/// Schnorr proof of knowledge for one threshold key share.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyProof {
    /// Nonce commitment `w*G`.
    pub commitment: [u8; 32],
    /// Response `w + e*sk`.
    pub response: [u8; 32],
}

impl KeyProof {
    /// Produces a proof in a transcript already initialized with the key-PoP
    /// domain and common attempt frame.
    ///
    /// # Errors
    ///
    /// Returns [`SigmaError`] if the secret does not match either public share,
    /// nonce sampling fails, or the transcript derives a zero challenge.
    pub fn prove<R>(
        transcript: &mut Transcript,
        generators: &ProtocolGenerators,
        public_a: &PublicKeyShare,
        public_b: &PublicKeyShare,
        secret: &SecretKeyShare,
        rng: &mut R,
    ) -> Result<Self, SigmaError>
    where
        R: CryptoRng + RngCore,
    {
        append_statement(transcript, public_a, public_b);
        let derived_public = secret.public_key(generators);
        if derived_public != *public_a && derived_public != *public_b {
            return Err(SigmaError::VerificationFailed);
        }

        let secret_bytes = Zeroizing::new(secret.as_nonzero_scalar().to_bytes());
        let mut nonce_rng = witness_rng(transcript, &[secret_bytes.as_ref()], rng);
        let nonce = random_nonzero(&mut nonce_rng)?;
        let temporary = nonce.as_scalar() * generators.blinding();
        append_point(transcript, b"T", &temporary);
        let challenge = challenge_scalar(transcript)?;
        let response = nonce.as_scalar() + challenge * secret.as_nonzero_scalar().as_scalar();

        Ok(Self {
            commitment: temporary.compress().to_bytes(),
            response: response.to_bytes(),
        })
    }

    /// Verifies the proof against the public key selected by `prover_is_alice`.
    ///
    /// # Errors
    ///
    /// Returns [`SigmaError`] for malformed proof elements, a zero challenge,
    /// or a failed Schnorr equation.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        generators: &ProtocolGenerators,
        public_a: &PublicKeyShare,
        public_b: &PublicKeyShare,
        prover_is_alice: bool,
    ) -> Result<(), SigmaError> {
        append_statement(transcript, public_a, public_b);
        let temporary = decode_point(self.commitment, false)?;
        let response = decode_scalar(self.response)?;
        append_point(transcript, b"T", &temporary);
        let challenge = challenge_scalar(transcript)?;
        let public = if prover_is_alice { public_a } else { public_b };

        if response * generators.blinding() == temporary + challenge * public.as_point() {
            Ok(())
        } else {
            Err(SigmaError::VerificationFailed)
        }
    }
}

impl Encode for KeyProof {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        writer.write_bytes(&self.commitment);
        writer.write_bytes(&self.response);
        Ok(())
    }
}

impl Decode for KeyProof {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            commitment: reader.read_array()?,
            response: reader.read_array()?,
        })
    }
}

fn append_statement(
    transcript: &mut Transcript,
    public_a: &PublicKeyShare,
    public_b: &PublicKeyShare,
) {
    transcript.append_message(b"PK-A", &public_a.to_bytes());
    transcript.append_message(b"PK-B", &public_b.to_bytes());
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use bp52_codec::{Decode, Encode};
    use bp52_group::{JointPublicKey, ProtocolGenerators, SecretKeyShare};
    use merlin::Transcript;
    use rand_core::OsRng;

    use super::KeyProof;
    use crate::SigmaError;

    fn transcript() -> Transcript {
        let mut transcript = Transcript::new(b"BP52/key-pop/v1");
        transcript.append_message(b"test-context", b"fixed");
        transcript
    }

    #[test]
    fn key_proof_round_trip() {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| panic!("{error}"));
        let secret_a = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let secret_b = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let public_a = secret_a.public_key(&generators);
        let public_b = secret_b.public_key(&generators);
        let _joint =
            JointPublicKey::combine(&public_a, &public_b).unwrap_or_else(|error| panic!("{error}"));

        let proof = KeyProof::prove(
            &mut transcript(),
            &generators,
            &public_a,
            &public_b,
            &secret_a,
            &mut OsRng,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let bytes = proof
            .encode_to_vec()
            .unwrap_or_else(|error| panic!("{error}"));
        let proof = KeyProof::decode_exact(&bytes).unwrap_or_else(|error| panic!("{error}"));
        proof
            .verify(&mut transcript(), &generators, &public_a, &public_b, true)
            .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn proof_is_bound_to_both_public_keys_and_role() {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| panic!("{error}"));
        let secret_a = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let secret_b = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let public_a = secret_a.public_key(&generators);
        let public_b = secret_b.public_key(&generators);
        let proof = KeyProof::prove(
            &mut transcript(),
            &generators,
            &public_a,
            &public_b,
            &secret_a,
            &mut OsRng,
        )
        .unwrap_or_else(|error| panic!("{error}"));

        assert!(matches!(
            proof.verify(&mut transcript(), &generators, &public_a, &public_b, false,),
            Err(SigmaError::VerificationFailed)
        ));
    }

    #[test]
    fn altered_response_fails() {
        let generators = ProtocolGenerators::derive().unwrap_or_else(|error| panic!("{error}"));
        let secret_a = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let secret_b = SecretKeyShare::random(&mut OsRng).unwrap_or_else(|error| panic!("{error}"));
        let public_a = secret_a.public_key(&generators);
        let public_b = secret_b.public_key(&generators);
        let mut proof = KeyProof::prove(
            &mut transcript(),
            &generators,
            &public_a,
            &public_b,
            &secret_a,
            &mut OsRng,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        proof.response[0] ^= 1;
        assert!(
            proof
                .verify(&mut transcript(), &generators, &public_a, &public_b, true,)
                .is_err()
        );
    }
}
