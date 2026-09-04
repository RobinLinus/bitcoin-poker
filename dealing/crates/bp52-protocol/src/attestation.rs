//! Compact identity-signed evidence produced by a disposable DEAL verifier.
//!
//! A DEAL worker performs the expensive proof verification while it consumes
//! the authenticated sixteen-envelope attempt.  Once the attempt reaches a
//! terminal result, the worker signs this compact artifact.  Long-lived GAME
//! and CHAIN runtimes can then verify the artifact and ordinary BIP340
//! signatures without replaying the Bulletproof archive.

use bitcoin::secp256k1::{Keypair, Secp256k1, Signing, Verification};
use bp52_codec::{CodecError, Decode, Encode, Reader, Writer};

use crate::{
    PROTOCOL_VERSION, Role,
    archive::{ArchiveProgress, VerifiedAcceptedDeal},
    auth::{
        AuthError, CanonicalIdentities, sign_role_digest, verify_accepted_deal_signatures,
        verify_role_digest,
    },
    messages::{AcceptedDeal, AcceptedDealBody},
};

const ATTESTATION_MAGIC: [u8; 8] = *b"BP52DVA1";
const ATTESTATION_VERSION: u16 = 1;
const ACCEPTED_RESULT: u8 = 0;
const DEGENERATE_RETRY_RESULT: u8 = 1;
const COLLISION_RETRY_RESULT: u8 = 2;

/// Tagged-hash domain for disposable DEAL-verifier attestations.
pub const DEAL_VERIFICATION_SIGNATURE_TAG: &[u8] = b"BP52/deal-verification/v1";

/// Exact terminal result established by the disposable DEAL verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DealVerificationResult {
    /// The complete attempt uniquely derived this accepted body.
    Accepted(AcceptedDealBody),
    /// The complete attempt derived the neutral aggregate and must retry.
    DegenerateRetry,
    /// The complete attempt detected a duplicate card and must retry.
    CollisionRetry,
}

impl DealVerificationResult {
    /// Converts an archive retry result into its compact attestation result.
    fn from_archive_progress(progress: ArchiveProgress) -> Result<Self, DealVerificationError> {
        match progress {
            ArchiveProgress::DegenerateRetry => Ok(Self::DegenerateRetry),
            ArchiveProgress::CollisionRetry => Ok(Self::CollisionRetry),
            ArchiveProgress::Continue => Err(DealVerificationError::NonterminalResult),
        }
    }

    /// Returns the attested accepted body, if the result was accepted.
    #[must_use]
    pub const fn accepted_body(self) -> Option<AcceptedDealBody> {
        match self {
            Self::Accepted(body) => Some(body),
            Self::DegenerateRetry | Self::CollisionRetry => None,
        }
    }

    /// Returns the attested retry reason, if the result requires a retry.
    #[must_use]
    pub const fn retry_progress(self) -> Option<ArchiveProgress> {
        match self {
            Self::Accepted(_) => None,
            Self::DegenerateRetry => Some(ArchiveProgress::DegenerateRetry),
            Self::CollisionRetry => Some(ArchiveProgress::CollisionRetry),
        }
    }
}

/// Immutable statement signed by one disposable DEAL verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DealVerificationStatement {
    /// Hash of the role-independent session configuration.
    pub shared_config_hash: [u8; 32],
    /// Fresh nonce identifying the exact DEAL session.
    pub session_nonce: [u8; 32],
    /// Funding-derived DEAL game identifier.
    pub game_id: [u8; 32],
    /// Zero-based DEAL attempt number.
    pub attempt: u32,
    /// `T_16`, committing to every authenticated envelope in order.
    pub archive_transcript_root: [u8; 32],
    /// Terminal result established by semantic proof verification.
    pub result: DealVerificationResult,
}

impl DealVerificationStatement {
    /// Constructs an accepted statement and checks all duplicated bindings.
    ///
    /// # Errors
    ///
    /// Returns [`DealVerificationError::ContextMismatch`] if the accepted body
    /// names another game, attempt, transcript root, or protocol version.
    pub fn accepted(
        shared_config_hash: [u8; 32],
        session_nonce: [u8; 32],
        game_id: [u8; 32],
        attempt: u32,
        archive_transcript_root: [u8; 32],
        body: AcceptedDealBody,
    ) -> Result<Self, DealVerificationError> {
        let statement = Self {
            shared_config_hash,
            session_nonce,
            game_id,
            attempt,
            archive_transcript_root,
            result: DealVerificationResult::Accepted(body),
        };
        statement.validate()?;
        Ok(statement)
    }

    /// Constructs a terminal retry statement.
    ///
    /// # Errors
    ///
    /// Rejects [`ArchiveProgress::Continue`], which is not a terminal result.
    pub fn retry(
        shared_config_hash: [u8; 32],
        session_nonce: [u8; 32],
        game_id: [u8; 32],
        attempt: u32,
        archive_transcript_root: [u8; 32],
        progress: ArchiveProgress,
    ) -> Result<Self, DealVerificationError> {
        let statement = Self {
            shared_config_hash,
            session_nonce,
            game_id,
            attempt,
            archive_transcript_root,
            result: DealVerificationResult::from_archive_progress(progress)?,
        };
        statement.validate()?;
        Ok(statement)
    }

    fn validate(&self) -> Result<(), DealVerificationError> {
        if self.shared_config_hash == [0; 32]
            || self.session_nonce == [0; 32]
            || self.game_id == [0; 32]
            || self.archive_transcript_root == [0; 32]
        {
            return Err(DealVerificationError::ContextMismatch);
        }
        if let DealVerificationResult::Accepted(body) = self.result {
            if body.protocol_version != PROTOCOL_VERSION
                || body.game_id != self.game_id
                || body.attempt != self.attempt
                || body.verification_transcript_root != self.archive_transcript_root
            {
                return Err(DealVerificationError::ContextMismatch);
            }
        }
        Ok(())
    }
}

impl Encode for DealVerificationStatement {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.validate().map_err(|_| CodecError::NonCanonical)?;
        writer.write_bytes(&ATTESTATION_MAGIC);
        writer.write_u16(ATTESTATION_VERSION);
        writer.write_bytes(&self.shared_config_hash);
        writer.write_bytes(&self.session_nonce);
        writer.write_bytes(&self.game_id);
        writer.write_u32(self.attempt);
        writer.write_bytes(&self.archive_transcript_root);
        match self.result {
            DealVerificationResult::Accepted(body) => {
                writer.write_u8(ACCEPTED_RESULT);
                body.encode(writer)?;
            }
            DealVerificationResult::DegenerateRetry => {
                writer.write_u8(DEGENERATE_RETRY_RESULT);
            }
            DealVerificationResult::CollisionRetry => {
                writer.write_u8(COLLISION_RETRY_RESULT);
            }
        }
        Ok(())
    }
}

impl Decode for DealVerificationStatement {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        if reader.read_array::<8>()? != ATTESTATION_MAGIC
            || reader.read_u16()? != ATTESTATION_VERSION
        {
            return Err(CodecError::NonCanonical);
        }
        let shared_config_hash = reader.read_array()?;
        let session_nonce = reader.read_array()?;
        let game_id = reader.read_array()?;
        let attempt = reader.read_u32()?;
        let archive_transcript_root = reader.read_array()?;
        let result = match reader.read_u8()? {
            ACCEPTED_RESULT => DealVerificationResult::Accepted(AcceptedDealBody::decode(reader)?),
            DEGENERATE_RETRY_RESULT => DealVerificationResult::DegenerateRetry,
            COLLISION_RETRY_RESULT => DealVerificationResult::CollisionRetry,
            _ => return Err(CodecError::NonCanonical),
        };
        let statement = Self {
            shared_config_hash,
            session_nonce,
            game_id,
            attempt,
            archive_transcript_root,
            result,
        };
        statement.validate().map_err(|_| CodecError::NonCanonical)?;
        Ok(statement)
    }
}

/// One canonical identity-signed disposable-verifier artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DealVerificationAttestation {
    /// Exact context and terminal result that were verified.
    pub statement: DealVerificationStatement,
    /// Canonical identity role of the disposable verifier.
    pub signer_role: Role,
    /// BIP340 signature over the tagged statement digest.
    pub signature: [u8; 64],
}

impl Encode for DealVerificationAttestation {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.statement.encode(writer)?;
        self.signer_role.encode(writer)?;
        writer.write_bytes(&self.signature);
        Ok(())
    }
}

impl Decode for DealVerificationAttestation {
    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            statement: DealVerificationStatement::decode(reader)?,
            signer_role: Role::decode(reader)?,
            signature: reader.read_array()?,
        })
    }
}

/// Failures while signing or consuming compact DEAL-verifier evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DealVerificationError {
    /// The canonical artifact or accepted body was malformed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// A BIP340 identity signature was malformed, forged, or role-confused.
    #[error(transparent)]
    Authentication(#[from] AuthError),
    /// The artifact does not belong to the exact expected session context.
    #[error("DEAL verification attestation context mismatch")]
    ContextMismatch,
    /// A disposable verifier attempted to attest an unfinished archive.
    #[error("DEAL verification attestation result is not terminal")]
    NonterminalResult,
    /// The accepted certificate differs from the verifier-attested result.
    #[error("accepted certificate differs from the DEAL verification attestation")]
    ResultMismatch,
}

/// Opaque evidence that one attestation signature and all context bindings
/// were verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedDealVerification {
    attestation: DealVerificationAttestation,
}

impl VerifiedDealVerification {
    /// Borrows the authenticated statement.
    #[must_use]
    pub const fn statement(&self) -> &DealVerificationStatement {
        &self.attestation.statement
    }

    /// Returns the canonical role that signed the authenticated statement.
    #[must_use]
    pub const fn signer_role(&self) -> Role {
        self.attestation.signer_role
    }
}

fn statement_digest(statement: &DealVerificationStatement) -> Result<[u8; 32], AuthError> {
    use bp52_group::hash::TaggedHash;

    let bytes = statement.encode_to_vec()?;
    let mut hash = TaggedHash::new(DEAL_VERIFICATION_SIGNATURE_TAG);
    hash.update(bytes);
    Ok(hash.finalize())
}

/// Signs one already-verified terminal statement with the local identity.
///
/// # Errors
///
/// Returns an authentication or canonical-encoding error, including when the
/// signing key does not own `signer_role`.
pub fn sign_deal_verification<C: Signing>(
    secp: &Secp256k1<C>,
    statement: DealVerificationStatement,
    signer_role: Role,
    signing_key: &Keypair,
    identities: &CanonicalIdentities,
    auxiliary_randomness: &[u8; 32],
) -> Result<DealVerificationAttestation, DealVerificationError> {
    statement.validate()?;
    let signature = sign_role_digest(
        secp,
        statement_digest(&statement)?,
        signer_role,
        signing_key,
        identities,
        auxiliary_randomness,
    )?;
    Ok(DealVerificationAttestation {
        statement,
        signer_role,
        signature,
    })
}

/// Verifies one attestation against the exact immutable local context.
///
/// # Errors
///
/// Returns a context mismatch before accepting an artifact from another
/// deployment, session, game, attempt, transcript, or local identity role.
pub fn verify_deal_verification<C: Verification>(
    secp: &Secp256k1<C>,
    identities: &CanonicalIdentities,
    expected_signer: Role,
    expected_shared_config_hash: [u8; 32],
    expected_session_nonce: [u8; 32],
    expected_game_id: [u8; 32],
    expected_attempt: u32,
    expected_archive_transcript_root: [u8; 32],
    attestation: &DealVerificationAttestation,
) -> Result<VerifiedDealVerification, DealVerificationError> {
    attestation.statement.validate()?;
    if attestation.signer_role != expected_signer
        || attestation.statement.shared_config_hash != expected_shared_config_hash
        || attestation.statement.session_nonce != expected_session_nonce
        || attestation.statement.game_id != expected_game_id
        || attestation.statement.attempt != expected_attempt
        || attestation.statement.archive_transcript_root != expected_archive_transcript_root
    {
        return Err(DealVerificationError::ContextMismatch);
    }
    verify_role_digest(
        secp,
        statement_digest(&attestation.statement)?,
        attestation.signer_role,
        &attestation.signature,
        identities,
    )?;
    Ok(VerifiedDealVerification {
        attestation: *attestation,
    })
}

/// Verifies a fully signed accepted certificate against authenticated
/// disposable-verifier evidence without replaying the proof archive.
///
/// # Errors
///
/// Returns [`DealVerificationError::ResultMismatch`] for a retry attestation
/// or a certificate body that differs from the attested accepted body, and an
/// authentication error if either accepted-deal signature is invalid.
pub fn verify_attested_accepted_deal<C: Verification>(
    secp: &Secp256k1<C>,
    identities: &CanonicalIdentities,
    verification: &VerifiedDealVerification,
    deal: &AcceptedDeal,
) -> Result<VerifiedAcceptedDeal, DealVerificationError> {
    let Some(body) = verification.statement().result.accepted_body() else {
        return Err(DealVerificationError::ResultMismatch);
    };
    if deal.body() != body {
        return Err(DealVerificationError::ResultMismatch);
    }
    verify_accepted_deal_signatures(secp, deal, identities)?;
    Ok(VerifiedAcceptedDeal::from_authenticated_deal(*deal))
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use bp52_codec::{Decode, Encode};

    use super::{
        DealVerificationError, DealVerificationStatement, sign_deal_verification,
        verify_attested_accepted_deal, verify_deal_verification,
    };
    use crate::{
        N_SLOTS, PROTOCOL_VERSION, Role,
        archive::ArchiveProgress,
        auth::{CanonicalIdentities, sign_accepted_deal},
        messages::{AcceptedDeal, AcceptedDealBody},
    };

    fn keypair(value: u8) -> Keypair {
        let secp = Secp256k1::new();
        let mut bytes = [0_u8; 32];
        bytes[31] = value;
        Keypair::from_seckey_slice(&secp, &bytes).unwrap_or_else(|_| unreachable!())
    }

    fn fixture() -> (
        Secp256k1<bitcoin::secp256k1::All>,
        Keypair,
        Keypair,
        CanonicalIdentities,
        DealVerificationStatement,
    ) {
        let secp = Secp256k1::new();
        let first = keypair(1);
        let second = keypair(2);
        let identities =
            CanonicalIdentities::new(first.x_only_public_key().0, second.x_only_public_key().0)
                .unwrap_or_else(|_| unreachable!());
        let body = AcceptedDealBody {
            protocol_version: PROTOCOL_VERSION,
            game_id: [3; 32],
            attempt: 7,
            hashes_a: [[4; 32]; N_SLOTS],
            hashes_b: [[5; 32]; N_SLOTS],
            verification_transcript_root: [6; 32],
        };
        let statement =
            DealVerificationStatement::accepted([1; 32], [2; 32], [3; 32], 7, [6; 32], body)
                .unwrap_or_else(|_| unreachable!());
        (secp, first, second, identities, statement)
    }

    #[test]
    fn attestation_round_trip_and_context_binding_are_exact() {
        let (secp, alice, _, identities, statement) = fixture();
        let attestation =
            sign_deal_verification(&secp, statement, Role::Alice, &alice, &identities, &[9; 32])
                .unwrap_or_else(|_| unreachable!());
        let encoded = attestation
            .encode_to_vec()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(encoded.len(), 854);
        let decoded = super::DealVerificationAttestation::decode_exact(&encoded)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(decoded, attestation);
        assert!(
            verify_deal_verification(
                &secp,
                &identities,
                Role::Alice,
                [1; 32],
                [2; 32],
                [3; 32],
                7,
                [6; 32],
                &decoded,
            )
            .is_ok()
        );
        for (signer, config, session, game, attempt, root) in [
            (Role::Alice, [8; 32], [2; 32], [3; 32], 7, [6; 32]),
            (Role::Alice, [1; 32], [8; 32], [3; 32], 7, [6; 32]),
            (Role::Alice, [1; 32], [2; 32], [8; 32], 7, [6; 32]),
            (Role::Alice, [1; 32], [2; 32], [3; 32], 8, [6; 32]),
            (Role::Alice, [1; 32], [2; 32], [3; 32], 7, [8; 32]),
            (Role::Bob, [1; 32], [2; 32], [3; 32], 7, [6; 32]),
        ] {
            assert_eq!(
                verify_deal_verification(
                    &secp,
                    &identities,
                    signer,
                    config,
                    session,
                    game,
                    attempt,
                    root,
                    &decoded,
                ),
                Err(DealVerificationError::ContextMismatch)
            );
        }
    }

    #[test]
    fn forged_and_wrong_role_attestations_are_rejected() {
        let (secp, alice, _, identities, statement) = fixture();
        let mut attestation =
            sign_deal_verification(&secp, statement, Role::Alice, &alice, &identities, &[9; 32])
                .unwrap_or_else(|_| unreachable!());
        attestation.signature[0] ^= 1;
        assert!(matches!(
            verify_deal_verification(
                &secp,
                &identities,
                Role::Alice,
                [1; 32],
                [2; 32],
                [3; 32],
                7,
                [6; 32],
                &attestation,
            ),
            Err(DealVerificationError::Authentication(_))
        ));
        assert!(matches!(
            sign_deal_verification(&secp, statement, Role::Bob, &alice, &identities, &[9; 32],),
            Err(DealVerificationError::Authentication(_))
        ));
    }

    #[test]
    fn accepted_certificate_requires_both_signatures_and_exact_body() {
        let (secp, alice, bob, identities, statement) = fixture();
        let attestation =
            sign_deal_verification(&secp, statement, Role::Alice, &alice, &identities, &[9; 32])
                .unwrap_or_else(|_| unreachable!());
        let verified = verify_deal_verification(
            &secp,
            &identities,
            Role::Alice,
            [1; 32],
            [2; 32],
            [3; 32],
            7,
            [6; 32],
            &attestation,
        )
        .unwrap_or_else(|_| unreachable!());
        let body = statement
            .result
            .accepted_body()
            .unwrap_or_else(|| unreachable!());
        let signature_a =
            sign_accepted_deal(&secp, &body, Role::Alice, &alice, &identities, &[10; 32])
                .unwrap_or_else(|_| unreachable!());
        let signature_b = sign_accepted_deal(&secp, &body, Role::Bob, &bob, &identities, &[11; 32])
            .unwrap_or_else(|_| unreachable!());
        let deal = AcceptedDeal {
            protocol_version: body.protocol_version,
            game_id: body.game_id,
            attempt: body.attempt,
            hashes_a: body.hashes_a,
            hashes_b: body.hashes_b,
            verification_transcript_root: body.verification_transcript_root,
            signature_a,
            signature_b,
        };
        assert!(verify_attested_accepted_deal(&secp, &identities, &verified, &deal).is_ok());
        let forged = AcceptedDeal {
            signature_b: [0; 64],
            ..deal
        };
        assert!(matches!(
            verify_attested_accepted_deal(&secp, &identities, &verified, &forged),
            Err(DealVerificationError::Authentication(_))
        ));
    }

    #[test]
    fn canonical_decoder_rejects_trailing_and_cross_bound_accepted_body() {
        let (_, _, _, _, statement) = fixture();
        let mut encoded = statement.encode_to_vec().unwrap_or_else(|_| unreachable!());
        encoded.push(0);
        assert!(DealVerificationStatement::decode_exact(&encoded).is_err());

        let mut body = statement
            .result
            .accepted_body()
            .unwrap_or_else(|| unreachable!());
        body.attempt += 1;
        assert!(
            DealVerificationStatement::accepted([1; 32], [2; 32], [3; 32], 7, [6; 32], body,)
                .is_err()
        );
    }

    #[test]
    fn retry_attestations_are_terminal_and_canonical() {
        let (secp, alice, _, identities, _) = fixture();
        let statement = DealVerificationStatement::retry(
            [1; 32],
            [2; 32],
            [3; 32],
            9,
            [4; 32],
            ArchiveProgress::CollisionRetry,
        )
        .unwrap_or_else(|_| unreachable!());
        let attestation =
            sign_deal_verification(&secp, statement, Role::Alice, &alice, &identities, &[5; 32])
                .unwrap_or_else(|_| unreachable!());
        let encoded = attestation
            .encode_to_vec()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(encoded.len(), 208);
        let decoded = super::DealVerificationAttestation::decode_exact(&encoded)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            decoded.statement.result.retry_progress(),
            Some(ArchiveProgress::CollisionRetry)
        );
        assert!(
            DealVerificationStatement::retry(
                [1; 32],
                [2; 32],
                [3; 32],
                9,
                [4; 32],
                ArchiveProgress::Continue,
            )
            .is_err()
        );
    }
}
