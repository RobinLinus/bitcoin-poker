//! BIP340 authentication for protocol envelopes and accepted deals.
//!
//! Identity roles are derived once from the two long-term Bitcoin x-only
//! public keys. Signature helpers then select the expected key from that
//! canonical assignment instead of accepting an independently supplied public
//! key that could disagree with the signed role.

use bitcoin::secp256k1::{
    Keypair, Message, Secp256k1, Signing, Verification, XOnlyPublicKey, schnorr::Signature,
};
use bp52_codec::{CodecError, Encode};
use bp52_group::hash::TaggedHash;

use crate::{
    Role,
    messages::{
        AcceptedDeal, AcceptedDealBody, Envelope, RawEnvelope, UnsignedEnvelope,
        encode_raw_unsigned_fields, encode_unsigned_fields_for_auth,
    },
};

/// Size of a Bitcoin outpoint's consensus encoding (`txid || vout`).
pub const CONSENSUS_OUTPOINT_SIZE: usize = 36;

/// Tagged-hash domain for funded game identifiers.
pub const GAME_ID_TAG: &[u8] = b"BP52/game/v1";
/// Tagged-hash domain for authenticated message envelopes.
pub const ENVELOPE_SIGNATURE_TAG: &[u8] = b"BP52/envelope/v1";
/// Tagged-hash domain for accepted-deal certificates.
pub const ACCEPTED_DEAL_SIGNATURE_TAG: &[u8] = b"BP52/accepted-deal/v1";

/// Authentication and identity-assignment failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthError {
    /// Both participants supplied the same long-term identity key.
    #[error("identity keys must be distinct")]
    DuplicateIdentityKeys,
    /// A key is not either participant's canonical identity key.
    #[error("identity key is not part of this game")]
    UnknownIdentityKey,
    /// A raw envelope contained a sender role byte outside the v1 role set.
    #[error("unknown envelope sender role")]
    UnknownSenderRole,
    /// The signing key does not own the claimed canonical role.
    #[error("signing key does not match the claimed role")]
    RoleKeyMismatch,
    /// The object cannot be encoded canonically and therefore cannot be signed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// A BIP340 signature is malformed or does not verify under the role's key.
    #[error("invalid BIP340 signature")]
    InvalidSignature,
}

/// The two identity keys in their canonical Alice-then-Bob order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalIdentities {
    alice: XOnlyPublicKey,
    bob: XOnlyPublicKey,
}

impl CanonicalIdentities {
    /// Sorts two valid x-only keys into canonical role order.
    ///
    /// Alice owns the lexicographically smaller 32-byte serialized key. Equal
    /// keys are rejected because one identity cannot occupy both roles.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::DuplicateIdentityKeys`] when the keys are equal.
    pub fn new(first: XOnlyPublicKey, second: XOnlyPublicKey) -> Result<Self, AuthError> {
        let first_bytes = first.serialize();
        let second_bytes = second.serialize();
        if first_bytes == second_bytes {
            return Err(AuthError::DuplicateIdentityKeys);
        }
        let (alice, bob) = if first_bytes < second_bytes {
            (first, second)
        } else {
            (second, first)
        };
        Ok(Self { alice, bob })
    }

    /// Returns Alice's lexicographically smaller x-only key.
    #[must_use]
    pub const fn alice(&self) -> &XOnlyPublicKey {
        &self.alice
    }

    /// Returns Bob's lexicographically larger x-only key.
    #[must_use]
    pub const fn bob(&self) -> &XOnlyPublicKey {
        &self.bob
    }

    /// Returns the canonical identity key for `role`.
    #[must_use]
    pub const fn key_for_role(&self, role: Role) -> &XOnlyPublicKey {
        match role {
            Role::Alice => &self.alice,
            Role::Bob => &self.bob,
        }
    }

    /// Determines which canonical role owns `identity`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::UnknownIdentityKey`] when `identity` is neither
    /// participant in this game.
    pub fn role_for_key(&self, identity: &XOnlyPublicKey) -> Result<Role, AuthError> {
        if identity == &self.alice {
            Ok(Role::Alice)
        } else if identity == &self.bob {
            Ok(Role::Bob)
        } else {
            Err(AuthError::UnknownIdentityKey)
        }
    }

    /// Returns both canonical serialized identities in Alice-then-Bob order.
    #[must_use]
    pub fn serialized(&self) -> ([u8; 32], [u8; 32]) {
        (self.alice.serialize(), self.bob.serialize())
    }
}

/// Derives the canonical Alice/Bob assignment from two x-only identity keys.
///
/// # Errors
///
/// Returns [`AuthError::DuplicateIdentityKeys`] when the keys are equal.
pub fn derive_roles(
    first: XOnlyPublicKey,
    second: XOnlyPublicKey,
) -> Result<CanonicalIdentities, AuthError> {
    CanonicalIdentities::new(first, second)
}

/// Derives the funded-session game identifier from canonical consensus bytes.
///
/// `network_id` is the 32-byte consensus serialization of the network genesis
/// block hash. `funding_outpoint` is the 36-byte consensus serialization of a
/// Bitcoin outpoint: transaction ID in wire order followed by little-endian
/// `vout`. The identity keys are always hashed in Alice-then-Bob order.
#[must_use]
pub fn derive_game_id(
    network_id: &[u8; 32],
    funding_outpoint: &[u8; CONSENSUS_OUTPOINT_SIZE],
    identities: &CanonicalIdentities,
    session_nonce: &[u8; 32],
) -> [u8; 32] {
    let (alice, bob) = identities.serialized();
    let mut hash = TaggedHash::new(GAME_ID_TAG);
    hash.update(network_id);
    hash.update(funding_outpoint);
    hash.update(alice);
    hash.update(bob);
    hash.update(session_nonce);
    hash.finalize()
}

/// Computes the exact BIP340 digest for an unsigned envelope.
///
/// # Errors
///
/// Returns a codec error when the envelope is not a canonical v1 message.
pub fn envelope_digest(unsigned: &UnsignedEnvelope) -> Result<[u8; 32], AuthError> {
    tagged_encoded_digest(ENVELOPE_SIGNATURE_TAG, unsigned)
}

/// Signs an unsigned envelope with its claimed role's identity key.
///
/// `auxiliary_randomness` is passed directly to the BIP340 nonce function and
/// should be fresh unpredictable data in production. Supplying a fixed value
/// is useful only for deterministic test vectors.
///
/// # Errors
///
/// Returns [`AuthError::RoleKeyMismatch`] if `signing_key` does not own
/// `unsigned.sender_role`, or a codec error if the unsigned envelope is not
/// canonical.
pub fn sign_envelope<C: Signing>(
    secp: &Secp256k1<C>,
    unsigned: &UnsignedEnvelope,
    signing_key: &Keypair,
    identities: &CanonicalIdentities,
    auxiliary_randomness: &[u8; 32],
) -> Result<Envelope, AuthError> {
    let signature = sign_role_digest(
        secp,
        envelope_digest(unsigned)?,
        unsigned.sender_role,
        signing_key,
        identities,
        auxiliary_randomness,
    )?;
    Ok(Envelope {
        unsigned: unsigned.clone(),
        signature,
    })
}

/// Verifies an envelope under the identity key assigned to its sender role.
///
/// Authentication uses the bounded raw unsigned-envelope encoding and does
/// not apply the selected payload type's exact length check. The semantic
/// driver performs that check after this signature succeeds, so a signer of a
/// malformed-but-bounded payload can be attributed safely.
///
/// # Errors
///
/// Returns a codec error for a noncanonical unsigned envelope or
/// [`AuthError::InvalidSignature`] if authentication fails.
pub fn verify_envelope<C: Verification>(
    secp: &Secp256k1<C>,
    envelope: &Envelope,
    identities: &CanonicalIdentities,
) -> Result<(), AuthError> {
    verify_role_digest(
        secp,
        raw_unsigned_digest(&envelope.unsigned)?,
        envelope.unsigned.sender_role,
        &envelope.signature,
        identities,
    )
}

/// Authenticates a structurally decoded raw envelope and returns the identity
/// key that actually signed it.
///
/// Both canonical identity keys are tried against the exact raw digest. This
/// allows an invalid or dishonest raw sender-role byte to be attributed after
/// the driver has established that the envelope targets its exact live cursor.
/// Payload type and payload length are intentionally not checked here.
pub(crate) fn verify_raw_envelope<C: Verification>(
    secp: &Secp256k1<C>,
    envelope: &RawEnvelope,
    identities: &CanonicalIdentities,
) -> Result<Role, AuthError> {
    let digest = raw_wire_envelope_digest(envelope)?;
    for role in [Role::Alice, Role::Bob] {
        if verify_role_digest(secp, digest, role, &envelope.signature, identities).is_ok() {
            return Ok(role);
        }
    }
    Err(AuthError::InvalidSignature)
}

fn raw_unsigned_digest(unsigned: &UnsignedEnvelope) -> Result<[u8; 32], AuthError> {
    let bytes = encode_unsigned_fields_for_auth(unsigned)?;
    let mut hash = TaggedHash::new(ENVELOPE_SIGNATURE_TAG);
    hash.update(bytes);
    Ok(hash.finalize())
}

fn raw_wire_envelope_digest(envelope: &RawEnvelope) -> Result<[u8; 32], AuthError> {
    let mut bytes = bp52_codec::Writer::with_capacity(
        2 + 32 + 4 + 2 + 1 + 4 + 32 + 2 + 4 + envelope.payload.len(),
    );
    encode_raw_unsigned_fields(
        envelope.protocol_version,
        envelope.game_id,
        envelope.attempt,
        envelope.round,
        envelope.sender_role,
        envelope.sequence,
        envelope.previous_message_hash,
        envelope.payload_type,
        &envelope.payload,
        &mut bytes,
    )?;
    let mut hash = TaggedHash::new(ENVELOPE_SIGNATURE_TAG);
    hash.update(bytes.into_bytes());
    Ok(hash.finalize())
}

#[cfg(test)]
pub(crate) fn sign_raw_wire_envelope_for_test<C: Signing>(
    secp: &Secp256k1<C>,
    envelope: &RawEnvelope,
    signing_key: &Keypair,
    identities: &CanonicalIdentities,
    auxiliary_randomness: &[u8; 32],
) -> Result<RawEnvelope, AuthError> {
    let (identity, _) = signing_key.x_only_public_key();
    let role = identities.role_for_key(&identity)?;
    let signature = sign_role_digest(
        secp,
        raw_wire_envelope_digest(envelope)?,
        role,
        signing_key,
        identities,
        auxiliary_randomness,
    )?;
    let mut signed = envelope.clone();
    signed.signature = signature;
    Ok(signed)
}

/// Computes the exact BIP340 digest for an accepted-deal body.
///
/// # Errors
///
/// Returns a codec error when the body is not canonical protocol version 1.
pub fn accepted_deal_digest(body: &AcceptedDealBody) -> Result<[u8; 32], AuthError> {
    tagged_encoded_digest(ACCEPTED_DEAL_SIGNATURE_TAG, body)
}

/// Signs an accepted-deal body for one canonical role.
///
/// `auxiliary_randomness` follows the same production requirements as in
/// [`sign_envelope`].
///
/// # Errors
///
/// Returns [`AuthError::RoleKeyMismatch`] if the key does not own `role`, or a
/// codec error if the accepted body is not canonical.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn sign_accepted_deal<C: Signing>(
    secp: &Secp256k1<C>,
    body: &AcceptedDealBody,
    role: Role,
    signing_key: &Keypair,
    identities: &CanonicalIdentities,
    auxiliary_randomness: &[u8; 32],
) -> Result<[u8; 64], AuthError> {
    sign_role_digest(
        secp,
        accepted_deal_digest(body)?,
        role,
        signing_key,
        identities,
        auxiliary_randomness,
    )
}

/// Verifies one role's signature over an accepted-deal body.
///
/// # Errors
///
/// Returns a codec error for a noncanonical body or
/// [`AuthError::InvalidSignature`] if authentication fails.
pub fn verify_accepted_deal_signature<C: Verification>(
    secp: &Secp256k1<C>,
    body: &AcceptedDealBody,
    role: Role,
    signature: &[u8; 64],
    identities: &CanonicalIdentities,
) -> Result<(), AuthError> {
    verify_role_digest(
        secp,
        accepted_deal_digest(body)?,
        role,
        signature,
        identities,
    )
}

/// Verifies only the two signatures on an accepted-deal body.
///
/// This helper does not establish that the body came from a valid protocol
/// attempt. Public certificate verification must use
/// [`crate::verify_accepted_archive`], which replays all sixteen envelopes and
/// then checks these signatures.
///
/// # Errors
///
/// Returns a codec error for a noncanonical body or
/// [`AuthError::InvalidSignature`] if either role's signature fails.
pub fn verify_accepted_deal_signatures<C: Verification>(
    secp: &Secp256k1<C>,
    deal: &AcceptedDeal,
    identities: &CanonicalIdentities,
) -> Result<(), AuthError> {
    let body = deal.body();
    verify_accepted_deal_signature(secp, &body, Role::Alice, &deal.signature_a, identities)?;
    verify_accepted_deal_signature(secp, &body, Role::Bob, &deal.signature_b, identities)
}

fn tagged_encoded_digest<T: Encode>(tag: &[u8], value: &T) -> Result<[u8; 32], AuthError> {
    let bytes = value.encode_to_vec()?;
    let mut hash = TaggedHash::new(tag);
    hash.update(bytes);
    Ok(hash.finalize())
}

pub(crate) fn sign_role_digest<C: Signing>(
    secp: &Secp256k1<C>,
    digest: [u8; 32],
    role: Role,
    signing_key: &Keypair,
    identities: &CanonicalIdentities,
    auxiliary_randomness: &[u8; 32],
) -> Result<[u8; 64], AuthError> {
    let (signer_identity, _) = signing_key.x_only_public_key();
    if identities.role_for_key(&signer_identity) != Ok(role) {
        return Err(AuthError::RoleKeyMismatch);
    }
    let message = Message::from_digest(digest);
    #[cfg(not(all(
        target_arch = "wasm32",
        target_os = "unknown",
        feature = "pure-rust-bip340",
        not(feature = "rust-secp256k1-auth")
    )))]
    let signature = secp.sign_schnorr_with_aux_rand(&message, signing_key, auxiliary_randomness);
    #[cfg(all(
        target_arch = "wasm32",
        target_os = "unknown",
        feature = "pure-rust-bip340",
        not(feature = "rust-secp256k1-auth")
    ))]
    let signature = secp
        .sign_schnorr_with_aux_rand(&message, signing_key, auxiliary_randomness)
        .map_err(|_| AuthError::InvalidSignature)?;
    Ok(signature.serialize())
}

pub(crate) fn verify_role_digest<C: Verification>(
    secp: &Secp256k1<C>,
    digest: [u8; 32],
    role: Role,
    signature: &[u8; 64],
    identities: &CanonicalIdentities,
) -> Result<(), AuthError> {
    let signature = Signature::from_slice(signature).map_err(|_| AuthError::InvalidSignature)?;
    secp.verify_schnorr(
        &signature,
        &Message::from_digest(digest),
        identities.key_for_role(role),
    )
    .map_err(|_| AuthError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

    use super::{
        AuthError, CanonicalIdentities, accepted_deal_digest, derive_game_id, derive_roles,
        envelope_digest, sign_accepted_deal, sign_envelope, verify_accepted_deal_signature,
        verify_accepted_deal_signatures, verify_envelope,
    };
    use crate::{
        N_SLOTS, PROTOCOL_VERSION, Role,
        messages::{AcceptedDeal, AcceptedDealBody, PayloadType, UnsignedEnvelope},
    };

    const AUXILIARY_RANDOMNESS: [u8; 32] = [0xa5; 32];

    fn keypair(secret_number: u8) -> Result<Keypair, bitcoin::secp256k1::Error> {
        let secp = Secp256k1::new();
        let mut secret = [0_u8; 32];
        secret[31] = secret_number;
        Keypair::from_seckey_slice(&secp, &secret)
    }

    fn identity(keypair: &Keypair) -> XOnlyPublicKey {
        keypair.x_only_public_key().0
    }

    fn identities(first: &Keypair, second: &Keypair) -> Result<CanonicalIdentities, AuthError> {
        derive_roles(identity(first), identity(second))
    }

    fn sample_unsigned(role: Role) -> UnsignedEnvelope {
        UnsignedEnvelope {
            protocol_version: PROTOCOL_VERSION,
            game_id: [0x11; 32],
            attempt: 7,
            round: 0,
            sender_role: role,
            sequence: 0,
            previous_message_hash: [0x22; 32],
            payload_type: PayloadType::KeyCommit,
            payload: vec![0x33; 32],
        }
    }

    fn sample_accepted_body() -> AcceptedDealBody {
        AcceptedDealBody {
            protocol_version: PROTOCOL_VERSION,
            game_id: [0x10; 32],
            attempt: 5,
            hashes_a: core::array::from_fn(|index| [index.to_le_bytes()[0]; 32]),
            hashes_b: core::array::from_fn(|index| [(index + N_SLOTS).to_le_bytes()[0]; 32]),
            verification_transcript_root: [0x44; 32],
        }
    }

    #[test]
    fn roles_are_derived_from_serialized_key_order() -> Result<(), Box<dyn std::error::Error>> {
        let first = keypair(1)?;
        let second = keypair(2)?;
        let roles = derive_roles(identity(&second), identity(&first))?;

        assert!(roles.alice().serialize() < roles.bob().serialize());
        assert_eq!(roles.role_for_key(&identity(&first))?, Role::Alice);
        assert_eq!(roles.role_for_key(&identity(&second))?, Role::Bob);
        assert_eq!(
            derive_roles(identity(&first), identity(&first)),
            Err(AuthError::DuplicateIdentityKeys)
        );
        assert_eq!(
            roles.role_for_key(&identity(&keypair(3)?)),
            Err(AuthError::UnknownIdentityKey)
        );
        Ok(())
    }

    #[test]
    fn game_id_matches_immutable_profile_vector() -> Result<(), Box<dyn std::error::Error>> {
        let roles = identities(&keypair(2)?, &keypair(1)?)?;
        let network_id = [0x11; 32];
        let funding_outpoint = core::array::from_fn(|index| index.to_le_bytes()[0]);
        let actual = derive_game_id(&network_id, &funding_outpoint, &roles, &[0x22; 32]);
        assert_eq!(
            actual,
            [
                0x86, 0x59, 0x1c, 0x25, 0x86, 0xfc, 0xc6, 0xa9, 0x2a, 0x57, 0xd5, 0x58, 0xc9, 0x10,
                0x42, 0xed, 0x05, 0x80, 0xf0, 0xa3, 0x5c, 0xdc, 0x7e, 0x69, 0xf9, 0xef, 0xd2, 0xa1,
                0xf5, 0x64, 0x80, 0xd5,
            ]
        );
        Ok(())
    }

    #[test]
    fn signing_digests_match_immutable_profile_vectors() -> Result<(), AuthError> {
        assert_eq!(
            envelope_digest(&sample_unsigned(Role::Alice))?,
            [
                0xac, 0x74, 0xc5, 0x1d, 0x21, 0xe2, 0xf2, 0x32, 0x4d, 0xd3, 0x4e, 0x23, 0xcf, 0xc9,
                0x00, 0x3e, 0x41, 0x5d, 0x36, 0xfa, 0x3a, 0xd8, 0xc4, 0xb8, 0xd9, 0x58, 0x79, 0x62,
                0x68, 0xf2, 0xf5, 0xf1,
            ]
        );
        assert_eq!(
            accepted_deal_digest(&sample_accepted_body())?,
            [
                0x7f, 0x59, 0xb7, 0x13, 0xd5, 0x95, 0xa5, 0xa6, 0xa7, 0x6a, 0xe7, 0x53, 0x5d, 0xeb,
                0x4b, 0x5a, 0xec, 0xb7, 0x12, 0xeb, 0xc2, 0x75, 0xb1, 0x16, 0x8d, 0xad, 0x99, 0x7c,
                0x52, 0x1f, 0x56, 0x8f,
            ]
        );
        Ok(())
    }

    #[test]
    fn envelope_authentication_rejects_wrong_role_and_key() -> Result<(), Box<dyn std::error::Error>>
    {
        let secp = Secp256k1::new();
        let alice = keypair(1)?;
        let bob = keypair(2)?;
        let roles = identities(&alice, &bob)?;
        let unsigned = sample_unsigned(Role::Alice);

        assert_eq!(
            sign_envelope(&secp, &unsigned, &bob, &roles, &AUXILIARY_RANDOMNESS),
            Err(AuthError::RoleKeyMismatch)
        );
        assert_eq!(
            sign_envelope(
                &secp,
                &unsigned,
                &keypair(3)?,
                &roles,
                &AUXILIARY_RANDOMNESS,
            ),
            Err(AuthError::RoleKeyMismatch)
        );

        let envelope = sign_envelope(&secp, &unsigned, &alice, &roles, &AUXILIARY_RANDOMNESS)?;
        let repeated = sign_envelope(&secp, &unsigned, &alice, &roles, &AUXILIARY_RANDOMNESS)?;
        assert_eq!(envelope.signature, repeated.signature);
        verify_envelope(&secp, &envelope, &roles)?;

        let mut wrong_role = envelope.clone();
        wrong_role.unsigned.sender_role = Role::Bob;
        assert_eq!(
            verify_envelope(&secp, &wrong_role, &roles),
            Err(AuthError::InvalidSignature)
        );

        let wrong_identities = identities(&bob, &keypair(3)?)?;
        assert_eq!(
            verify_envelope(&secp, &envelope, &wrong_identities),
            Err(AuthError::InvalidSignature)
        );
        Ok(())
    }

    #[test]
    fn accepted_deal_requires_both_canonical_signers() -> Result<(), Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();
        let alice = keypair(1)?;
        let bob = keypair(2)?;
        let roles = identities(&alice, &bob)?;
        let body = sample_accepted_body();

        assert_eq!(
            sign_accepted_deal(
                &secp,
                &body,
                Role::Bob,
                &alice,
                &roles,
                &AUXILIARY_RANDOMNESS,
            ),
            Err(AuthError::RoleKeyMismatch)
        );

        let signature_a = sign_accepted_deal(
            &secp,
            &body,
            Role::Alice,
            &alice,
            &roles,
            &AUXILIARY_RANDOMNESS,
        )?;
        let signature_b =
            sign_accepted_deal(&secp, &body, Role::Bob, &bob, &roles, &AUXILIARY_RANDOMNESS)?;
        verify_accepted_deal_signature(&secp, &body, Role::Alice, &signature_a, &roles)?;
        assert_eq!(
            verify_accepted_deal_signature(&secp, &body, Role::Bob, &signature_a, &roles,),
            Err(AuthError::InvalidSignature)
        );

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
        verify_accepted_deal_signatures(&secp, &deal, &roles)?;

        let mut swapped = deal;
        swapped.signature_a = deal.signature_b;
        swapped.signature_b = deal.signature_a;
        assert_eq!(
            verify_accepted_deal_signatures(&secp, &swapped, &roles),
            Err(AuthError::InvalidSignature)
        );
        Ok(())
    }
}
