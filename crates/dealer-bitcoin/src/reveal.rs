//! Contract extension specified in `docs/ONCHAIN_REVEAL_EXTENSION.md`.

use dealer_group::{encode_point, protocol_parameters};
use k256::{ProjectivePoint, Scalar};
use musig2::{
    AdaptorSignature, BinaryEncoding, LiftedSignature, adaptor,
    secp::{MaybePoint, MaybeScalar, Point, Scalar as SigningScalar},
};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Compile one reveal step. Witness order is actor signature, then one completed
/// adaptor signature for each slot in the supplied order. The graph must bind
/// these distinct keys to the opponent and retain the corresponding packages.
/// Deal, node, and slot metadata are validated here and bound by the caller's
/// graph and signing context; they are not repeated in the executable script.
///
/// # Errors
///
/// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
pub fn reveal_tapscript(
    deal_id: [u8; 32],
    node_id: [u8; 32],
    actor: [u8; 32],
    slots: &[(u8, [u8; 32])],
) -> Result<bitcoin::ScriptBuf, RevealError> {
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY};
    if deal_id == [0; 32] || node_id == [0; 32] || slots.is_empty() || slots.len() > 3 {
        return Err(RevealError::Context);
    }
    Point::lift_x(actor).map_err(|_| RevealError::Context)?;
    for (index, (slot, key)) in slots.iter().enumerate() {
        Point::lift_x(*key).map_err(|_| RevealError::Context)?;
        if *slot > 8 || *key == actor || slots[..index].iter().any(|(s, k)| s == slot || k == key) {
            return Err(RevealError::Context);
        }
    }
    let mut builder = bitcoin::script::Builder::new();
    for (_, key) in slots.iter().rev() {
        builder = builder.push_slice(key).push_opcode(OP_CHECKSIGVERIFY);
    }
    Ok(builder
        .push_slice(actor)
        .push_opcode(OP_CHECKSIG)
        .into_script())
}

/// Number of possible values of one contribution.
pub const SHARE_CANDIDATES: usize = 52;
/// Canonical package size: context hash and 52 compressed adaptor signatures.
pub const REVEAL_PACKAGE_BYTES: usize = 32 + SHARE_CANDIDATES * 65;

thread_local! {
    // A deal has eighteen public contribution commitments. Every tree branch
    // reuses their 52 encryption points; only its signature context changes.
    static ENCRYPTION_POINTS: std::cell::RefCell<Vec<(ProjectivePoint, Vec<MaybePoint>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Public context independently supplied by the verified graph, never the peer package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevealContext {
    /// Replay-verified accepted deal hash.
    pub deal_id: [u8; 32],
    /// Agreed graph/profile commitment.
    pub graph_id: [u8; 32],
    /// Exact parent node identifier.
    pub node_id: [u8; 32],
    /// Owning role, zero for Alice or one for Bob.
    pub revealer: u8,
    /// Slot in the accepted deal.
    pub slot: u8,
    /// Unique slot-specific opponent authorization key from the graph.
    pub authorizer: [u8; 32],
    /// Exact BIP341 `SIGHASH_DEFAULT` transaction digest.
    pub sighash: [u8; 32],
    /// Accepted full signed commitment of this role and slot.
    pub commitment: ProjectivePoint,
}

/// A failed binding, malformed encoding, or invalid cryptographic relation.
#[derive(Debug, Error)]
pub enum RevealError {
    /// Context or key is invalid.
    #[error("invalid on-chain reveal context")]
    Context,
    /// Package has the wrong size or a noncanonical signature.
    #[error("invalid on-chain reveal encoding")]
    Encoding,
    /// An adaptor or final signature does not verify.
    #[error("invalid on-chain reveal authorization")]
    Signature,
    /// An opening or extracted secret does not match the accepted commitment.
    #[error("on-chain reveal opening does not match commitment")]
    Opening,
}

/// Preauthorizations which all verify against an independently known context.
/// The wire bytes contain no secret openings.
#[derive(Clone)]
pub struct VerifiedRevealPackage {
    context: RevealContext,
    context_digest: [u8; 32],
    candidates: Vec<AdaptorSignature>,
}

impl RevealContext {
    fn validate(&self) -> Result<Point, RevealError> {
        if self.revealer > 1
            || self.slot > 8
            || self.deal_id == [0; 32]
            || self.graph_id == [0; 32]
            || self.node_id == [0; 32]
            || self.commitment == ProjectivePoint::IDENTITY
        {
            return Err(RevealError::Context);
        }
        Point::lift_x(self.authorizer).map_err(|_| RevealError::Context)
    }

    fn encryption_point(&self, value: u8) -> Result<MaybePoint, RevealError> {
        if usize::from(value) >= SHARE_CANDIDATES { return Err(RevealError::Context); }
        ENCRYPTION_POINTS.with(|cache| {
            let mut cache = cache.borrow_mut();
            if let Some((_, points)) = cache.iter().find(|(commitment, _)| *commitment == self.commitment) {
                return Ok(points[usize::from(value)]);
            }
            let mut point = self.commitment;
            let mut points = Vec::with_capacity(SHARE_CANDIDATES);
            let mut bytes = Vec::with_capacity(33);
            for _ in 0..SHARE_CANDIDATES {
                bytes.clear();
                encode_point(&point, &mut bytes);
                // Use the canonical encoding across the k256/secp backends.
                points.push(MaybePoint::from_slice(&bytes).map_err(|_| RevealError::Context)?);
                point -= protocol_parameters().m;
            }
            let result = points[usize::from(value)];
            if cache.len() == 18 { cache.remove(0); }
            cache.push((self.commitment, points));
            Ok(result)
        })
    }

    fn digest(&self) -> [u8; 32] {
        let tag = Sha256::digest(b"DLOG52/onchain-reveal-context/v1");
        let mut hash = Sha256::new();
        hash.update(tag);
        hash.update(tag);
        hash.update(self.deal_id);
        hash.update(self.graph_id);
        hash.update(self.node_id);
        hash.update([self.revealer, self.slot]);
        hash.update(self.authorizer);
        hash.update(self.sighash);
        let mut commitment = Vec::with_capacity(33);
        encode_point(&self.commitment, &mut commitment);
        hash.update(commitment);
        hash.finalize().into()
    }

    fn nonce_seed(&self, value: u8, auxiliary: &[u8; 32]) -> Result<[u8; 32], RevealError> {
        let tag = Sha256::digest(b"DLOG52/onchain-reveal-adaptor-nonce/v1");
        let mut hash = Sha256::new();
        hash.update(tag);
        hash.update(tag);
        hash.update(auxiliary);
        hash.update(self.deal_id);
        hash.update(self.graph_id);
        hash.update(self.node_id);
        hash.update([self.revealer, self.slot, value]);
        hash.update(self.authorizer);
        hash.update(self.sighash);
        hash.update(self.encryption_point(value)?.serialize());
        Ok(hash.finalize().into())
    }
}

/// Locally generated outgoing authorizations. This type has no decoder and
/// cannot be used as a verified peer package; receivers must call `verify`.
pub struct GeneratedRevealPackage {
    bytes: Vec<u8>,
}

impl GeneratedRevealPackage {
    /// Preauthorize every possible opening without knowing the releaser's secret.
    /// The caller must persist the returned bytes before sending them.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn create(
        context: &RevealContext,
        signing_key: &[u8; 32],
        auxiliary: &[u8; 32],
    ) -> Result<Self, RevealError> {
        let public = context.validate()?;
        let secret = SigningScalar::from_slice(signing_key).map_err(|_| RevealError::Context)?;
        if secret.base_point_mul().serialize_xonly() != public.serialize_xonly() {
            return Err(RevealError::Context);
        }
        let mut candidates = Vec::with_capacity(SHARE_CANDIDATES);
        for value in 0..52_u8 {
            let point = context.encryption_point(value)?;
            let signature = adaptor::sign_solo(
                secret,
                context.sighash,
                context.nonce_seed(value, auxiliary)?,
                point,
            );
            candidates.push(signature);
        }
        let context_digest = context.digest();
        let mut bytes = Vec::with_capacity(REVEAL_PACKAGE_BYTES);
        bytes.extend_from_slice(&context_digest);
        bytes.extend(candidates.iter().flat_map(BinaryEncoding::to_bytes));
        Ok(Self { bytes })
    }

    /// Canonical wire bytes; local provenance does not verify peer input.
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> { self.bytes }
}

impl VerifiedRevealPackage {
    /// Generate and independently verify a package for callers requiring the
    /// verified type. The outgoing worker uses `GeneratedRevealPackage` instead.
    ///
    /// # Errors
    /// Rejects invalid contexts, keys or authorizations.
    pub fn create(context: RevealContext, signing_key: &[u8; 32], auxiliary: &[u8; 32]) -> Result<Self, RevealError> {
        let outgoing = GeneratedRevealPackage::create(&context, signing_key, auxiliary)?;
        Self::verify(context, &outgoing.to_bytes())
    }

    /// Verify exactly 52 canonical adaptors against the graph's expected context.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn verify(context: RevealContext, bytes: &[u8]) -> Result<Self, RevealError> {
        let public = context.validate()?;
        if bytes.len() != REVEAL_PACKAGE_BYTES || bytes[..32] != context.digest() {
            return Err(RevealError::Encoding);
        }
        let mut candidates = Vec::with_capacity(SHARE_CANDIDATES);
        for (value, encoded) in (0..52_u8).zip(bytes[32..].chunks_exact(65)) {
            let signature =
                AdaptorSignature::from_bytes(encoded).map_err(|_| RevealError::Encoding)?;
            if signature.to_bytes() != encoded {
                return Err(RevealError::Encoding);
            }
            adaptor::verify_single(
                public,
                &signature,
                context.sighash,
                context.encryption_point(value)?,
            )
            .map_err(|_| RevealError::Signature)?;
            candidates.push(signature);
        }
        let context_digest = context.digest();
        Ok(Self {
            context,
            context_digest,
            candidates,
        })
    }

    /// Canonical, durable public package bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(REVEAL_PACKAGE_BYTES);
        bytes.extend_from_slice(&self.context_digest);
        bytes.extend(self.candidates.iter().flat_map(BinaryEncoding::to_bytes));
        bytes
    }

    /// Complete one ordinary Bitcoin signature with the actual accepted opening.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn complete(&self, value: u8, blinding: Scalar) -> Result<[u8; 64], RevealError> {
        if value > 51
            || self.context.encryption_point(value)? != MaybeScalar::from(blinding).base_point_mul()
        {
            return Err(RevealError::Opening);
        }
        let signature: LiftedSignature = self.candidates[usize::from(value)]
            .adapt(MaybeScalar::from(blinding))
            .ok_or(RevealError::Signature)?;
        musig2::verify_single(self.context.validate()?, signature, self.context.sighash)
            .map_err(|_| RevealError::Signature)?;
        Ok(signature.to_bytes())
    }

    /// Recover the opening from a valid completed transaction signature.
    /// Call only after the chain runtime authenticates the containing transition.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn extract(&self, bytes: &[u8; 64]) -> Result<(u8, Scalar), RevealError> {
        let signature = LiftedSignature::from_bytes(bytes).map_err(|_| RevealError::Encoding)?;
        musig2::verify_single(self.context.validate()?, signature, self.context.sighash)
            .map_err(|_| RevealError::Signature)?;
        for (value, candidate) in (0..52_u8).zip(&self.candidates) {
            if let Some(secret) = candidate.reveal_secret::<MaybeScalar>(&signature) {
                if secret.base_point_mul() == self.context.encryption_point(value)? {
                    return Ok((value, Scalar::from(secret)));
                }
            }
        }
        Err(RevealError::Opening)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_encryption_points_match_scalar_formula_and_stay_bounded() -> Result<(), RevealError> {
        for n in 0..20_u64 {
            let context = RevealContext { deal_id: [1; 32], graph_id: [2; 32], node_id: [3; 32],
                revealer: 0, slot: 0, authorizer: [4; 32], sighash: [5; 32],
                commitment: protocol_parameters().m * Scalar::from(n) };
            for value in 0..52_u8 {
                let mut bytes = Vec::new();
                encode_point(&(context.commitment - protocol_parameters().m * Scalar::from(u64::from(value))), &mut bytes);
                let expected = MaybePoint::from_slice(&bytes).map_err(|_| RevealError::Context)?;
                assert_eq!(context.encryption_point(value)?, expected);
                assert_eq!(context.encryption_point(value)?, expected);
            }
            assert!(context.encryption_point(52).is_err());
        }
        ENCRYPTION_POINTS.with(|cache| assert_eq!(cache.borrow().len(), 18));
        Ok(())
    }

    #[test]
    fn reveal_packages_bind_all_candidates_and_recover_the_opening() -> Result<(), RevealError> {
        let key = [19; 32];
        let authorizer = SigningScalar::from_slice(&key)
            .map_err(|_| RevealError::Context)?
            .base_point_mul()
            .serialize_xonly();
        for value in 0..52_u8 {
            for blinding in [Scalar::ZERO, Scalar::from(71_u64), -Scalar::from(83_u64)] {
                let context = RevealContext {
                    deal_id: [1; 32],
                    graph_id: [2; 32],
                    node_id: [3; 32],
                    revealer: 0,
                    slot: 4,
                    authorizer,
                    sighash: [4; 32],
                    commitment: protocol_parameters().m * Scalar::from(u64::from(value))
                        + ProjectivePoint::GENERATOR * blinding,
                };
                if context.commitment == ProjectivePoint::IDENTITY {
                    continue;
                }
                let sent = VerifiedRevealPackage::create(context.clone(), &key, &[5; 32])?;
                let received = VerifiedRevealPackage::verify(context.clone(), &sent.to_bytes())?;
                let signature = received.complete(value, blinding)?;
                assert_eq!(sent.extract(&signature)?, (value, blinding));
                assert!(received.complete((value + 1) % 52, blinding).is_err());
                let mut wrong_signature = signature;
                wrong_signature[40] ^= 1;
                assert!(sent.extract(&wrong_signature).is_err());
                let mut seeds = std::collections::HashSet::new();
                for candidate in 0..52 {
                    assert!(seeds.insert(context.nonce_seed(candidate, &[5; 32])?));
                }
                for field in 0..8 {
                    let mut wrong_context = context.clone();
                    match field {
                        0 => wrong_context.deal_id[0] ^= 1,
                        1 => wrong_context.graph_id[0] ^= 1,
                        2 => wrong_context.node_id[0] ^= 1,
                        3 => wrong_context.revealer ^= 1,
                        4 => wrong_context.slot += 1,
                        5 => wrong_context.authorizer[0] ^= 1,
                        6 => wrong_context.sighash[0] ^= 1,
                        _ => wrong_context.commitment += ProjectivePoint::GENERATOR,
                    }
                    assert!(
                        VerifiedRevealPackage::verify(wrong_context, &sent.to_bytes()).is_err()
                    );
                }
                let mut corrupted = sent.to_bytes();
                corrupted[64] ^= 1;
                assert!(
                    VerifiedRevealPackage::verify(received.context.clone(), &corrupted).is_err()
                );
            }
        }
        Ok(())
    }
}
