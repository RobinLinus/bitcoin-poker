//! BIP341 `SIGHASH_DEFAULT` digest and signature helpers.

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{
    Keypair, Message, Secp256k1, Signing, Verification, XOnlyPublicKey, schnorr::Signature,
};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{Script, Transaction, TxOut};

use crate::BitcoinBackendError;

/// Exact witness size of a Taproot `SIGHASH_DEFAULT` signature.
pub const DEFAULT_SIGHASH_SIGNATURE_BYTES: usize = 64;

/// A BIP340 signature using Taproot's implicit `SIGHASH_DEFAULT` mode.
///
/// The client produces and accepts exactly 64-byte witness encodings. The
/// tapscripts rely directly on `OP_CHECKSIG`; they do not duplicate this
/// off-chain encoding check with an `OP_SIZE` guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DefaultSighashSignature([u8; DEFAULT_SIGHASH_SIGNATURE_BYTES]);

impl DefaultSighashSignature {
    /// Parse a strict Taproot signature encoding.
    ///
    /// # Errors
    ///
    /// Rejects bytes that are not a canonical BIP340 signature.
    pub fn from_bytes(
        bytes: [u8; DEFAULT_SIGHASH_SIGNATURE_BYTES],
    ) -> Result<Self, BitcoinBackendError> {
        Signature::from_slice(&bytes).map_err(|_| BitcoinBackendError::InvalidBitcoinSignature)?;
        Ok(Self(bytes))
    }

    /// Parse an untrusted witness element and enforce the exact 64-byte
    /// `SIGHASH_DEFAULT` encoding.
    ///
    /// # Errors
    ///
    /// Rejects every explicit sighash encoding and malformed BIP340 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, BitcoinBackendError> {
        let bytes: [u8; DEFAULT_SIGHASH_SIGNATURE_BYTES] = bytes
            .try_into()
            .map_err(|_| BitcoinBackendError::NonDefaultSighashEncoding)?;
        Self::from_bytes(bytes)
    }

    /// Return the exact 64-byte witness encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; DEFAULT_SIGHASH_SIGNATURE_BYTES] {
        self.0
    }

    /// Return the exact 64-byte witness encoding by reference.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DEFAULT_SIGHASH_SIGNATURE_BYTES] {
        &self.0
    }

    fn schnorr_signature(self) -> Result<Signature, BitcoinBackendError> {
        Signature::from_slice(&self.0).map_err(|_| BitcoinBackendError::InvalidBitcoinSignature)
    }
}

/// Compute `SIGHASH_DEFAULT` for one Taproot script-path input.
///
/// Under BIP341, `SIGHASH_DEFAULT` selects the same input/output commitment set
/// as `SIGHASH_ALL`, while permitting the script to reject every alternative
/// mode by enforcing a 64-byte signature.
///
/// # Errors
///
/// Rejects an invalid input index or prevout set.
pub fn taproot_script_sighash_default(
    transaction: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
    script: &Script,
) -> Result<[u8; 32], BitcoinBackendError> {
    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let sighash = SighashCache::new(transaction)
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|_| BitcoinBackendError::SighashComputation)?;
    Ok(sighash.to_byte_array())
}

/// Compute `SIGHASH_DEFAULT` for one Taproot key-path input.
///
/// # Errors
///
/// Rejects an invalid input index or prevout set.
pub fn taproot_key_sighash_default(
    transaction: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<[u8; 32], BitcoinBackendError> {
    let sighash = SighashCache::new(transaction)
        .taproot_key_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            TapSighashType::Default,
        )
        .map_err(|_| BitcoinBackendError::SighashComputation)?;
    Ok(sighash.to_byte_array())
}

/// Deterministically sign one already-computed BIP341 digest for tests and
/// offline graph preauthorization.
#[must_use]
pub fn sign_sighash_default<C: Signing>(
    secp: &Secp256k1<C>,
    keypair: &Keypair,
    digest: [u8; 32],
) -> DefaultSighashSignature {
    let message = Message::from_digest(digest);
    let signature = secp.sign_schnorr_no_aux_rand(&message, keypair);
    DefaultSighashSignature(signature.serialize())
}

/// Verify one signature under an exact x-only key and BIP341 digest.
///
/// # Errors
///
/// Rejects malformed keys and failed BIP340 verification. The signature type
/// itself proves the exact implicit-DEFAULT witness encoding.
pub fn verify_sighash_default<C: Verification>(
    secp: &Secp256k1<C>,
    public_key: [u8; 32],
    digest: [u8; 32],
    signature: DefaultSighashSignature,
) -> Result<(), BitcoinBackendError> {
    let public_key = XOnlyPublicKey::from_slice(&public_key).map_err(|_| {
        BitcoinBackendError::InvalidXOnlyPublicKey {
            purpose: "BIP340 signature verification",
        }
    })?;
    let message = Message::from_digest(digest);
    secp.verify_schnorr(&signature.schnorr_signature()?, &message, &public_key)
        .map_err(|_| BitcoinBackendError::InvalidBitcoinSignature)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut, Txid};

    use super::{
        DefaultSighashSignature, sign_sighash_default, taproot_script_sighash_default,
        verify_sighash_default,
    };
    use crate::{BitcoinBackendError, TransactionTemplate};

    fn keypair(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        byte: u8,
    ) -> Result<Keypair, bitcoin::secp256k1::Error> {
        let secret = SecretKey::from_slice(&[byte; 32])?;
        Ok(Keypair::from_secret_key(secp, &secret))
    }

    fn output(value: u64, script: ScriptBuf) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: script,
        }
    }

    #[test]
    fn default_signature_round_trip_and_output_binding() -> Result<(), Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();
        let keypair = keypair(&secp, 9)?;
        let (public_key, _) = keypair.x_only_public_key();
        let leaf = ScriptBuf::from_bytes(vec![0x51]);
        let parent = output(1_000, ScriptBuf::from_bytes(vec![0x51]));
        let template = TransactionTemplate::normal(
            Network::Regtest,
            OutPoint::new(Txid::from_byte_array([3_u8; 32]), 0),
            parent.clone(),
            vec![output(900, ScriptBuf::from_bytes(vec![0x51]))],
            100,
        )?;
        let digest = taproot_script_sighash_default(
            template.transaction(),
            0,
            std::slice::from_ref(&parent),
            &leaf,
        )?;
        let signature = sign_sighash_default(&secp, &keypair, digest);
        assert_eq!(signature.as_bytes().len(), 64);
        verify_sighash_default(&secp, public_key.serialize(), digest, signature)?;

        let changed = TransactionTemplate::normal(
            Network::Regtest,
            OutPoint::new(Txid::from_byte_array([3_u8; 32]), 0),
            parent.clone(),
            vec![output(899, ScriptBuf::from_bytes(vec![0x51]))],
            101,
        )?;
        let changed_digest = taproot_script_sighash_default(
            changed.transaction(),
            0,
            std::slice::from_ref(&parent),
            &leaf,
        )?;
        assert_ne!(digest, changed_digest);
        assert_eq!(
            verify_sighash_default(&secp, public_key.serialize(), changed_digest, signature,),
            Err(BitcoinBackendError::InvalidBitcoinSignature)
        );
        Ok(())
    }

    #[test]
    fn signature_codec_rejects_every_explicit_hash_type() -> Result<(), bitcoin::secp256k1::Error> {
        let secp = Secp256k1::new();
        let keypair = keypair(&secp, 10)?;
        let signature = sign_sighash_default(&secp, &keypair, [42_u8; 32]);
        for explicit in [0_u8, 1, 2, 3, 0x81] {
            let mut bytes = signature.to_bytes().to_vec();
            bytes.push(explicit);
            assert_eq!(
                DefaultSighashSignature::from_slice(&bytes),
                Err(BitcoinBackendError::NonDefaultSighashEncoding)
            );
        }
        Ok(())
    }
}
