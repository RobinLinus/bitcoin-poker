//! Native origin-package construction and signing checks.

use std::path::Path;

use bp52_origin::{OriginContext, OriginPackage, ParticipantId, SignatureShare, StagingInput};

use crate::wallet::NativeWallet;

/// Exercise the complete fair-refund-before-funding signing order locally.
pub fn self_test(directory: &Path) -> Result<(), String> {
    let first = NativeWallet::load_or_create(&directory.join("host-wallet.key"))?;
    let second = NativeWallet::load_or_create(&directory.join("guest-wallet.key"))?;
    let context =
        OriginContext::new([1; 32], [2; 32], [3; 32]).map_err(|error| error.to_string())?;
    let first_input =
        StagingInput::from_display_txid_bytes([4; 32], 0, 27_000, first.compressed_public_key())
            .map_err(|error| error.to_string())?;
    let second_input =
        StagingInput::from_display_txid_bytes([5; 32], 1, 27_000, second.compressed_public_key())
            .map_err(|error| error.to_string())?;
    let package = OriginPackage::new(context, first_input, second_input)
        .map_err(|error| error.to_string())?;
    let first_id = ParticipantId::from_compressed_public_key(first.compressed_public_key())
        .map_err(|error| error.to_string())?;
    let second_id = ParticipantId::from_compressed_public_key(second.compressed_public_key())
        .map_err(|error| error.to_string())?;

    let refund_shares = [
        SignatureShare::new(first_id, first.sign_compact(package.refund_sighash())?),
        SignatureShare::new(second_id, second.sign_compact(package.refund_sighash())?),
    ];
    let signed_refund = package
        .assemble_signed_refund(refund_shares)
        .map_err(|error| error.to_string())?;
    if signed_refund.consensus_bytes().is_empty() {
        return Err("assembled refund is empty".to_owned());
    }

    let funding_shares = [
        SignatureShare::new(
            first_id,
            first.sign_compact(
                package
                    .funding_sighash(first_id)
                    .map_err(|error| error.to_string())?,
            )?,
        ),
        SignatureShare::new(
            second_id,
            second.sign_compact(
                package
                    .funding_sighash(second_id)
                    .map_err(|error| error.to_string())?,
            )?,
        ),
    ];
    let signed_funding = package
        .assemble_signed_funding(funding_shares)
        .map_err(|error| error.to_string())?;
    if signed_funding.txid() != package.funding_txid() {
        return Err("funding witness changed the transaction id".to_owned());
    }
    Ok(())
}
