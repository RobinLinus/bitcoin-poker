//! Two-party native origin funding with refund-first safety.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bitcoin::Transaction;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::DisplayHex as _;
use bp52_adapter_esplora::EsploraClient;
use bp52_client_ports::{
    ChainProfile, ChainReader, RawTransaction, TransactionPublisher, TransactionStatus,
};
use bp52_origin::{
    CONTRIBUTION_SAT, CompactSignature, NonceSeat, OriginContext, OriginPackage, ParticipantId,
    SignatureShare, StagingInput, commit_session_nonce_share, derive_session_nonce,
};
use bp52_transport_libp2p::{PeerEvents, PeerHandle};
use rand::RngCore as _;
use rand::rngs::OsRng;

use crate::game::receive;
use crate::wallet::NativeWallet;

const IDENTITY_KIND: &str = "origin-identity-v1";
const ROOM_KIND: &str = "origin-room-v1";
const NONCE_COMMIT_KIND: &str = "origin-nonce-commit-v1";
const NONCE_REVEAL_KIND: &str = "origin-nonce-reveal-v1";
const STAGING_KIND: &str = "origin-staging-v1";
const PACKAGE_KIND: &str = "origin-package-v1";
const REFUND_SIGNATURE_KIND: &str = "origin-refund-signature-v1";
const FUNDING_SIGNATURE_KIND: &str = "origin-funding-signature-v1";
const FUNDING_TXID_KIND: &str = "origin-funding-txid-v1";

/// Public outputs required to bind DEAL and CHAIN to the confirmed origin.
pub struct FundedOrigin {
    /// Canonical profile identifier.
    pub network_id: [u8; 32],
    /// Private room binding committed by the origin script.
    pub room_id: [u8; 32],
    /// Joint nonce produced by commit/reveal.
    pub session_nonce: [u8; 32],
    /// Confirmed funding outpoint in consensus encoding.
    pub outpoint: [u8; 36],
    /// Canonical participant identities.
    pub identities: [[u8; 32]; 2],
    /// Exact origin witness script.
    pub witness_script: Vec<u8>,
}

/// Coordinate, sign, publish, and confirm a fresh shared origin.
pub async fn create(
    handle: &PeerHandle,
    events: &mut PeerEvents,
    wallet: &NativeWallet,
    host: bool,
    client: &mut EsploraClient,
    profile: &ChainProfile,
) -> Result<FundedOrigin, String> {
    let local_identity = wallet.xonly_public_key();
    let mut identity_message = Vec::with_capacity(65);
    identity_message.extend_from_slice(&local_identity);
    identity_message.extend_from_slice(&wallet.compressed_public_key());
    send(handle, IDENTITY_KIND, identity_message).await?;
    let peer_identity_message = receive(events, IDENTITY_KIND).await?;
    if peer_identity_message.len() != 65 {
        return Err("peer origin identity has the wrong length".to_owned());
    }
    let peer_identity: [u8; 32] = fixed(&peer_identity_message[..32])?;
    let peer_compressed: [u8; 33] = fixed(&peer_identity_message[32..])?;
    let local_is_alice = local_identity < peer_identity;
    if local_identity == peer_identity {
        return Err("players have the same Bitcoin identity".to_owned());
    }
    let identities = if local_is_alice {
        [local_identity, peer_identity]
    } else {
        [peer_identity, local_identity]
    };

    let room_id = if host {
        let room = random_nonzero();
        send(handle, ROOM_KIND, room.to_vec()).await?;
        room
    } else {
        fixed(&receive(events, ROOM_KIND).await?)?
    };
    let local_share = random_nonzero();
    let local_seat = if local_is_alice {
        NonceSeat::Alice
    } else {
        NonceSeat::Bob
    };
    let peer_seat = if local_is_alice {
        NonceSeat::Bob
    } else {
        NonceSeat::Alice
    };
    let local_commitment = commit_session_nonce_share(room_id, local_seat, local_share);
    send(handle, NONCE_COMMIT_KIND, local_commitment.to_vec()).await?;
    let peer_commitment: [u8; 32] = fixed(&receive(events, NONCE_COMMIT_KIND).await?)?;
    send(handle, NONCE_REVEAL_KIND, local_share.to_vec()).await?;
    let peer_share: [u8; 32] = fixed(&receive(events, NONCE_REVEAL_KIND).await?)?;
    if commit_session_nonce_share(room_id, peer_seat, peer_share) != peer_commitment {
        return Err("peer session-nonce opening does not match its commitment".to_owned());
    }
    let session_nonce = if local_is_alice {
        derive_session_nonce(room_id, local_share, peer_share)
    } else {
        derive_session_nonce(room_id, peer_share, local_share)
    };
    let context = OriginContext::new(profile.profile_id(), room_id, session_nonce)
        .map_err(|error| error.to_string())?;

    let local_utxo = wait_for_staging(client, wallet).await?;
    let local_input = staging_input(
        local_utxo.txid,
        local_utxo.vout,
        local_utxo.value_sat,
        wallet.compressed_public_key(),
    )?;
    send(handle, STAGING_KIND, encode_staging(&local_input)).await?;
    let peer_input = decode_staging(&receive(events, STAGING_KIND).await?, peer_compressed)?;
    let package =
        OriginPackage::new(context, local_input, peer_input).map_err(|error| error.to_string())?;
    send(handle, PACKAGE_KIND, package.package_id().to_vec()).await?;
    if fixed::<32>(&receive(events, PACKAGE_KIND).await?)? != package.package_id() {
        return Err("players derived different origin packages".to_owned());
    }

    let local_id = ParticipantId::from_compressed_public_key(wallet.compressed_public_key())
        .map_err(|error| error.to_string())?;
    let refund_share =
        SignatureShare::new(local_id, wallet.sign_compact(package.refund_sighash())?);
    send(
        handle,
        REFUND_SIGNATURE_KIND,
        encode_signature(refund_share),
    )
    .await?;
    let peer_refund = decode_signature(&receive(events, REFUND_SIGNATURE_KIND).await?)?;
    let signed_refund = package
        .assemble_signed_refund([refund_share, peer_refund])
        .map_err(|error| error.to_string())?;
    persist_refund(package.package_id(), signed_refund.consensus_bytes(), host)?;
    println!(
        "Fair refund saved before funding signature: {}",
        package.refund_txid()
    );

    let funding_share = SignatureShare::new(
        local_id,
        wallet.sign_compact(
            package
                .funding_sighash(local_id)
                .map_err(|error| error.to_string())?,
        )?,
    );
    send(
        handle,
        FUNDING_SIGNATURE_KIND,
        encode_signature(funding_share),
    )
    .await?;
    let peer_funding = decode_signature(&receive(events, FUNDING_SIGNATURE_KIND).await?)?;
    let signed_funding = package
        .assemble_signed_funding([funding_share, peer_funding])
        .map_err(|error| error.to_string())?;
    let transaction: Transaction = deserialize(signed_funding.consensus_bytes())
        .map_err(|_| "assembled origin funding is not a Bitcoin transaction".to_owned())?;
    let txid = transaction.compute_txid().to_byte_array();
    if host {
        let chain = client
            .verify_chain_identity(profile)
            .map_err(|error| error.to_string())?;
        let raw = RawTransaction::new(txid, signed_funding.consensus_bytes().to_vec())
            .map_err(|error| error.to_string())?;
        let published = client
            .broadcast(&chain, &raw)
            .map_err(|error| error.to_string())?;
        if published != txid {
            return Err("Esplora returned a different funding txid".to_owned());
        }
        send(handle, FUNDING_TXID_KIND, txid.to_vec()).await?;
    } else if fixed::<32>(&receive(events, FUNDING_TXID_KIND).await?)? != txid {
        return Err("host announced a different origin funding transaction".to_owned());
    }
    wait_for_confirmation(client, profile, txid).await?;

    let mut outpoint = [0_u8; 36];
    outpoint[..32].copy_from_slice(&txid);
    println!("Shared origin confirmed: {}:0", transaction.compute_txid());
    Ok(FundedOrigin {
        network_id: profile.profile_id(),
        room_id,
        session_nonce,
        outpoint,
        identities,
        witness_script: package.origin_witness_script().to_vec(),
    })
}

async fn wait_for_staging(
    client: &EsploraClient,
    wallet: &NativeWallet,
) -> Result<bp52_adapter_esplora::AddressUtxo, String> {
    println!(
        "Waiting for at least {CONTRIBUTION_SAT} confirmed sats at {}",
        wallet.staging_address()
    );
    loop {
        let mut candidates = client
            .confirmed_address_utxos(&wallet.staging_address())
            .map_err(|error| error.to_string())?;
        candidates.sort_unstable_by_key(|candidate| {
            (candidate.value_sat, candidate.txid, candidate.vout)
        });
        if let Some(candidate) = candidates.into_iter().find(|candidate| {
            candidate.value_sat == CONTRIBUTION_SAT || candidate.value_sat >= CONTRIBUTION_SAT + 330
        }) {
            return Ok(candidate);
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn wait_for_confirmation(
    client: &mut EsploraClient,
    profile: &ChainProfile,
    txid: [u8; 32],
) -> Result<(), String> {
    let chain = client
        .verify_chain_identity(profile)
        .map_err(|error| error.to_string())?;
    loop {
        match client
            .transaction_status(&chain, txid)
            .map_err(|error| error.to_string())?
        {
            TransactionStatus::Confirmed { .. } => return Ok(()),
            TransactionStatus::Unknown | TransactionStatus::Mempool => {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

fn staging_input(
    mut consensus_txid: [u8; 32],
    vout: u32,
    value_sat: u64,
    public_key: [u8; 33],
) -> Result<StagingInput, String> {
    consensus_txid.reverse();
    StagingInput::from_display_txid_bytes(consensus_txid, vout, value_sat, public_key)
        .map_err(|error| error.to_string())
}

fn encode_staging(input: &StagingInput) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(77);
    bytes.extend_from_slice(&input.outpoint().txid().to_display_bytes());
    bytes.extend_from_slice(&input.outpoint().vout().to_le_bytes());
    bytes.extend_from_slice(&input.value_sat().to_le_bytes());
    bytes.extend_from_slice(&input.compressed_public_key());
    bytes
}

fn decode_staging(bytes: &[u8], expected_key: [u8; 33]) -> Result<StagingInput, String> {
    if bytes.len() != 77 {
        return Err("peer staging input has the wrong length".to_owned());
    }
    let key: [u8; 33] = fixed(&bytes[44..])?;
    if key != expected_key {
        return Err("peer staging key differs from its authenticated identity".to_owned());
    }
    StagingInput::from_display_txid_bytes(
        fixed(&bytes[..32])?,
        u32::from_le_bytes(fixed(&bytes[32..36])?),
        u64::from_le_bytes(fixed(&bytes[36..44])?),
        key,
    )
    .map_err(|error| error.to_string())
}

fn encode_signature(share: SignatureShare) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(&share.signer().to_bytes());
    bytes.extend_from_slice(&share.signature().to_bytes());
    bytes
}

fn decode_signature(bytes: &[u8]) -> Result<SignatureShare, String> {
    if bytes.len() != 96 {
        return Err("peer signature share has the wrong length".to_owned());
    }
    let signer =
        ParticipantId::from_bytes(fixed(&bytes[..32])?).map_err(|error| error.to_string())?;
    let signature =
        CompactSignature::new(fixed(&bytes[32..])?).map_err(|error| error.to_string())?;
    Ok(SignatureShare::new(signer, signature))
}

fn refund_path(package_id: [u8; 32], host: bool) -> PathBuf {
    Path::new(".bp52")
        .join("refunds")
        .join(if host { "host" } else { "guest" })
        .join(format!("{}.tx", package_id.to_lower_hex_string()))
}

fn persist_refund(package_id: [u8; 32], transaction: &[u8], host: bool) -> Result<(), String> {
    let path = refund_path(package_id, host);
    let directory = path
        .parent()
        .ok_or_else(|| "refund path has no parent directory".to_owned())?;
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    match fs::read(&path) {
        Ok(existing) if existing == transaction => return Ok(()),
        Ok(_) => return Err("stored refund file conflicts with this package".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return match fs::read(&path) {
                Ok(existing) if existing == transaction => Ok(()),
                Ok(_) => Err("stored refund file conflicts with this package".to_owned()),
                Err(read_error) => Err(read_error.to_string()),
            };
        }
        Err(error) => return Err(error.to_string()),
    };
    file.write_all(transaction)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())
}

async fn send(handle: &PeerHandle, kind: &str, payload: Vec<u8>) -> Result<(), String> {
    handle
        .send(kind.to_owned(), payload)
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::refund_path;

    #[test]
    fn refund_files_are_scoped_to_each_cli_role() {
        let package_id = [0x42; 32];
        let host = refund_path(package_id, true);
        let guest = refund_path(package_id, false);
        assert_ne!(host, guest);
        assert!(host.starts_with(".bp52/refunds/host"));
        assert!(guest.starts_with(".bp52/refunds/guest"));
        assert_eq!(host.file_name(), guest.file_name());
    }
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| "peer artifact has the wrong length".to_owned())
}

fn random_nonzero() -> [u8; 32] {
    loop {
        let mut bytes = [0_u8; 32];
        OsRng.fill_bytes(&mut bytes);
        if bytes != [0; 32] {
            return bytes;
        }
    }
}
