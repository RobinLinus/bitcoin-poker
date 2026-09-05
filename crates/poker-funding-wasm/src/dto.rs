use serde::{Deserialize, Serialize};

/// Transport seat used by the relay-facing coordinator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TransportRole {
    Alice,
    Bob,
}

impl TransportRole {
    pub(crate) const fn seat(self) -> usize {
        match self {
            Self::Alice => 0,
            Self::Bob => 1,
        }
    }

    pub(crate) const fn opposite(self) -> Self {
        match self {
            Self::Alice => Self::Bob,
            Self::Bob => Self::Alice,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NonceCommitmentControlDto {
    pub(crate) version: u32,
    pub(crate) room_id: String,
    pub(crate) transport_role: TransportRole,
    pub(crate) nonce_share: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SessionNonceControlDto {
    pub(crate) version: u32,
    pub(crate) room_id: String,
    pub(crate) alice_share: String,
    pub(crate) bob_share: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NonceCommitmentResultDto {
    pub(crate) commitment: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SessionNonceResultDto {
    pub(crate) session_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StagingArtifactDto {
    pub(crate) version: u32,
    pub(crate) protocol_profile_code: u8,
    pub(crate) network_id: String,
    pub(crate) room_id: String,
    pub(crate) session_nonce: String,
    pub(crate) transport_role: TransportRole,
    pub(crate) txid: String,
    pub(crate) vout: u32,
    pub(crate) value_sat: u64,
    pub(crate) witness_script_hex: String,
    pub(crate) script_pub_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StagingFundingControlDto {
    pub(crate) txid: String,
    pub(crate) vout: u32,
    pub(crate) value_sat: u64,
    pub(crate) witness_script_hex: String,
    pub(crate) script_pub_key_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PackageArtifactDto {
    pub(crate) version: u32,
    pub(crate) protocol_profile_code: u8,
    pub(crate) network_id: String,
    pub(crate) room_id: String,
    pub(crate) session_nonce: String,
    pub(crate) transport_role: TransportRole,
    pub(crate) package_id: String,
    pub(crate) funding_txid: String,
    pub(crate) refund_txid: String,
    pub(crate) origin_vout: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SignatureFrameDto {
    pub(crate) version: u32,
    pub(crate) protocol_profile_code: u8,
    pub(crate) network_id: String,
    pub(crate) room_id: String,
    pub(crate) session_nonce: String,
    pub(crate) transport_role: TransportRole,
    pub(crate) package_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) input_index: Option<u8>,
    pub(crate) sighash_type: u8,
    pub(crate) sighash_hex: String,
    pub(crate) compact_low_s_signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ActivationArtifactDto {
    pub(crate) version: u32,
    pub(crate) protocol_profile_code: u8,
    pub(crate) network_id: String,
    pub(crate) room_id: String,
    pub(crate) session_nonce: String,
    pub(crate) package_id: String,
    pub(crate) activation_id: String,
    pub(crate) activation_txid: String,
    pub(crate) gameplay_root_script_pub_key_hex: String,
    pub(crate) unsigned_tx_hex: String,
}

/// Strict superset DTO shared by the origin operations.
///
/// Each operation checks an exact presence set for the optional fields, so a
/// known field cannot be smuggled into an operation where it has no meaning.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OriginCommandInput {
    pub(crate) version: u32,
    pub(crate) protocol_profile_code: u8,
    pub(crate) network_id: String,
    pub(crate) room_id: String,
    pub(crate) session_nonce: String,
    pub(crate) transport_role: TransportRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) staging_funding: Option<StagingFundingControlDto>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) local_staging_funding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) peer_staging_funding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) package_frame: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) peer_package_frame: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) local_input_index: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sighash_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) local_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) peer_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) signed_refund_tx_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) local_refund_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) peer_refund_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) gameplay_root_script_pub_key_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) activation_frame: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) local_activation_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) peer_activation_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) signed_activation_tx_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) candidate_signature_hex: Option<String>,
}

impl OriginCommandInput {
    pub(crate) fn require_shape(&self, expected: u32) -> Result<(), String> {
        let actual = self.shape();
        if actual == expected {
            Ok(())
        } else {
            Err(format!(
                "origin operation has the wrong artifact set: expected {:?}, received {:?}",
                shape_names(expected),
                shape_names(actual),
            ))
        }
    }

    fn shape(&self) -> u32 {
        [
            (shape::STAGING, self.staging_funding.is_some()),
            (shape::LOCAL_STAGING, self.local_staging_funding.is_some()),
            (shape::PEER_STAGING, self.peer_staging_funding.is_some()),
            (shape::PACKAGE, self.package_frame.is_some()),
            (shape::PEER_PACKAGE, self.peer_package_frame.is_some()),
            (shape::LOCAL_INDEX, self.local_input_index.is_some()),
            (shape::SIGHASH, self.sighash_hex.is_some()),
            (shape::LOCAL_SIGNATURE, self.local_signature.is_some()),
            (shape::PEER_SIGNATURE, self.peer_signature.is_some()),
            (shape::SIGNED_REFUND, self.signed_refund_tx_hex.is_some()),
            (shape::LOCAL_REFUND, self.local_refund_signature.is_some()),
            (shape::PEER_REFUND, self.peer_refund_signature.is_some()),
            (
                shape::GAMEPLAY_ROOT,
                self.gameplay_root_script_pub_key_hex.is_some(),
            ),
            (shape::ACTIVATION, self.activation_frame.is_some()),
            (
                shape::LOCAL_ACTIVATION,
                self.local_activation_signature.is_some(),
            ),
            (
                shape::PEER_ACTIVATION,
                self.peer_activation_signature.is_some(),
            ),
            (
                shape::SIGNED_ACTIVATION,
                self.signed_activation_tx_hex.is_some(),
            ),
            (
                shape::CANDIDATE_SIGNATURE,
                self.candidate_signature_hex.is_some(),
            ),
        ]
        .into_iter()
        .filter_map(|(bit, present)| present.then_some(bit))
        .fold(0, |mask, bit| mask | bit)
    }
}

pub(crate) mod shape {
    pub(crate) const STAGING: u32 = 1 << 0;
    pub(crate) const LOCAL_STAGING: u32 = 1 << 1;
    pub(crate) const PEER_STAGING: u32 = 1 << 2;
    pub(crate) const PACKAGE: u32 = 1 << 3;
    pub(crate) const PEER_PACKAGE: u32 = 1 << 4;
    pub(crate) const LOCAL_INDEX: u32 = 1 << 5;
    pub(crate) const SIGHASH: u32 = 1 << 6;
    pub(crate) const LOCAL_SIGNATURE: u32 = 1 << 7;
    pub(crate) const PEER_SIGNATURE: u32 = 1 << 8;
    pub(crate) const SIGNED_REFUND: u32 = 1 << 9;
    pub(crate) const LOCAL_REFUND: u32 = 1 << 10;
    pub(crate) const PEER_REFUND: u32 = 1 << 11;
    pub(crate) const GAMEPLAY_ROOT: u32 = 1 << 12;
    pub(crate) const ACTIVATION: u32 = 1 << 13;
    pub(crate) const LOCAL_ACTIVATION: u32 = 1 << 14;
    pub(crate) const PEER_ACTIVATION: u32 = 1 << 15;
    pub(crate) const SIGNED_ACTIVATION: u32 = 1 << 16;
    pub(crate) const CANDIDATE_SIGNATURE: u32 = 1 << 17;
}

fn shape_names(mask: u32) -> Vec<&'static str> {
    [
        (shape::STAGING, "stagingFunding"),
        (shape::LOCAL_STAGING, "localStagingFunding"),
        (shape::PEER_STAGING, "peerStagingFunding"),
        (shape::PACKAGE, "packageFrame"),
        (shape::PEER_PACKAGE, "peerPackageFrame"),
        (shape::LOCAL_INDEX, "localInputIndex"),
        (shape::SIGHASH, "sighashHex"),
        (shape::LOCAL_SIGNATURE, "localSignature"),
        (shape::PEER_SIGNATURE, "peerSignature"),
        (shape::SIGNED_REFUND, "signedRefundTxHex"),
        (shape::LOCAL_REFUND, "localRefundSignature"),
        (shape::PEER_REFUND, "peerRefundSignature"),
        (shape::GAMEPLAY_ROOT, "gameplayRootScriptPubKeyHex"),
        (shape::ACTIVATION, "activationFrame"),
        (shape::LOCAL_ACTIVATION, "localActivationSignature"),
        (shape::PEER_ACTIVATION, "peerActivationSignature"),
        (shape::SIGNED_ACTIVATION, "signedActivationTxHex"),
        (shape::CANDIDATE_SIGNATURE, "candidateSignatureHex"),
    ]
    .into_iter()
    .filter_map(|(bit, name)| (mask & bit != 0).then_some(name))
    .collect()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PackageResultDto {
    pub(crate) package_frame: String,
    pub(crate) peer_package_frame: String,
    pub(crate) local_staging: StagingFundingControlDto,
    pub(crate) peer_staging: StagingFundingControlDto,
    pub(crate) package_id: String,
    pub(crate) funding_txid: String,
    pub(crate) refund_txid: String,
    pub(crate) origin_vout: u32,
    pub(crate) origin_value_sat: u64,
    pub(crate) origin_witness_script_hex: String,
    pub(crate) origin_script_pubkey_hex: String,
    pub(crate) funding_sighashes_hex: [String; 2],
    pub(crate) refund_sighash_hex: String,
    pub(crate) local_input_index: u8,
}

impl From<&StagingArtifactDto> for StagingFundingControlDto {
    fn from(value: &StagingArtifactDto) -> Self {
        Self {
            txid: value.txid.clone(),
            vout: value.vout,
            value_sat: value.value_sat,
            witness_script_hex: value.witness_script_hex.clone(),
            script_pub_key_hex: value.script_pub_key_hex.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StagingResultDto {
    pub(crate) staging_frame: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ActivationResultDto {
    pub(crate) activation_frame: String,
    pub(crate) activation_id: String,
    pub(crate) activation_txid: String,
    pub(crate) activation_sighash_hex: String,
    pub(crate) unsigned_tx_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SigningAuthorizationDto {
    pub(crate) sighash_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignatureResultDto {
    pub(crate) signature_frame: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SignedTransactionDto {
    pub(crate) signed_tx_hex: String,
    pub(crate) txid: String,
}

pub(crate) fn decode_hex_array<const LENGTH: usize>(
    value: &str,
    label: &str,
) -> Result<[u8; LENGTH], String> {
    if value.len() != LENGTH.saturating_mul(2) {
        return Err(format!("{label} must contain exactly {LENGTH} bytes"));
    }
    let bytes = value.as_bytes();
    let mut output = [0_u8; LENGTH];
    for (index, slot) in output.iter_mut().enumerate() {
        let high = decode_nibble(bytes[index * 2])
            .ok_or_else(|| format!("{label} must use canonical lowercase hexadecimal encoding"))?;
        let low = decode_nibble(bytes[index * 2 + 1])
            .ok_or_else(|| format!("{label} must use canonical lowercase hexadecimal encoding"))?;
        *slot = (high << 4) | low;
    }
    Ok(output)
}

pub(crate) fn encode_hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
