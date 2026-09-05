use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use poker_funding::diagnostic::{
    ACTIVATION_FEE_SAT, CONTRIBUTION_SAT, GAMEPLAY_ROOT_VALUE_SAT, ORIGIN_VALUE_SAT,
};
use poker_funding::{
    ActivationPackage, CompactSignature, EscrowFundingPackage, FundingContext, NonceSeat,
    ParticipantId, PlayerFundingInput, SignatureShare, commit_session_nonce_share,
    derive_session_nonce,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::ABI_VERSION;
use crate::dto::{
    ActivationArtifactDto, ActivationResultDto, NonceCommitmentControlDto,
    NonceCommitmentResultDto, OriginCommandInput, PackageArtifactDto, PackageResultDto,
    SessionNonceControlDto, SessionNonceResultDto, SignatureFrameDto, SignatureResultDto,
    SignedTransactionDto, SigningAuthorizationDto, StagingArtifactDto, StagingResultDto,
    TransportRole, decode_hex_array, encode_hex, shape,
};

const MAX_ARTIFACT_BYTES: usize = 16 * 1024;
const AUDITED_PROTOCOL_PROFILE_CODE: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    BuildStagingFrame,
    BuildPackage,
    AuthorizeRefundSignature,
    SealRefundSignature,
    AssembleRefund,
    BuildActivation,
    AuthorizeActivationSignature,
    SealActivationSignature,
    AssembleActivation,
    AuthorizeFundingSignature,
    SealFundingSignature,
    AssembleFunding,
}

#[derive(Clone, Copy)]
enum SignatureTarget<'a> {
    Refund,
    Funding,
    Activation(&'a ActivationPackage),
}

struct OriginEngine {
    package: EscrowFundingPackage,
    participants_by_seat: [ParticipantId; 2],
    local_staging: StagingArtifactDto,
    peer_staging: StagingArtifactDto,
    local_role: TransportRole,
    network_id: [u8; 32],
    room_id: [u8; 32],
    session_nonce: [u8; 32],
}

pub(crate) fn execute(
    operation: Operation,
    request: &OriginCommandInput,
) -> Result<Vec<u8>, String> {
    validate_shape(operation, request)?;
    if operation == Operation::BuildStagingFrame {
        return serde_json::to_vec(&build_staging_result(request)?)
            .map_err(|error| format!("could not serialize staging result: {error}"));
    }
    let engine = OriginEngine::new(request)?;
    let output = match operation {
        Operation::BuildStagingFrame => {
            return Err("staging operation reached the package engine".to_owned());
        }
        Operation::BuildPackage => serde_json::to_vec(&engine.package_result()?),
        Operation::AuthorizeRefundSignature => {
            engine.validate_package_request(request)?;
            let supplied = required(request.sighash_hex.as_ref(), "sighashHex")?;
            let expected = encode_hex(&engine.package.refund_sighash());
            require_equal(supplied, &expected, "refund signing digest")?;
            serde_json::to_vec(&SigningAuthorizationDto {
                sighash_hex: expected,
            })
        }
        Operation::SealRefundSignature => {
            engine.validate_package_request(request)?;
            serde_json::to_vec(&engine.seal_signature(request, SignatureTarget::Refund)?)
        }
        Operation::AssembleRefund => {
            engine.validate_package_request(request)?;
            let signed = engine.assemble_refund(request)?;
            serde_json::to_vec(&SignedTransactionDto {
                signed_tx_hex: encode_hex(&signed),
                txid: display_txid(engine.package.refund_txid()),
            })
        }
        Operation::BuildActivation => {
            engine.validate_package_request(request)?;
            let activation = engine.activation(request, false)?;
            serde_json::to_vec(&engine.activation_result(&activation)?)
        }
        Operation::AuthorizeActivationSignature => {
            engine.validate_package_request(request)?;
            let activation = engine.activation(request, true)?;
            let supplied = required(request.sighash_hex.as_ref(), "sighashHex")?;
            let expected = encode_hex(&activation.sighash());
            require_equal(supplied, &expected, "activation signing digest")?;
            serde_json::to_vec(&SigningAuthorizationDto {
                sighash_hex: expected,
            })
        }
        Operation::SealActivationSignature => {
            engine.validate_package_request(request)?;
            let activation = engine.activation(request, true)?;
            serde_json::to_vec(
                &engine.seal_signature(request, SignatureTarget::Activation(&activation))?,
            )
        }
        Operation::AssembleActivation => {
            engine.validate_package_request(request)?;
            engine.validate_durable_refund(request)?;
            let activation = engine.activation(request, true)?;
            let signed = engine.assemble_activation(request, &activation)?;
            serde_json::to_vec(&SignedTransactionDto {
                signed_tx_hex: encode_hex(&signed),
                txid: display_txid(activation.txid()),
            })
        }
        Operation::SealFundingSignature => {
            engine.validate_package_request(request)?;
            engine.validate_durable_refund(request)?;
            engine.validate_optional_durable_activation(request)?;
            serde_json::to_vec(&engine.seal_signature(request, SignatureTarget::Funding)?)
        }
        Operation::AuthorizeFundingSignature => {
            engine.validate_package_request(request)?;
            engine.validate_durable_refund(request)?;
            engine.validate_optional_durable_activation(request)?;
            let local_index = engine.local_input_index()?;
            let supplied = required(request.sighash_hex.as_ref(), "sighashHex")?;
            let expected =
                encode_hex(&engine.package.funding_sighashes()[usize::from(local_index)]);
            require_equal(supplied, &expected, "funding signing digest")?;
            serde_json::to_vec(&SigningAuthorizationDto {
                sighash_hex: expected,
            })
        }
        Operation::AssembleFunding => {
            engine.validate_package_request(request)?;
            engine.validate_durable_refund(request)?;
            engine.validate_optional_durable_activation(request)?;
            let signed = engine.assemble_funding(request)?;
            serde_json::to_vec(&SignedTransactionDto {
                signed_tx_hex: encode_hex(&signed),
                txid: display_txid(engine.package.funding_txid()),
            })
        }
    }
    .map_err(|error| format!("could not serialize origin result: {error}"))?;
    Ok(output)
}

pub(crate) fn nonce_commitment(request: &NonceCommitmentControlDto) -> Result<Vec<u8>, String> {
    require_nonce_version(request.version)?;
    let room_id = decode_nonzero_hex(&request.room_id, "roomId")?;
    let share = decode_nonzero_hex(&request.nonce_share, "nonceShare")?;
    let seat = match request.transport_role {
        TransportRole::Alice => NonceSeat::Alice,
        TransportRole::Bob => NonceSeat::Bob,
    };
    serde_json::to_vec(&NonceCommitmentResultDto {
        commitment: encode_hex(&commit_session_nonce_share(room_id, seat, share)),
    })
    .map_err(|error| format!("could not serialize nonce commitment: {error}"))
}

pub(crate) fn session_nonce(request: &SessionNonceControlDto) -> Result<Vec<u8>, String> {
    require_nonce_version(request.version)?;
    let room_id = decode_nonzero_hex(&request.room_id, "roomId")?;
    let alice_share = decode_nonzero_hex(&request.alice_share, "aliceShare")?;
    let bob_share = decode_nonzero_hex(&request.bob_share, "bobShare")?;
    let nonce = derive_session_nonce(room_id, alice_share, bob_share);
    if nonce == [0; 32] {
        return Err("derived session nonce is zero".to_owned());
    }
    serde_json::to_vec(&SessionNonceResultDto {
        session_nonce: encode_hex(&nonce),
    })
    .map_err(|error| format!("could not serialize session nonce: {error}"))
}

fn require_nonce_version(version: u32) -> Result<(), String> {
    if version == ABI_VERSION {
        Ok(())
    } else {
        Err("unsupported origin nonce request version".to_owned())
    }
}

fn decode_nonzero_hex(value: &str, label: &str) -> Result<[u8; 32], String> {
    let decoded = decode_hex_array(value, label)?;
    if decoded == [0; 32] {
        Err(format!("{label} must be nonzero"))
    } else {
        Ok(decoded)
    }
}

fn validate_shape(operation: Operation, request: &OriginCommandInput) -> Result<(), String> {
    const STAGING_PAIR: u32 = shape::LOCAL_STAGING | shape::PEER_STAGING;
    const PACKAGE_PAIR: u32 = shape::PACKAGE | shape::PEER_PACKAGE | shape::LOCAL_INDEX;
    const BASE: u32 = STAGING_PAIR | PACKAGE_PAIR;
    const REFUND_PROTECTION: u32 = shape::SIGNED_REFUND | shape::LOCAL_REFUND | shape::PEER_REFUND;
    const ACTIVATION_PROTECTION: u32 = shape::GAMEPLAY_ROOT
        | shape::ACTIVATION
        | shape::LOCAL_ACTIVATION
        | shape::PEER_ACTIVATION
        | shape::SIGNED_ACTIVATION;
    match operation {
        Operation::BuildStagingFrame => request.require_shape(shape::STAGING),
        Operation::BuildPackage => request.require_shape(STAGING_PAIR),
        Operation::AuthorizeRefundSignature => request.require_shape(BASE | shape::SIGHASH),
        Operation::SealRefundSignature => {
            request.require_shape(BASE | shape::SIGHASH | shape::CANDIDATE_SIGNATURE)
        }
        Operation::AssembleRefund => {
            request.require_shape(BASE | shape::LOCAL_SIGNATURE | shape::PEER_SIGNATURE)
        }
        Operation::BuildActivation => request.require_shape(BASE | shape::GAMEPLAY_ROOT),
        Operation::AuthorizeActivationSignature => {
            request.require_shape(BASE | shape::SIGHASH | shape::GAMEPLAY_ROOT | shape::ACTIVATION)
        }
        Operation::SealActivationSignature => request.require_shape(
            BASE | shape::SIGHASH
                | shape::GAMEPLAY_ROOT
                | shape::ACTIVATION
                | shape::CANDIDATE_SIGNATURE,
        ),
        Operation::AssembleActivation => request.require_shape(
            BASE | REFUND_PROTECTION
                | shape::GAMEPLAY_ROOT
                | shape::ACTIVATION
                | shape::LOCAL_SIGNATURE
                | shape::PEER_SIGNATURE,
        ),
        Operation::AuthorizeFundingSignature => request
            .require_shape(BASE | REFUND_PROTECTION | shape::SIGHASH)
            .or_else(|_| {
                request.require_shape(
                    BASE | REFUND_PROTECTION | ACTIVATION_PROTECTION | shape::SIGHASH,
                )
            }),
        Operation::SealFundingSignature => request
            .require_shape(BASE | REFUND_PROTECTION | shape::SIGHASH | shape::CANDIDATE_SIGNATURE)
            .or_else(|_| {
                request.require_shape(
                    BASE | REFUND_PROTECTION
                        | ACTIVATION_PROTECTION
                        | shape::SIGHASH
                        | shape::CANDIDATE_SIGNATURE,
                )
            }),
        Operation::AssembleFunding => request
            .require_shape(
                BASE | REFUND_PROTECTION | shape::LOCAL_SIGNATURE | shape::PEER_SIGNATURE,
            )
            .or_else(|_| {
                request.require_shape(
                    BASE | REFUND_PROTECTION
                        | ACTIVATION_PROTECTION
                        | shape::LOCAL_SIGNATURE
                        | shape::PEER_SIGNATURE,
                )
            }),
    }
}

impl OriginEngine {
    fn new(request: &OriginCommandInput) -> Result<Self, String> {
        if request.version != ABI_VERSION {
            return Err("unsupported origin request version".to_owned());
        }
        validate_protocol_profile(request)?;
        let network_id = decode_hex_array(&request.network_id, "networkId")?;
        let room_id = decode_hex_array(&request.room_id, "roomId")?;
        let session_nonce = decode_hex_array(&request.session_nonce, "sessionNonce")?;
        let context = FundingContext::new(network_id, room_id, session_nonce)
            .map_err(|error| format!("invalid origin context: {error}"))?;

        let local_frame: StagingArtifactDto = decode_artifact(
            required(
                request.local_staging_funding.as_ref(),
                "localStagingFunding",
            )?,
            "localStagingFunding",
        )?;
        let peer_frame: StagingArtifactDto = decode_artifact(
            required(request.peer_staging_funding.as_ref(), "peerStagingFunding")?,
            "peerStagingFunding",
        )?;
        let local = validate_staging(
            &local_frame,
            request,
            request.transport_role,
            "localStagingFunding",
        )?;
        let peer = validate_staging(
            &peer_frame,
            request,
            request.transport_role.opposite(),
            "peerStagingFunding",
        )?;
        let participants_by_seat = if request.transport_role == TransportRole::Alice {
            [local.participant_id(), peer.participant_id()]
        } else {
            [peer.participant_id(), local.participant_id()]
        };
        let package = EscrowFundingPackage::new(context, local, peer)
            .map_err(|error| format!("invalid origin package: {error}"))?;
        Ok(Self {
            package,
            participants_by_seat,
            local_staging: local_frame,
            peer_staging: peer_frame,
            local_role: request.transport_role,
            network_id,
            room_id,
            session_nonce,
        })
    }

    fn local_input_index(&self) -> Result<u8, String> {
        self.input_index(self.local_role)
    }

    fn input_index(&self, role: TransportRole) -> Result<u8, String> {
        let index = self
            .package
            .participant_index(self.participants_by_seat[role.seat()])
            .ok_or_else(|| "transport participant is absent from the origin package".to_owned())?;
        u8::try_from(index).map_err(|_| "origin input index exceeds the u8 range".to_owned())
    }

    fn package_result(&self) -> Result<PackageResultDto, String> {
        let funding = self.package.funding_sighashes();
        let artifact = self.package_artifact(self.local_role);
        Ok(PackageResultDto {
            package_frame: encode_artifact(&artifact)?,
            peer_package_frame: encode_artifact(
                &self.package_artifact(self.local_role.opposite()),
            )?,
            local_staging: (&self.local_staging).into(),
            peer_staging: (&self.peer_staging).into(),
            package_id: encode_hex(&self.package.package_id()),
            funding_txid: display_txid(self.package.funding_txid()),
            refund_txid: display_txid(self.package.refund_txid()),
            origin_vout: self.package.origin_outpoint().vout(),
            origin_value_sat: ORIGIN_VALUE_SAT,
            origin_witness_script_hex: encode_hex(self.package.origin_witness_script()),
            origin_script_pubkey_hex: encode_hex(&self.package.origin_script_pubkey()),
            funding_sighashes_hex: [encode_hex(&funding[0]), encode_hex(&funding[1])],
            refund_sighash_hex: encode_hex(&self.package.refund_sighash()),
            local_input_index: self.local_input_index()?,
        })
    }

    fn validate_package_request(&self, request: &OriginCommandInput) -> Result<(), String> {
        let local: PackageArtifactDto = decode_artifact(
            required(request.package_frame.as_ref(), "packageFrame")?,
            "packageFrame",
        )?;
        let peer: PackageArtifactDto = decode_artifact(
            required(request.peer_package_frame.as_ref(), "peerPackageFrame")?,
            "peerPackageFrame",
        )?;
        self.validate_package_frame(&local, self.local_role)?;
        self.validate_package_frame(&peer, self.local_role.opposite())?;
        let supplied_index = *required(request.local_input_index.as_ref(), "localInputIndex")?;
        if supplied_index != self.local_input_index()? {
            return Err(
                "localInputIndex is not the local participant's canonical input".to_owned(),
            );
        }
        Ok(())
    }

    fn package_artifact(&self, role: TransportRole) -> PackageArtifactDto {
        PackageArtifactDto {
            version: ABI_VERSION,
            protocol_profile_code: AUDITED_PROTOCOL_PROFILE_CODE,
            network_id: encode_hex(&self.network_id),
            room_id: encode_hex(&self.room_id),
            session_nonce: encode_hex(&self.session_nonce),
            transport_role: role,
            package_id: encode_hex(&self.package.package_id()),
            funding_txid: display_txid(self.package.funding_txid()),
            refund_txid: display_txid(self.package.refund_txid()),
            origin_vout: self.package.origin_outpoint().vout(),
        }
    }

    fn validate_package_frame(
        &self,
        frame: &PackageArtifactDto,
        expected_role: TransportRole,
    ) -> Result<(), String> {
        if frame.version != ABI_VERSION
            || frame.protocol_profile_code != AUDITED_PROTOCOL_PROFILE_CODE
            || frame.transport_role != expected_role
            || decode_hex_array::<32>(&frame.network_id, "packageFrame.networkId")?
                != self.network_id
            || decode_hex_array::<32>(&frame.room_id, "packageFrame.roomId")? != self.room_id
            || decode_hex_array::<32>(&frame.session_nonce, "packageFrame.sessionNonce")?
                != self.session_nonce
            || decode_hex_array::<32>(&frame.package_id, "packageFrame.packageId")?
                != self.package.package_id()
            || frame.funding_txid != display_txid(self.package.funding_txid())
            || frame.refund_txid != display_txid(self.package.refund_txid())
            || frame.origin_vout != self.package.origin_outpoint().vout()
        {
            return Err("packageFrame is not the canonical local origin package".to_owned());
        }
        Ok(())
    }

    fn signature_share(
        &self,
        encoded_frame: &str,
        expected_role: TransportRole,
        target: SignatureTarget<'_>,
    ) -> Result<SignatureShare, String> {
        let frame: SignatureFrameDto = decode_artifact(encoded_frame, "signature frame")?;
        let expected_digest = match target {
            SignatureTarget::Refund => self.package.refund_sighash(),
            SignatureTarget::Funding => {
                self.package.funding_sighashes()[usize::from(self.input_index(expected_role)?)]
            }
            SignatureTarget::Activation(activation) => activation.sighash(),
        };
        let expected_index = match target {
            SignatureTarget::Funding => Some(self.input_index(expected_role)?),
            SignatureTarget::Refund | SignatureTarget::Activation(_) => None,
        };
        if frame.version != ABI_VERSION
            || frame.protocol_profile_code != AUDITED_PROTOCOL_PROFILE_CODE
            || frame.transport_role != expected_role
            || decode_hex_array::<32>(&frame.network_id, "signature.networkId")? != self.network_id
            || decode_hex_array::<32>(&frame.room_id, "signature.roomId")? != self.room_id
            || decode_hex_array::<32>(&frame.session_nonce, "signature.sessionNonce")?
                != self.session_nonce
            || decode_hex_array::<32>(&frame.package_id, "signature.packageId")?
                != self.package.package_id()
            || frame.input_index != expected_index
            || frame.sighash_type != 1
            || decode_hex_array::<32>(&frame.sighash_hex, "signature.sighashHex")?
                != expected_digest
        {
            return Err(
                "origin signature frame is not canonically bound to its signer and digest"
                    .to_owned(),
            );
        }
        let signature_bytes = decode_hex_array::<64>(
            &frame.compact_low_s_signature_hex,
            "signature.compactLowSSignatureHex",
        )?;
        let signature = CompactSignature::new(signature_bytes)
            .map_err(|error| format!("invalid compact low-S signature: {error}"))?;
        Ok(SignatureShare::new(
            self.participants_by_seat[expected_role.seat()],
            signature,
        ))
    }

    fn seal_signature(
        &self,
        request: &OriginCommandInput,
        target: SignatureTarget<'_>,
    ) -> Result<SignatureResultDto, String> {
        let digest = match target {
            SignatureTarget::Refund => self.package.refund_sighash(),
            SignatureTarget::Funding => {
                self.package.funding_sighashes()[usize::from(self.local_input_index()?)]
            }
            SignatureTarget::Activation(activation) => activation.sighash(),
        };
        let expected = encode_hex(&digest);
        require_equal(
            required(request.sighash_hex.as_ref(), "sighashHex")?,
            &expected,
            "signing digest",
        )?;
        let frame = SignatureFrameDto {
            version: ABI_VERSION,
            protocol_profile_code: AUDITED_PROTOCOL_PROFILE_CODE,
            network_id: encode_hex(&self.network_id),
            room_id: encode_hex(&self.room_id),
            session_nonce: encode_hex(&self.session_nonce),
            transport_role: self.local_role,
            package_id: encode_hex(&self.package.package_id()),
            input_index: match target {
                SignatureTarget::Funding => Some(self.local_input_index()?),
                SignatureTarget::Refund | SignatureTarget::Activation(_) => None,
            },
            sighash_type: 1,
            sighash_hex: expected,
            compact_low_s_signature_hex: required(
                request.candidate_signature_hex.as_ref(),
                "candidateSignatureHex",
            )?
            .clone(),
        };
        let encoded = encode_artifact(&frame)?;
        let share = self.signature_share(&encoded, self.local_role, target)?;
        match target {
            SignatureTarget::Refund => self.package.verify_refund_signature(share),
            SignatureTarget::Funding => self.package.verify_funding_signature(share),
            SignatureTarget::Activation(activation) => activation.verify_signature(share),
        }
        .map_err(|error| format!("wallet signature verification failed: {error}"))?;
        Ok(SignatureResultDto {
            signature_frame: encoded,
        })
    }

    fn shares(
        &self,
        request: &OriginCommandInput,
        target: SignatureTarget<'_>,
    ) -> Result<[SignatureShare; 2], String> {
        let local = required(request.local_signature.as_ref(), "localSignature")?;
        let peer = required(request.peer_signature.as_ref(), "peerSignature")?;
        Ok([
            self.signature_share(local, self.local_role, target)?,
            self.signature_share(peer, self.local_role.opposite(), target)?,
        ])
    }

    fn refund_shares(&self, request: &OriginCommandInput) -> Result<[SignatureShare; 2], String> {
        let local = required(
            request.local_refund_signature.as_ref(),
            "localRefundSignature",
        )?;
        let peer = required(
            request.peer_refund_signature.as_ref(),
            "peerRefundSignature",
        )?;
        Ok([
            self.signature_share(local, self.local_role, SignatureTarget::Refund)?,
            self.signature_share(peer, self.local_role.opposite(), SignatureTarget::Refund)?,
        ])
    }

    fn activation_shares(
        &self,
        request: &OriginCommandInput,
        activation: &ActivationPackage,
    ) -> Result<[SignatureShare; 2], String> {
        let local = required(
            request.local_activation_signature.as_ref(),
            "localActivationSignature",
        )?;
        let peer = required(
            request.peer_activation_signature.as_ref(),
            "peerActivationSignature",
        )?;
        Ok([
            self.signature_share(
                local,
                self.local_role,
                SignatureTarget::Activation(activation),
            )?,
            self.signature_share(
                peer,
                self.local_role.opposite(),
                SignatureTarget::Activation(activation),
            )?,
        ])
    }

    fn assemble_refund(&self, request: &OriginCommandInput) -> Result<Vec<u8>, String> {
        self.package
            .assemble_signed_refund(self.shares(request, SignatureTarget::Refund)?)
            .map(poker_funding::SignedTransaction::into_consensus_bytes)
            .map_err(|error| format!("refund signature verification failed: {error}"))
    }

    fn validate_durable_refund(&self, request: &OriginCommandInput) -> Result<(), String> {
        let expected = self
            .package
            .assemble_signed_refund(self.refund_shares(request)?)
            .map_err(|error| format!("refund signature verification failed: {error}"))?
            .into_consensus_bytes();
        require_equal(
            required(request.signed_refund_tx_hex.as_ref(), "signedRefundTxHex")?,
            &encode_hex(&expected),
            "durable signed refund",
        )
    }

    fn activation(
        &self,
        request: &OriginCommandInput,
        require_frame: bool,
    ) -> Result<ActivationPackage, String> {
        let root = decode_hex_array::<34>(
            required(
                request.gameplay_root_script_pub_key_hex.as_ref(),
                "gameplayRootScriptPubKeyHex",
            )?,
            "gameplayRootScriptPubKeyHex",
        )?;
        let activation = self
            .package
            .activation(root)
            .map_err(|error| format!("invalid gameplay activation: {error}"))?;
        if require_frame {
            let frame: ActivationArtifactDto = decode_artifact(
                required(request.activation_frame.as_ref(), "activationFrame")?,
                "activationFrame",
            )?;
            self.validate_activation_frame(&frame, &activation)?;
        }
        Ok(activation)
    }

    fn activation_artifact(&self, activation: &ActivationPackage) -> ActivationArtifactDto {
        ActivationArtifactDto {
            version: ABI_VERSION,
            protocol_profile_code: AUDITED_PROTOCOL_PROFILE_CODE,
            network_id: encode_hex(&self.network_id),
            room_id: encode_hex(&self.room_id),
            session_nonce: encode_hex(&self.session_nonce),
            package_id: encode_hex(&self.package.package_id()),
            activation_id: encode_hex(&activation.activation_id()),
            activation_txid: display_txid(activation.txid()),
            gameplay_root_script_pub_key_hex: encode_hex(&activation.gameplay_root_script_pubkey()),
            unsigned_tx_hex: encode_hex(activation.unsigned_transaction_bytes()),
        }
    }

    fn activation_result(
        &self,
        activation: &ActivationPackage,
    ) -> Result<ActivationResultDto, String> {
        Ok(ActivationResultDto {
            activation_frame: encode_artifact(&self.activation_artifact(activation))?,
            activation_id: encode_hex(&activation.activation_id()),
            activation_txid: display_txid(activation.txid()),
            activation_sighash_hex: encode_hex(&activation.sighash()),
            unsigned_tx_hex: encode_hex(activation.unsigned_transaction_bytes()),
        })
    }

    fn validate_activation_frame(
        &self,
        frame: &ActivationArtifactDto,
        activation: &ActivationPackage,
    ) -> Result<(), String> {
        if frame.version != ABI_VERSION
            || frame.protocol_profile_code != AUDITED_PROTOCOL_PROFILE_CODE
            || decode_hex_array::<32>(&frame.network_id, "activationFrame.networkId")?
                != self.network_id
            || decode_hex_array::<32>(&frame.room_id, "activationFrame.roomId")? != self.room_id
            || decode_hex_array::<32>(&frame.session_nonce, "activationFrame.sessionNonce")?
                != self.session_nonce
            || decode_hex_array::<32>(&frame.package_id, "activationFrame.packageId")?
                != self.package.package_id()
            || decode_hex_array::<32>(&frame.activation_id, "activationFrame.activationId")?
                != activation.activation_id()
            || frame.activation_txid != display_txid(activation.txid())
            || frame.gameplay_root_script_pub_key_hex
                != encode_hex(&activation.gameplay_root_script_pubkey())
            || frame.unsigned_tx_hex != encode_hex(activation.unsigned_transaction_bytes())
        {
            return Err("activationFrame is not the canonical root-bound activation".to_owned());
        }
        Ok(())
    }

    fn assemble_activation(
        &self,
        request: &OriginCommandInput,
        activation: &ActivationPackage,
    ) -> Result<Vec<u8>, String> {
        activation
            .assemble_signed(self.shares(request, SignatureTarget::Activation(activation))?)
            .map(poker_funding::SignedTransaction::into_consensus_bytes)
            .map_err(|error| format!("activation signature verification failed: {error}"))
    }

    fn validate_optional_durable_activation(
        &self,
        request: &OriginCommandInput,
    ) -> Result<(), String> {
        if request.activation_frame.is_none() {
            return Ok(());
        }
        let activation = self.activation(request, true)?;
        let expected = activation
            .assemble_signed(self.activation_shares(request, &activation)?)
            .map_err(|error| format!("activation signature verification failed: {error}"))?
            .into_consensus_bytes();
        require_equal(
            required(
                request.signed_activation_tx_hex.as_ref(),
                "signedActivationTxHex",
            )?,
            &encode_hex(&expected),
            "durable signed activation",
        )
    }

    fn assemble_funding(&self, request: &OriginCommandInput) -> Result<Vec<u8>, String> {
        self.package
            .assemble_signed_funding(self.shares(request, SignatureTarget::Funding)?)
            .map(poker_funding::SignedTransaction::into_consensus_bytes)
            .map_err(|error| format!("funding signature verification failed: {error}"))
    }
}

fn validate_protocol_profile(request: &OriginCommandInput) -> Result<(), String> {
    if request.protocol_profile_code != AUDITED_PROTOCOL_PROFILE_CODE
        || ORIGIN_VALUE_SAT.checked_sub(ACTIVATION_FEE_SAT) != Some(GAMEPLAY_ROOT_VALUE_SAT)
    {
        return Err("unsupported audited origin protocol profile".to_owned());
    }
    Ok(())
}

fn build_staging_result(request: &OriginCommandInput) -> Result<StagingResultDto, String> {
    if request.version != ABI_VERSION {
        return Err("unsupported origin request version".to_owned());
    }
    validate_protocol_profile(request)?;
    let network_id = decode_hex_array(&request.network_id, "networkId")?;
    let room_id = decode_hex_array(&request.room_id, "roomId")?;
    let session_nonce = decode_hex_array(&request.session_nonce, "sessionNonce")?;
    FundingContext::new(network_id, room_id, session_nonce)
        .map_err(|error| format!("invalid origin context: {error}"))?;
    let control = required(request.staging_funding.as_ref(), "stagingFunding")?;
    let artifact = StagingArtifactDto {
        version: ABI_VERSION,
        protocol_profile_code: AUDITED_PROTOCOL_PROFILE_CODE,
        network_id: request.network_id.clone(),
        room_id: request.room_id.clone(),
        session_nonce: request.session_nonce.clone(),
        transport_role: request.transport_role,
        txid: control.txid.clone(),
        vout: control.vout,
        value_sat: control.value_sat,
        witness_script_hex: control.witness_script_hex.clone(),
        script_pub_key_hex: control.script_pub_key_hex.clone(),
    };
    validate_staging(&artifact, request, request.transport_role, "stagingFunding")?;
    Ok(StagingResultDto {
        staging_frame: encode_artifact(&artifact)?,
    })
}

fn validate_staging(
    frame: &StagingArtifactDto,
    request: &OriginCommandInput,
    expected_role: TransportRole,
    label: &str,
) -> Result<PlayerFundingInput, String> {
    if frame.version != ABI_VERSION
        || frame.protocol_profile_code != AUDITED_PROTOCOL_PROFILE_CODE
        || frame.transport_role != expected_role
        || frame.network_id != request.network_id
        || frame.room_id != request.room_id
        || frame.session_nonce != request.session_nonce
    {
        return Err(format!("{label} is bound to the wrong origin context"));
    }
    if frame.value_sat != CONTRIBUTION_SAT {
        return Err(format!(
            "{label}.valueSat does not match the audited contribution"
        ));
    }
    let display_txid = decode_hex_array(&frame.txid, &format!("{label}.txid"))?;
    let witness = decode_hex_array::<35>(
        &frame.witness_script_hex,
        &format!("{label}.witnessScriptHex"),
    )?;
    if witness[0] != 33 || witness[34] != 0xac {
        return Err(format!(
            "{label}.witnessScriptHex is not a canonical staging CHECKSIG script"
        ));
    }
    let mut public_key = [0_u8; 33];
    public_key.copy_from_slice(&witness[1..34]);
    let staging = PlayerFundingInput::from_display_txid_bytes(
        display_txid,
        frame.vout,
        frame.value_sat,
        public_key,
        poker_funding::FundingTerms::diagnostic(),
    )
    .map_err(|error| format!("invalid {label}: {error}"))?;
    if staging.staging_witness_script() != witness
        || decode_hex_array::<34>(
            &frame.script_pub_key_hex,
            &format!("{label}.scriptPubKeyHex"),
        )? != staging.staging_script_pubkey()
    {
        return Err(format!("{label} contains inconsistent script artifacts"));
    }
    Ok(staging)
}

fn display_txid(txid: poker_funding::DisplayTxid) -> String {
    encode_hex(&txid.to_display_bytes())
}

fn required<'a, T>(value: Option<&'a T>, label: &str) -> Result<&'a T, String> {
    value.ok_or_else(|| format!("origin operation requires {label}"))
}

fn require_equal(actual: &str, expected: &str, label: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} does not match the independently rebuilt artifact"
        ))
    }
}

fn encode_artifact<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("could not serialize canonical origin artifact: {error}"))?;
    if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES {
        return Err("canonical origin artifact exceeds its fixed bound".to_owned());
    }
    Ok(STANDARD.encode(bytes))
}

fn decode_artifact<T: DeserializeOwned + Serialize>(
    encoded: &str,
    label: &str,
) -> Result<T, String> {
    if encoded.is_empty() || encoded.len() > MAX_ARTIFACT_BYTES.saturating_mul(2) {
        return Err(format!("{label} exceeds its fixed encoded bound"));
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| format!("{label} is not canonical base64"))?;
    if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_BYTES || STANDARD.encode(&bytes) != encoded {
        return Err(format!(
            "{label} is not a bounded canonical base64 artifact"
        ));
    }
    let value: T = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{label} has an invalid Serde schema: {error}"))?;
    let canonical = serde_json::to_vec(&value)
        .map_err(|error| format!("could not canonicalize {label}: {error}"))?;
    if canonical != bytes {
        return Err(format!("{label} is not canonically serialized"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use bitcoin::Transaction;
    use bitcoin::consensus::deserialize;
    use k256::{
        SecretKey,
        ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner},
        elliptic_curve::sec1::ToEncodedPoint,
    };
    use serde_json::{Value, from_slice, json};

    use super::*;
    use crate::dto::StagingFundingControlDto;

    fn key(secret_byte: u8) -> ([u8; 33], [u8; 32]) {
        let mut secret = [0_u8; 32];
        secret[31] = secret_byte;
        let parsed = SecretKey::from_slice(&secret).unwrap_or_else(|_| unreachable!());
        let encoded = parsed.public_key().to_encoded_point(true);
        let mut public = [0_u8; 33];
        public.copy_from_slice(encoded.as_bytes());
        (public, secret)
    }

    fn staging(role: TransportRole, byte: u8, context: (&str, &str, &str)) -> StagingArtifactDto {
        let (public, _) = key(byte);
        let input = PlayerFundingInput::from_display_txid_bytes(
            [byte.wrapping_add(0x40); 32],
            u32::from(byte),
            CONTRIBUTION_SAT,
            public,
            poker_funding::FundingTerms::diagnostic(),
        )
        .unwrap_or_else(|_| unreachable!());
        StagingArtifactDto {
            version: ABI_VERSION,
            protocol_profile_code: AUDITED_PROTOCOL_PROFILE_CODE,
            network_id: context.0.to_owned(),
            room_id: context.1.to_owned(),
            session_nonce: context.2.to_owned(),
            transport_role: role,
            txid: encode_hex(&[byte.wrapping_add(0x40); 32]),
            vout: u32::from(byte),
            value_sat: input.value_sat(),
            witness_script_hex: encode_hex(&input.staging_witness_script()),
            script_pub_key_hex: encode_hex(&input.staging_script_pubkey()),
        }
    }

    fn fixture(role: TransportRole) -> OriginCommandInput {
        let network = encode_hex(&[0x11; 32]);
        let room = encode_hex(&[0x22; 32]);
        let nonce = encode_hex(&[0x33; 32]);
        let context = (network.as_str(), room.as_str(), nonce.as_str());
        let alice = staging(TransportRole::Alice, 1, context);
        let bob = staging(TransportRole::Bob, 2, context);
        let (local, peer) = if role == TransportRole::Alice {
            (alice, bob)
        } else {
            (bob, alice)
        };
        OriginCommandInput {
            version: ABI_VERSION,
            protocol_profile_code: AUDITED_PROTOCOL_PROFILE_CODE,
            network_id: network,
            room_id: room,
            session_nonce: nonce,
            transport_role: role,
            staging_funding: None,
            local_staging_funding: Some(encode_artifact(&local).unwrap_or_else(|_| unreachable!())),
            peer_staging_funding: Some(encode_artifact(&peer).unwrap_or_else(|_| unreachable!())),
            package_frame: None,
            peer_package_frame: None,
            local_input_index: None,
            sighash_hex: None,
            local_signature: None,
            peer_signature: None,
            signed_refund_tx_hex: None,
            local_refund_signature: None,
            peer_refund_signature: None,
            gameplay_root_script_pub_key_hex: None,
            activation_frame: None,
            local_activation_signature: None,
            peer_activation_signature: None,
            signed_activation_tx_hex: None,
            candidate_signature_hex: None,
        }
    }

    fn engine(request: &OriginCommandInput) -> OriginEngine {
        OriginEngine::new(request).unwrap_or_else(|_| unreachable!())
    }

    fn attach_packages(request: &mut OriginCommandInput) {
        let built = engine(request);
        request.package_frame = Some(
            encode_artifact(&built.package_artifact(request.transport_role))
                .unwrap_or_else(|_| unreachable!()),
        );
        request.peer_package_frame = Some(
            encode_artifact(&built.package_artifact(request.transport_role.opposite()))
                .unwrap_or_else(|_| unreachable!()),
        );
        request.local_input_index =
            Some(built.local_input_index().unwrap_or_else(|_| unreachable!()));
    }

    fn sign(secret_byte: u8, digest: [u8; 32]) -> String {
        let (_, secret) = key(secret_byte);
        let signing = SigningKey::from_slice(&secret).unwrap_or_else(|_| unreachable!());
        let signature: Signature = signing
            .sign_prehash(&digest)
            .unwrap_or_else(|_| unreachable!());
        encode_hex(&signature.to_bytes())
    }

    fn signature_artifact(
        request: &OriginCommandInput,
        built: &OriginEngine,
        role: TransportRole,
        target: SignatureTarget<'_>,
    ) -> String {
        let (digest, input_index) = match target {
            SignatureTarget::Refund => (built.package.refund_sighash(), None),
            SignatureTarget::Funding => {
                let index = built.input_index(role).unwrap_or_else(|_| unreachable!());
                (
                    built.package.funding_sighashes()[usize::from(index)],
                    Some(index),
                )
            }
            SignatureTarget::Activation(activation) => (activation.sighash(), None),
        };
        let secret = if role == TransportRole::Alice { 1 } else { 2 };
        encode_artifact(&SignatureFrameDto {
            version: ABI_VERSION,
            protocol_profile_code: AUDITED_PROTOCOL_PROFILE_CODE,
            network_id: request.network_id.clone(),
            room_id: request.room_id.clone(),
            session_nonce: request.session_nonce.clone(),
            transport_role: role,
            package_id: encode_hex(&built.package.package_id()),
            input_index,
            sighash_type: 1,
            sighash_hex: encode_hex(&digest),
            compact_low_s_signature_hex: sign(secret, digest),
        })
        .unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn nonce_controls_are_strict_and_match_the_domain_vectors() {
        let commitment_request = NonceCommitmentControlDto {
            version: ABI_VERSION,
            room_id: encode_hex(&[0x11; 32]),
            transport_role: TransportRole::Alice,
            nonce_share: encode_hex(&[0x22; 32]),
        };
        let commitment: Value =
            from_slice(&nonce_commitment(&commitment_request).unwrap_or_else(|_| unreachable!()))
                .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            commitment,
            json!({
                "commitment":
                    "5b766e9ead7ed7172f61dc3ac12beee824cc892cf7e0f3229776b3ec83c03d20"
            }),
        );

        let nonce_request = SessionNonceControlDto {
            version: ABI_VERSION,
            room_id: encode_hex(&[0x11; 32]),
            alice_share: encode_hex(&[0x22; 32]),
            bob_share: encode_hex(&[0x33; 32]),
        };
        let nonce: Value =
            from_slice(&session_nonce(&nonce_request).unwrap_or_else(|_| unreachable!()))
                .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            nonce,
            json!({
                "sessionNonce":
                    "4c2910d24a30bdc8eecd041b277ef4396bbf478ee4ce52c7303e3e191b3bbef4"
            }),
        );

        assert!(
            serde_json::from_value::<NonceCommitmentControlDto>(json!({
                "version": ABI_VERSION,
                "roomId": encode_hex(&[0x11; 32]),
                "transportRole": "alice",
                "nonceShare": encode_hex(&[0x22; 32]),
                "obsolete": true,
            }))
            .is_err(),
        );
        assert!(
            session_nonce(&SessionNonceControlDto {
                version: ABI_VERSION,
                room_id: encode_hex(&[0x11; 32]),
                alice_share: encode_hex(&[0; 32]),
                bob_share: encode_hex(&[0x33; 32]),
            })
            .is_err()
        );
    }

    fn attach_refund(request: &mut OriginCommandInput) -> Vec<u8> {
        let built = engine(request);
        request.local_refund_signature = Some(signature_artifact(
            request,
            &built,
            request.transport_role,
            SignatureTarget::Refund,
        ));
        request.peer_refund_signature = Some(signature_artifact(
            request,
            &built,
            request.transport_role.opposite(),
            SignatureTarget::Refund,
        ));
        let signed = built
            .package
            .assemble_signed_refund(
                built
                    .refund_shares(request)
                    .unwrap_or_else(|_| unreachable!()),
            )
            .unwrap_or_else(|_| unreachable!())
            .into_consensus_bytes();
        request.signed_refund_tx_hex = Some(encode_hex(&signed));
        signed
    }

    #[test]
    fn serde_package_build_is_seat_invariant_and_emits_opaque_frames() {
        let alice = fixture(TransportRole::Alice);
        let bob = fixture(TransportRole::Bob);
        let alice_json =
            execute(Operation::BuildPackage, &alice).unwrap_or_else(|_| unreachable!());
        let bob_json = execute(Operation::BuildPackage, &bob).unwrap_or_else(|_| unreachable!());
        let alice_value: Value = from_slice(&alice_json).unwrap_or_else(|_| unreachable!());
        let bob_value: Value = from_slice(&bob_json).unwrap_or_else(|_| unreachable!());
        for key in [
            "packageId",
            "fundingTxid",
            "refundTxid",
            "originWitnessScriptHex",
            "originScriptPubkeyHex",
            "fundingSighashesHex",
            "refundSighashHex",
        ] {
            assert_eq!(alice_value[key], bob_value[key]);
        }
        assert_ne!(alice_value["localInputIndex"], bob_value["localInputIndex"]);
        let alice_frame: PackageArtifactDto = decode_artifact(
            alice_value["packageFrame"].as_str().unwrap_or(""),
            "packageFrame",
        )
        .unwrap_or_else(|_| unreachable!());
        let bob_frame: PackageArtifactDto = decode_artifact(
            bob_value["packageFrame"].as_str().unwrap_or(""),
            "packageFrame",
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(alice_value["peerPackageFrame"], bob_value["packageFrame"]);
        assert_eq!(bob_value["peerPackageFrame"], alice_value["packageFrame"]);
        assert_eq!(alice_frame.transport_role, TransportRole::Alice);
        assert_eq!(bob_frame.transport_role, TransportRole::Bob);
        assert_eq!(alice_frame.package_id, bob_frame.package_id);
    }

    #[test]
    fn staging_control_is_validated_and_sealed_before_relay() {
        let mut request = fixture(TransportRole::Alice);
        let local: StagingArtifactDto = decode_artifact(
            request.local_staging_funding.as_deref().unwrap_or(""),
            "fixture staging",
        )
        .unwrap_or_else(|_| unreachable!());
        request.local_staging_funding = None;
        request.peer_staging_funding = None;
        request.staging_funding = Some(StagingFundingControlDto {
            txid: local.txid.clone(),
            vout: local.vout,
            value_sat: local.value_sat,
            witness_script_hex: local.witness_script_hex.clone(),
            script_pub_key_hex: local.script_pub_key_hex.clone(),
        });
        let encoded =
            execute(Operation::BuildStagingFrame, &request).unwrap_or_else(|_| unreachable!());
        let result: Value = from_slice(&encoded).unwrap_or_else(|_| unreachable!());
        let sealed: StagingArtifactDto = decode_artifact(
            result["stagingFrame"].as_str().unwrap_or(""),
            "stagingFrame",
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(sealed, local);

        request
            .staging_funding
            .as_mut()
            .unwrap_or_else(|| unreachable!())
            .script_pub_key_hex = encode_hex(&[0x22; 34]);
        assert!(execute(Operation::BuildStagingFrame, &request).is_err());

        request
            .staging_funding
            .as_mut()
            .unwrap_or_else(|| unreachable!())
            .script_pub_key_hex = local.script_pub_key_hex;
        request
            .staging_funding
            .as_mut()
            .unwrap_or_else(|| unreachable!())
            .value_sat += 1;
        assert!(execute(Operation::BuildStagingFrame, &request).is_err());
    }

    #[test]
    fn serde_and_artifact_decoders_fail_closed() {
        let request = fixture(TransportRole::Alice);
        let mut value = serde_json::to_value(&request).unwrap_or_else(|_| unreachable!());
        value
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .insert("legacyRoom".to_owned(), json!(true));
        assert!(serde_json::from_value::<OriginCommandInput>(value).is_err());

        let mut wrong_profile = request.clone();
        wrong_profile.protocol_profile_code = 0;
        assert!(OriginEngine::new(&wrong_profile).is_err());

        let artifact = engine(&request).package_artifact(TransportRole::Alice);
        let mut artifact_value = serde_json::to_value(&artifact).unwrap_or_else(|_| unreachable!());
        artifact_value
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .insert("legacy".to_owned(), json!(0));
        let malformed =
            STANDARD.encode(serde_json::to_vec(&artifact_value).unwrap_or_else(|_| unreachable!()));
        assert!(decode_artifact::<PackageArtifactDto>(&malformed, "packageFrame").is_err());

        let noncanonical = STANDARD.encode(
            format!(
                " {}",
                serde_json::to_string(&artifact).unwrap_or_else(|_| unreachable!())
            )
            .as_bytes(),
        );
        assert!(decode_artifact::<PackageArtifactDto>(&noncanonical, "packageFrame").is_err());
    }

    #[test]
    fn package_and_signature_cross_binding_is_rejected() {
        let mut request = fixture(TransportRole::Alice);
        attach_packages(&mut request);
        let built = engine(&request);
        let mut peer: PackageArtifactDto = decode_artifact(
            request.peer_package_frame.as_deref().unwrap_or(""),
            "peerPackageFrame",
        )
        .unwrap_or_else(|_| unreachable!());
        peer.room_id = encode_hex(&[0x99; 32]);
        request.peer_package_frame =
            Some(encode_artifact(&peer).unwrap_or_else(|_| unreachable!()));
        assert!(built.validate_package_request(&request).is_err());

        attach_packages(&mut request);
        request.local_signature = Some(signature_artifact(
            &request,
            &built,
            TransportRole::Alice,
            SignatureTarget::Refund,
        ));
        request.peer_signature = Some(signature_artifact(
            &request,
            &built,
            TransportRole::Alice,
            SignatureTarget::Refund,
        ));
        assert!(execute(Operation::AssembleRefund, &request).is_err());
    }

    #[test]
    fn refund_and_funding_flow_revalidates_durable_protection() {
        let mut request = fixture(TransportRole::Alice);
        attach_packages(&mut request);
        let built = engine(&request);
        request.local_signature = Some(signature_artifact(
            &request,
            &built,
            TransportRole::Alice,
            SignatureTarget::Refund,
        ));
        request.peer_signature = Some(signature_artifact(
            &request,
            &built,
            TransportRole::Bob,
            SignatureTarget::Refund,
        ));
        let encoded =
            execute(Operation::AssembleRefund, &request).unwrap_or_else(|_| unreachable!());
        let result: Value = from_slice(&encoded).unwrap_or_else(|_| unreachable!());
        let raw = decode_variable_hex(result["signedTxHex"].as_str().unwrap_or(""));
        let transaction: Transaction = deserialize(&raw).unwrap_or_else(|_| unreachable!());
        assert_eq!(transaction.input.len(), 1);
        assert_eq!(transaction.input[0].witness.len(), 3);

        request.local_signature = None;
        request.peer_signature = None;
        attach_refund(&mut request);
        request.sighash_hex = Some(encode_hex(
            &built.package.funding_sighashes()
                [usize::from(built.local_input_index().unwrap_or_else(|_| unreachable!()))],
        ));
        assert!(execute(Operation::AuthorizeFundingSignature, &request).is_ok());
        request.signed_refund_tx_hex = Some(encode_hex(&[0x55; 32]));
        assert!(execute(Operation::AuthorizeFundingSignature, &request).is_err());
        request.signed_refund_tx_hex = Some(encode_hex(&raw));
        request.sighash_hex = None;
        request.local_signature = Some(signature_artifact(
            &request,
            &built,
            TransportRole::Alice,
            SignatureTarget::Funding,
        ));
        request.peer_signature = Some(signature_artifact(
            &request,
            &built,
            TransportRole::Bob,
            SignatureTarget::Funding,
        ));
        let encoded =
            execute(Operation::AssembleFunding, &request).unwrap_or_else(|_| unreachable!());
        let result: Value = from_slice(&encoded).unwrap_or_else(|_| unreachable!());
        let funding: Transaction = deserialize(&decode_variable_hex(
            result["signedTxHex"].as_str().unwrap_or(""),
        ))
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(funding.input.len(), 2);
        assert!(funding.input.iter().all(|input| input.witness.len() == 2));
    }

    #[test]
    fn activation_artifact_and_signature_are_root_bound() {
        let mut request = fixture(TransportRole::Alice);
        attach_packages(&mut request);
        let built = engine(&request);
        let mut root = [0x77; 34];
        root[0] = 0x51;
        root[1] = 0x20;
        request.gameplay_root_script_pub_key_hex = Some(encode_hex(&root));
        let result =
            execute(Operation::BuildActivation, &request).unwrap_or_else(|_| unreachable!());
        let value: Value = from_slice(&result).unwrap_or_else(|_| unreachable!());
        request.activation_frame = Some(value["activationFrame"].as_str().unwrap_or("").to_owned());
        let activation = built
            .package
            .activation(root)
            .unwrap_or_else(|_| unreachable!());
        request.sighash_hex = Some(encode_hex(&activation.sighash()));
        request.candidate_signature_hex = Some(sign(1, activation.sighash()));
        let sealed = execute(Operation::SealActivationSignature, &request)
            .unwrap_or_else(|_| unreachable!());
        let sealed: Value = from_slice(&sealed).unwrap_or_else(|_| unreachable!());
        let frame: SignatureFrameDto = decode_artifact(
            sealed["signatureFrame"].as_str().unwrap_or(""),
            "signatureFrame",
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(frame.sighash_hex, encode_hex(&activation.sighash()));

        let mut crossed = request;
        let mut wrong_root = root;
        wrong_root[2] ^= 1;
        crossed.gameplay_root_script_pub_key_hex = Some(encode_hex(&wrong_root));
        assert!(execute(Operation::SealActivationSignature, &crossed).is_err());
    }

    fn decode_variable_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap_or_else(|_| unreachable!());
                u8::from_str_radix(text, 16).unwrap_or_else(|_| unreachable!())
            })
            .collect()
    }
}
