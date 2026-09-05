use crate::diagnostic::*;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Amount, ScriptBuf, Transaction};
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};

use super::{
    CompactSignature, DisplayTxid, EscrowFundingPackage, FundingContext, FundingError,
    MAX_MONEY_SAT, MAX_SIGNED_FUNDING_VBYTES, MAX_SIGNED_REFUND_VBYTES, NonceSeat, OutPoint,
    ParticipantId, PlayerFundingInput, SignatureShare, commit_session_nonce_share,
    derive_session_nonce,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn signing_key(byte: u8) -> Result<SigningKey, FundingError> {
    SigningKey::from_slice(&[byte; 32]).map_err(|_| FundingError::ConstructionInvariant)
}

fn public(key: &SigningKey) -> [u8; 33] {
    let encoded = key.verifying_key().to_encoded_point(true);
    let mut public_key = [0_u8; 33];
    public_key.copy_from_slice(encoded.as_bytes());
    public_key
}

fn context(nonce: u8) -> Result<FundingContext, FundingError> {
    FundingContext::new([0x51; 32], [0x52; 32], [nonce; 32])
}

fn staging(
    txid_byte: u8,
    vout: u32,
    value_sat: u64,
    key: &SigningKey,
) -> Result<PlayerFundingInput, FundingError> {
    PlayerFundingInput::new(
        OutPoint::new(DisplayTxid::from_display_bytes([txid_byte; 32]), vout),
        value_sat,
        public(key),
        crate::FundingTerms::diagnostic(),
    )
}

fn fixture() -> Result<(EscrowFundingPackage, SigningKey, SigningKey), Box<dyn std::error::Error>> {
    let first_key = signing_key(1)?;
    let second_key = signing_key(2)?;
    let package = EscrowFundingPackage::new(
        context(0x53)?,
        staging(0x11, 1, 500_000, &first_key)?,
        staging(0x22, 2, CONTRIBUTION_SAT, &second_key)?,
    )?;
    Ok((package, first_key, second_key))
}

fn sign(key: &SigningKey, digest: [u8; 32]) -> Result<SignatureShare, FundingError> {
    let signature: Signature = key
        .sign_prehash(&digest)
        .map_err(|_| FundingError::InvalidSignature)?;
    Ok(SignatureShare::new(
        ParticipantId::from_compressed_public_key(public(key))?,
        CompactSignature::new(signature.to_bytes().into())?,
    ))
}

fn package_shares(
    package: &EscrowFundingPackage,
    first_key: &SigningKey,
    second_key: &SigningKey,
    refund: bool,
) -> Result<[SignatureShare; 2], FundingError> {
    let first_id = ParticipantId::from_compressed_public_key(public(first_key))?;
    let second_id = ParticipantId::from_compressed_public_key(public(second_key))?;
    let first_digest = if refund {
        package.refund_sighash()
    } else {
        package.funding_sighash(first_id)?
    };
    let second_digest = if refund {
        package.refund_sighash()
    } else {
        package.funding_sighash(second_id)?
    };
    Ok([
        sign(first_key, first_digest)?,
        sign(second_key, second_digest)?,
    ])
}

fn decode(bytes: &[u8]) -> Result<Transaction, bitcoin::consensus::encode::Error> {
    deserialize(bytes)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[test]
fn fixed_policy_and_worst_case_vsize() {
    assert_eq!(ORIGIN_VALUE_SAT, 53_500);
    assert_eq!(REFUND_VALUE_PER_PARTICIPANT_SAT, 26_500);
    assert_eq!(FUNDING_FEE_SAT, 500);
    assert_eq!(REFUND_FEE_SAT, 500);
    assert_eq!(ACTIVATION_FEE_SAT, 500);
    assert_eq!(GAMEPLAY_ROOT_VALUE_SAT, 53_000);
    assert_eq!(REFUND_DELAY_BLOCKS, 144);
    // 221 stripped bytes and 224 witness bytes with two changes.
    assert_eq!((221_u64 * 4 + 224).div_ceil(4), MAX_SIGNED_FUNDING_VBYTES);
    // 137 stripped bytes and 256 witness bytes.
    assert_eq!((137_u64 * 4 + 256).div_ceil(4), MAX_SIGNED_REFUND_VBYTES);
}

#[test]
fn activation_is_exact_root_bound_and_fully_authorized() -> TestResult {
    let (package, first_key, second_key) = fixture()?;
    let mut root_script = [0x42; 34];
    root_script[0] = 0x51;
    root_script[1] = 32;
    let activation = package.activation(root_script)?;
    let transaction = decode(activation.unsigned_transaction_bytes())?;
    assert_eq!(transaction.input.len(), 1);
    assert_eq!(transaction.output.len(), 1);
    assert_eq!(transaction.input[0].previous_output.vout, 0);
    assert_eq!(
        transaction.input[0].previous_output.txid.to_string(),
        package.funding_txid().to_string()
    );
    assert_eq!(transaction.input[0].sequence.to_consensus_u32(), u32::MAX);
    assert_eq!(
        transaction.output[0].value.to_sat(),
        GAMEPLAY_ROOT_VALUE_SAT
    );
    assert_eq!(transaction.output[0].script_pubkey.as_bytes(), root_script);
    assert_eq!(ORIGIN_VALUE_SAT - transaction.output[0].value.to_sat(), 500);
    assert_eq!(
        transaction.compute_txid().to_string(),
        activation.txid().to_string()
    );

    let expected = SighashCache::new(&transaction).p2wsh_signature_hash(
        0,
        &ScriptBuf::from_bytes(package.origin_witness_script().to_vec()),
        Amount::from_sat(ORIGIN_VALUE_SAT),
        EcdsaSighashType::All,
    )?;
    assert_eq!(expected.to_byte_array(), activation.sighash());

    let signed = activation.assemble_signed([
        sign(&first_key, activation.sighash())?,
        sign(&second_key, activation.sighash())?,
    ])?;
    let signed_transaction = decode(signed.consensus_bytes())?;
    assert_eq!(
        signed_transaction.compute_txid().to_string(),
        activation.txid().to_string()
    );
    assert_eq!(signed_transaction.input[0].witness.len(), 3);
    assert_eq!(
        signed_transaction.input[0].witness.nth(2),
        Some(package.origin_witness_script())
    );

    let mut different_root = root_script;
    different_root[2] ^= 1;
    let substituted = package.activation(different_root)?;
    assert_ne!(activation.activation_id(), substituted.activation_id());
    assert_ne!(activation.txid(), substituted.txid());
    assert_ne!(activation.sighash(), substituted.sighash());
    assert_eq!(
        substituted.verify_signature(sign(&first_key, activation.sighash())?),
        Err(FundingError::InvalidSignature)
    );
    Ok(())
}

#[test]
fn cooperative_close_is_direct_exact_and_fully_authorized() -> TestResult {
    let (package, first_key, second_key) = fixture()?;
    let close = package.cooperative_close([30_000, 23_000])?;
    assert_eq!(close.payouts_sat(), [30_000, 23_000]);
    assert_eq!(close.origin_package_id(), package.package_id());
    let transaction = decode(close.unsigned_transaction_bytes())?;
    assert_eq!(transaction.input.len(), 1);
    assert_eq!(transaction.output.len(), 2);
    assert_eq!(transaction.input[0].previous_output.vout, 0);
    assert_eq!(
        transaction.input[0].previous_output.txid.to_string(),
        package.funding_txid().to_string()
    );
    assert_eq!(transaction.input[0].sequence.to_consensus_u32(), u32::MAX);
    assert_eq!(
        transaction
            .output
            .iter()
            .map(|output| output.value.to_sat())
            .sum::<u64>(),
        ORIGIN_VALUE_SAT - COOPERATIVE_CLOSE_FEE_SAT
    );
    let expected = SighashCache::new(&transaction).p2wsh_signature_hash(
        0,
        &ScriptBuf::from_bytes(package.origin_witness_script().to_vec()),
        Amount::from_sat(ORIGIN_VALUE_SAT),
        EcdsaSighashType::All,
    )?;
    assert_eq!(expected.to_byte_array(), close.sighash());
    let signed = close.assemble_signed([
        sign(&first_key, close.sighash())?,
        sign(&second_key, close.sighash())?,
    ])?;
    let signed_transaction = decode(signed.consensus_bytes())?;
    assert_eq!(
        signed_transaction.compute_txid().to_string(),
        close.txid().to_string()
    );
    assert_eq!(signed_transaction.input[0].witness.len(), 3);
    assert_eq!(
        signed_transaction.input[0].witness.nth(2),
        Some(package.origin_witness_script())
    );

    assert_eq!(
        package.cooperative_close([30_001, 23_000]),
        Err(FundingError::InvalidCooperativeClosePayouts)
    );
    assert_eq!(
        package.cooperative_close([329, 52_671]),
        Err(FundingError::InvalidCooperativeClosePayouts)
    );
    Ok(())
}

#[test]
fn activation_rejects_non_taproot_output() -> TestResult {
    let (package, _, _) = fixture()?;
    assert_eq!(
        package.activation([0; 34]),
        Err(FundingError::InvalidGameplayRootScript)
    );
    let mut wrong_version = [0x11; 34];
    wrong_version[1] = 32;
    assert_eq!(
        package.activation(wrong_version),
        Err(FundingError::InvalidGameplayRootScript)
    );
    Ok(())
}

#[test]
fn canonical_order_is_independent_of_argument_order() -> TestResult {
    let first_key = signing_key(1)?;
    let second_key = signing_key(2)?;
    let first = staging(0x11, 1, 500_000, &first_key)?;
    let second = staging(0x22, 2, CONTRIBUTION_SAT, &second_key)?;
    let forward = EscrowFundingPackage::new(context(0x53)?, first.clone(), second.clone())?;
    let reverse = EscrowFundingPackage::new(context(0x53)?, second, first)?;
    assert_eq!(forward, reverse);
    assert!(
        forward.participants()[0].participant_id() < forward.participants()[1].participant_id()
    );
    Ok(())
}

#[test]
fn rust_bitcoin_cross_checks_transactions_fees_and_sighashes() -> TestResult {
    let (package, _, _) = fixture()?;
    let funding = decode(&package.unsigned_funding_bytes())?;
    let refund = decode(&package.unsigned_refund_bytes())?;
    assert_eq!(
        funding.compute_txid().to_string(),
        package.funding_txid().to_string()
    );
    assert_eq!(
        refund.compute_txid().to_string(),
        package.refund_txid().to_string()
    );
    assert_eq!(funding.input.len(), 2);
    assert_eq!(funding.output.len(), 2);
    assert_eq!(funding.output[0].value.to_sat(), ORIGIN_VALUE_SAT);
    assert_eq!(
        funding.output[0].script_pubkey.as_bytes(),
        package.origin_script_pubkey()
    );
    assert_eq!(funding.output[1].value.to_sat(), 473_000);
    let input_sum = package
        .participants()
        .iter()
        .map(PlayerFundingInput::value_sat)
        .sum::<u64>();
    let output_sum = funding
        .output
        .iter()
        .map(|output| output.value.to_sat())
        .sum::<u64>();
    assert_eq!(input_sum - output_sum, FUNDING_FEE_SAT);
    assert_eq!(
        refund.input[0].sequence.to_consensus_u32(),
        u32::from(REFUND_DELAY_BLOCKS)
    );
    assert!(
        refund
            .output
            .iter()
            .all(|output| output.value.to_sat() == REFUND_VALUE_PER_PARTICIPANT_SAT)
    );
    assert_eq!(
        ORIGIN_VALUE_SAT
            - refund
                .output
                .iter()
                .map(|output| output.value.to_sat())
                .sum::<u64>(),
        REFUND_FEE_SAT
    );

    let mut funding_cache = SighashCache::new(&funding);
    for (index, participant) in package.participants().iter().enumerate() {
        let expected = funding_cache.p2wsh_signature_hash(
            index,
            &ScriptBuf::from_bytes(participant.staging_witness_script().to_vec()),
            Amount::from_sat(participant.value_sat()),
            EcdsaSighashType::All,
        )?;
        assert_eq!(expected.to_byte_array(), package.funding_sighashes()[index]);
    }
    let expected_refund = SighashCache::new(&refund).p2wsh_signature_hash(
        0,
        &ScriptBuf::from_bytes(package.origin_witness_script().to_vec()),
        Amount::from_sat(ORIGIN_VALUE_SAT),
        EcdsaSighashType::All,
    )?;
    assert_eq!(expected_refund.to_byte_array(), package.refund_sighash());
    Ok(())
}

#[test]
fn verifies_and_assembles_consensus_transactions() -> TestResult {
    let (package, first_key, second_key) = fixture()?;
    let signed_funding = package.assemble_signed_funding(package_shares(
        &package,
        &first_key,
        &second_key,
        false,
    )?)?;
    let funding = decode(signed_funding.consensus_bytes())?;
    assert_eq!(
        funding.compute_txid().to_string(),
        signed_funding.txid().to_string()
    );
    assert!(funding.input.iter().all(|input| input.witness.len() == 2));
    for (index, input) in funding.input.iter().enumerate() {
        assert_eq!(
            input.witness.last(),
            Some(
                package.participants()[index]
                    .staging_witness_script()
                    .as_slice()
            )
        );
    }

    let signed_refund =
        package.assemble_signed_refund(package_shares(&package, &first_key, &second_key, true)?)?;
    let refund = decode(signed_refund.consensus_bytes())?;
    assert_eq!(
        refund.compute_txid().to_string(),
        signed_refund.txid().to_string()
    );
    let witness = &refund.input[0].witness;
    assert_eq!(witness.len(), 3);
    assert_eq!(witness.nth(2), Some(package.origin_witness_script()));
    assert!(
        witness
            .nth(0)
            .is_some_and(|signature| signature.last() == Some(&1))
    );
    assert!(
        witness
            .nth(1)
            .is_some_and(|signature| signature.last() == Some(&1))
    );
    Ok(())
}

#[test]
fn signatures_cannot_replay_across_contexts() -> TestResult {
    let (first_package, first_key, second_key) = fixture()?;
    let second_package = EscrowFundingPackage::new(
        context(0x54)?,
        first_package.participants()[0].clone(),
        first_package.participants()[1].clone(),
    )?;
    assert_ne!(first_package.package_id(), second_package.package_id());
    assert_ne!(first_package.funding_txid(), second_package.funding_txid());
    for share in package_shares(&first_package, &first_key, &second_key, false)? {
        assert_eq!(
            second_package.verify_funding_signature(share),
            Err(FundingError::InvalidSignature)
        );
    }
    for share in package_shares(&first_package, &first_key, &second_key, true)? {
        assert_eq!(
            second_package.verify_refund_signature(share),
            Err(FundingError::InvalidSignature)
        );
    }
    Ok(())
}

#[test]
fn rejects_invalid_context_inputs_and_signature_sets() -> TestResult {
    assert_eq!(
        FundingContext::new([0; 32], [1; 32], [2; 32]),
        Err(FundingError::ZeroNetworkId)
    );
    assert_eq!(
        FundingContext::new([1; 32], [0; 32], [2; 32]),
        Err(FundingError::ZeroRoomId)
    );
    assert_eq!(
        FundingContext::new([1; 32], [2; 32], [0; 32]),
        Err(FundingError::ZeroSessionNonce)
    );
    let first_key = signing_key(1)?;
    let second_key = signing_key(2)?;
    let first = staging(0x11, 1, CONTRIBUTION_SAT, &first_key)?;
    let same_outpoint = PlayerFundingInput::new(
        first.outpoint(),
        CONTRIBUTION_SAT,
        public(&second_key),
        crate::FundingTerms::diagnostic(),
    )?;
    assert_eq!(
        EscrowFundingPackage::new(context(3)?, first.clone(), same_outpoint),
        Err(FundingError::DuplicateOutpoint)
    );
    assert_eq!(
        EscrowFundingPackage::new(
            context(3)?,
            first,
            staging(0x22, 2, CONTRIBUTION_SAT, &first_key)?,
        ),
        Err(FundingError::DuplicateParticipant)
    );
    assert_eq!(
        staging(1, 0, CONTRIBUTION_SAT - 1, &first_key),
        Err(FundingError::StagingValueTooSmall {
            value_sat: CONTRIBUTION_SAT - 1,
        })
    );
    assert!(matches!(
        staging(1, 0, CONTRIBUTION_SAT + 1, &first_key),
        Err(FundingError::DustChange { value_sat: 1, .. })
    ));
    assert_eq!(
        PlayerFundingInput::new(
            OutPoint::new(DisplayTxid::from_display_bytes([0; 32]), u32::MAX),
            CONTRIBUTION_SAT,
            public(&first_key),
            crate::FundingTerms::diagnostic()
        ),
        Err(FundingError::NullOutpoint)
    );
    assert_eq!(
        EscrowFundingPackage::new(
            context(3)?,
            staging(0x31, 0, MAX_MONEY_SAT, &first_key)?,
            staging(0x32, 0, CONTRIBUTION_SAT, &second_key)?,
        ),
        Err(FundingError::AggregateStagingValueOutOfRange)
    );
    let (package, first_key, _) = fixture()?;
    let first_id = ParticipantId::from_compressed_public_key(public(&first_key))?;
    let share = sign(&first_key, package.funding_sighash(first_id)?)?;
    assert_eq!(
        package.assemble_signed_funding([share, share]),
        Err(FundingError::DuplicateSignature)
    );
    let wrong = sign(&first_key, package.refund_sighash())?;
    assert_eq!(
        package.verify_funding_signature(wrong),
        Err(FundingError::InvalidSignature)
    );
    Ok(())
}

#[test]
fn rejects_high_s_compact_signature() {
    let mut high_s = [0_u8; 64];
    high_s[31] = 1;
    high_s[32..].copy_from_slice(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x40,
    ]);
    assert_eq!(
        CompactSignature::new(high_s),
        Err(FundingError::HighSSignature)
    );
}

#[test]
fn fixed_serialization_vector() -> TestResult {
    let (package, _, _) = fixture()?;
    assert_eq!(
        hex(&package.unsigned_funding_bytes()),
        "020000000211111111111111111111111111111111111111111111111111111111111111110100000000ffffffff22222222222222222222222222222222222222222222222222222222222222220200000000ffffffff02fcd000000000000022002063cd3a810e1406dc5a637df078bf8bb5827b698e91facc11bf43f5413fec1a59a8370700000000002200207a0f34ce0c30967eed1c5a2021b1e9321cd9949db04625c94580040b85c7433800000000"
    );
    assert_eq!(
        hex(&package.unsigned_refund_bytes()),
        "02000000011cd96704b781058f53084886c87005daf04c72fa512570a81e13c39e88db91ed0000000000900000000284670000000000002200207a0f34ce0c30967eed1c5a2021b1e9321cd9949db04625c94580040b85c743388467000000000000220020c8e67b034888874e4b80835ce8c50e310740fcd70aa85297c5dca4b786a6905b00000000"
    );
    assert_eq!(
        hex(package.origin_witness_script()),
        "207f1c586fbd5e683682bc9a7efbbed617b485e0f2f17869f5fb981df6f924ad4a7521031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fad21024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766ac"
    );
    assert_eq!(
        package.funding_sighashes().map(|digest| hex(&digest)),
        [
            "8e5d802047f98e2da3f80423ec70d03e47c8260eb8f5ba63c9e18dd58064400d",
            "317246293a621a17b750047f4a66d22d3cc75b9ccac4ccf353831f9242b60f5e",
        ]
    );
    assert_eq!(
        hex(&package.refund_sighash()),
        "b6f38b31d776a321948f7c3ba3fea55bcabcd8acebe5f34d44933521232fd102"
    );
    assert_eq!(
        hex(&package.package_id()),
        "db676113235fadc1ca1a7d55c7ca1f28012c5b74d5c7b3dff78f85779d091ea8"
    );
    assert_eq!(
        serialize(&decode(&package.unsigned_funding_bytes())?),
        package.unsigned_funding_bytes()
    );
    assert_eq!(
        serialize(&decode(&package.unsigned_refund_bytes())?),
        package.unsigned_refund_bytes()
    );
    Ok(())
}

#[test]
fn session_nonce_ceremony_has_fixed_domain_vectors() {
    let room_id = [0x11; 32];
    let alice_share = [0x22; 32];
    let bob_share = [0x33; 32];
    assert_eq!(
        hex(&commit_session_nonce_share(
            room_id,
            NonceSeat::Alice,
            alice_share,
        )),
        "5b766e9ead7ed7172f61dc3ac12beee824cc892cf7e0f3229776b3ec83c03d20",
    );
    assert_eq!(
        hex(&commit_session_nonce_share(
            room_id,
            NonceSeat::Bob,
            bob_share,
        )),
        "be489912dad579821d4681481b80f482e4a515f417a41a373d8cb1b3aa9ce9ca",
    );
    assert_eq!(
        hex(&derive_session_nonce(room_id, alice_share, bob_share)),
        "4c2910d24a30bdc8eecd041b277ef4396bbf478ee4ce52c7303e3e191b3bbef4",
    );
}

#[test]
fn funding_terms_follow_the_selected_gameplay_budget() -> TestResult {
    let terms = crate::FundingTerms::from_gameplay_budget(80_100, 500, 500, 500, 144)?;
    assert_eq!(terms.contribution_sat(), 40_550);
    assert_eq!(terms.origin_value_sat(), 80_600);
    assert_eq!(terms.refund_value_sat(), 40_050);
    let first = PlayerFundingInput::new(
        OutPoint::new(DisplayTxid::from_display_bytes([1; 32]), 0),
        40_550,
        public(&signing_key(1)?),
        terms,
    )?;
    let second = PlayerFundingInput::new(
        OutPoint::new(DisplayTxid::from_display_bytes([2; 32]), 0),
        40_550,
        public(&signing_key(2)?),
        terms,
    )?;
    let package = EscrowFundingPackage::new(context(9)?, first, second)?;
    let funding: Transaction = deserialize(&package.unsigned_funding)?;
    let refund: Transaction = deserialize(&package.unsigned_refund)?;
    assert_eq!(funding.output[0].value.to_sat(), terms.origin_value_sat());
    assert!(
        refund
            .output
            .iter()
            .all(|output| output.value.to_sat() == terms.refund_value_sat())
    );
    assert!(crate::FundingTerms::from_gameplay_budget(u64::MAX, 500, 500, 500, 144).is_err());
    assert!(crate::FundingTerms::from_gameplay_budget(80_101, 500, 500, 500, 144).is_err());
    assert!(crate::FundingTerms::from_gameplay_budget(80_100, 500, 500, 501, 144).is_err());
    Ok(())
}
