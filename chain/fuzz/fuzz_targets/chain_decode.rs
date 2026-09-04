#![no_main]

use bitcoin::{Amount, ScriptBuf, TxOut};
use bp52_chain_bitcoin::verify_logical_transaction;
use bp52_chain_compiler::{
    GraphRootOpening, Preauthorization, PreauthorizationBundle, SignatureBundleOpening,
    SignatureRequest, SignedCommitment,
};
use bp52_chain_types::{
    AmountState, BettingState, ChainGameDescriptor, EdgeKind, LogicalEdge, LogicalNodeRecord,
    LogicalOutput, LogicalTransaction, SignedChainGameDescriptor, TerminalAccounting, TimeoutSpec,
};
use bp52_codec::{Decode, Encode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    canonical_roundtrip::<ChainGameDescriptor>(data);
    canonical_roundtrip::<SignedChainGameDescriptor>(data);
    canonical_roundtrip::<AmountState>(data);
    canonical_roundtrip::<BettingState>(data);
    canonical_roundtrip::<TimeoutSpec>(data);
    canonical_roundtrip::<TerminalAccounting>(data);
    canonical_roundtrip::<EdgeKind>(data);
    canonical_roundtrip::<LogicalOutput>(data);
    canonical_roundtrip::<LogicalTransaction>(data);
    canonical_roundtrip::<LogicalEdge>(data);
    canonical_roundtrip::<LogicalNodeRecord>(data);
    canonical_roundtrip::<SignatureRequest>(data);
    canonical_roundtrip::<Preauthorization>(data);
    canonical_roundtrip::<PreauthorizationBundle>(data);
    canonical_roundtrip::<SignedCommitment>(data);
    canonical_roundtrip::<GraphRootOpening>(data);
    canonical_roundtrip::<SignatureBundleOpening>(data);

    if let Ok(logical) = LogicalTransaction::decode_exact(data) {
        if let Some(value_sat) = logical
            .output_value()
            .ok()
            .and_then(|value| value.checked_add(logical.fee_sat))
        {
            let parent = TxOut {
                value: Amount::from_sat(value_sat),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            };
            let _ = verify_logical_transaction(&logical, &parent);
        }
    }
});

fn canonical_roundtrip<T: Decode + Encode>(data: &[u8]) {
    if let Ok(value) = T::decode_exact(data) {
        assert_eq!(value.encode_to_vec().as_deref(), Ok(data));
    }
}
