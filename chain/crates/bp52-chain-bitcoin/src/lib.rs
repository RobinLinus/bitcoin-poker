#![forbid(unsafe_code)]
#![doc = "Bitcoin transaction and predicate backend for BP52-CHAIN-v1."]

mod error;

/// Dlog card gates and authenticated seven-card showdown witnesses.
pub mod dlog52;
/// Exact witness-assisted Tapscript implementation of five-card evaluation.
pub mod eval5_script;
/// Deterministic fee policies.
pub mod fees;
/// Native reference semantics for reveal and showdown witnesses.
pub mod predicates;
/// BIP341 `SIGHASH_DEFAULT` helpers.
pub mod signing;
/// Deterministic, fail-closed Taproot leaf programs.
pub mod taproot;
/// Witness-independent version-2 transaction templates.
pub mod transactions;

pub use bp52_lamport::AliceScoreCertificate;
pub use error::BitcoinBackendError;
pub use eval5_script::{
    EVAL5_PROOF_ELEMENTS, Eval5ScriptWitness, encode_script_num, eval5_tapscript,
    eval5_tapscript_for_category,
};
pub use fees::{ClassFeePolicy, FeeClass, FeeError, FeePolicy, FixedFeePolicy, MAX_EXECUTED_PATH};
pub use predicates::{ALICE_SEVEN_SLOTS, BOB_SEVEN_SLOTS, RevealPattern};
pub use signing::{
    DEFAULT_SIGHASH_SIGNATURE_BYTES, DefaultSighashSignature, sign_sighash_default,
    taproot_key_sighash_default, taproot_script_sighash_default, verify_sighash_default,
};
pub use taproot::{
    ActionProgram, AliceShowdownProgram, BobPayoutProgram, CompiledTapLeaf, CompiledTaprootState,
    DlogRevealProgram, LeafProgram, MAX_CONSENSUS_SCRIPT_BYTES, MAX_TAPROOT_LEAVES,
    MAX_WITNESS_ELEMENT_BYTES, SHOWDOWN_CATEGORIES, TimeoutProgram,
    assemble_timeout_witness_elements, tapleaf_hash,
};
pub use transactions::{
    TransactionTemplate, custom_signet_network_id, ensure_non_mainnet, network_from_genesis_id,
    outpoint_consensus_bytes, outpoint_from_consensus_bytes, validate_network_identity,
    verify_logical_transaction,
};
