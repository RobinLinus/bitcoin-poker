//! Fixed-tree contest outputs. These scripts are intentionally separate from
//! the deployed on-chain game format; they do not make a session cooperative.
//!
//! Every abandoned edge must land in a contest output, including terminal
//! edges. Its ordinary spend waits `contest_blocks`; justice is immediate and
//! requires both the offender's preimage and the counterparty's signature.
//! Revoking a sibling never revokes the selected prefix. A forced path pays
//! this delay at every protected output, not just at the hand entry.

use crate::taproot::SCRIPT_PATH_NUMS_KEY;
use bitcoin::{
    Script, ScriptBuf, Witness,
    opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_SHA256},
    script::Builder,
    secp256k1::{Secp256k1, Signing, Verification, XOnlyPublicKey},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
};
use sha2::{Digest, Sha256};

/// A script construction error.
#[derive(Debug, thiserror::Error)]
pub enum ContestError {
    /// A zero delay would permit the offender to bypass justice.
    #[error("contest delay must be nonzero")]
    ZeroDelay,
    /// No executable continuation was supplied.
    #[error("contest continuation must be nonempty")]
    EmptyContinuation,
    /// The generated Taproot tree was invalid.
    #[error("invalid contest Taproot tree")]
    Taproot,
}

/// Separate hand retirement from individual branch retirement.
#[derive(Clone, Copy)]
pub enum RetirementLevel {
    /// Retire one owner's hand commitment after replacement is enforceable.
    Hand,
    /// Retire an unused edge; never disclose this for a selected edge.
    Branch,
}

/// Domain-separated secret derivation for a single, fixed authorization.
/// `owner` selects the Bitcoin materialization and `offender` selects the
/// authorizer who can publish the obsolete edge; these are different roles.
#[must_use]
pub fn retirement_secret(
    seed: &[u8; 32],
    level: RetirementLevel,
    hand: [u8; 32],
    node: [u8; 32],
    edge: u32,
    owner: bool,
    offender: bool,
) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    // HMAC accepts keys of every length.
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(seed) else {
        unreachable!()
    };
    mac.update(b"POKER/channel-retirement/v1");
    mac.update(&[match level {
        RetirementLevel::Hand => 0,
        RetirementLevel::Branch => 1,
    }]);
    mac.update(&hand);
    mac.update(&node);
    mac.update(&edge.to_le_bytes());
    mac.update(&[u8::from(owner), u8::from(offender)]);
    mac.finalize().into_bytes().into()
}

/// Commitment published during preparation; the preimage stays private until
/// the corresponding hand or unselected branch is safely retired.
#[must_use]
pub fn retirement_commitment(secret: [u8; 32]) -> [u8; 32] {
    Sha256::digest(secret).into()
}

/// Public protection attached to the output of one incoming hand/branch edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationGuard {
    /// Block delay before ordinary continuation may spend this output.
    pub contest_blocks: u16,
    /// SHA256 commitment to the accountable author's private retirement secret.
    pub commitment: [u8; 32],
    /// Only the accountable author's counterparty may collect justice.
    pub counterparty: XOnlyPublicKey,
}

impl RevocationGuard {
    /// Exact immediate justice script. Witness: signature, retirement preimage.
    #[must_use]
    pub fn justice_script(&self) -> ScriptBuf {
        Builder::new().push_opcode(OP_SHA256).push_slice(self.commitment)
            .push_opcode(OP_EQUALVERIFY).push_x_only_key(&self.counterparty)
            .push_opcode(OP_CHECKSIG).into_script()
    }

    /// Stable lookup key for the added justice leaf, distinct from game predicates.
    #[must_use]
    pub fn predicate_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"POKER/channel-justice/v1");
        h.update(self.contest_blocks.to_le_bytes());
        h.update(self.justice_script().as_bytes());
        h.finalize().into()
    }
}

/// Script-only output with one delayed continuation and immediate justice.
pub struct ContestOutput {
    continuation: ScriptBuf,
    justice: ScriptBuf,
    spend: TaprootSpendInfo,
}

impl ContestOutput {
    /// Compute the exact two-leaf output without allocating witness control blocks.
    ///
    /// # Errors
    /// Rejects the same invalid delay/continuation as the witness materializer.
    pub fn signing_output<C: Signing>(
        secp: &Secp256k1<C>, continuation: &Script, guard: RevocationGuard,
    ) -> Result<ScriptBuf, ContestError> {
        use bitcoin::taproot::TapNodeHash;
        if guard.contest_blocks == 0 { return Err(ContestError::ZeroDelay); }
        if continuation.is_empty() { return Err(ContestError::EmptyContinuation); }
        let mut bytes = Builder::new().push_int(i64::from(guard.contest_blocks))
            .push_opcode(OP_CSV).push_opcode(OP_DROP).into_script().into_bytes();
        bytes.extend_from_slice(continuation.as_bytes());
        let root = TapNodeHash::from_node_hashes(
            TapNodeHash::from_script(&ScriptBuf::from_bytes(bytes), LeafVersion::TapScript),
            TapNodeHash::from_script(&guard.justice_script(), LeafVersion::TapScript),
        );
        crate::taproot::script_path_output(secp, root).map_err(|_| ContestError::Taproot)
    }

    /// Wrap an existing authorization program without weakening its checks.
    /// A timeout continuation must encode `contest_blocks + action_blocks`
    /// (CSV checks on the same output take the maximum, not their sum).
    ///
    /// # Errors
    /// Rejects zero delay, empty continuation, or an invalid Taproot tree.
    pub fn new<C: Verification>(
        secp: &Secp256k1<C>,
        continuation: &Script,
        contest_blocks: u16,
        commitment: [u8; 32],
        counterparty: XOnlyPublicKey,
    ) -> Result<Self, ContestError> {
        if contest_blocks == 0 {
            return Err(ContestError::ZeroDelay);
        }
        if continuation.is_empty() {
            return Err(ContestError::EmptyContinuation);
        }
        let mut bytes = Builder::new()
            .push_int(i64::from(contest_blocks))
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .into_script()
            .into_bytes();
        bytes.extend_from_slice(continuation.as_bytes());
        let continuation = ScriptBuf::from_bytes(bytes);
        let justice = Builder::new()
            .push_opcode(OP_SHA256)
            .push_slice(commitment)
            .push_opcode(OP_EQUALVERIFY)
            .push_x_only_key(&counterparty)
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let key =
            XOnlyPublicKey::from_slice(&SCRIPT_PATH_NUMS_KEY).map_err(|_| ContestError::Taproot)?;
        let spend = TaprootBuilder::new()
            .add_leaf(1, continuation.clone())
            .map_err(|_| ContestError::Taproot)?
            .add_leaf(1, justice.clone())
            .map_err(|_| ContestError::Taproot)?
            .finalize(secp, key)
            .map_err(|_| ContestError::Taproot)?;
        Ok(Self {
            continuation,
            justice,
            spend,
        })
    }

    /// Locking script; no participant knows the internal key's discrete log.
    #[must_use]
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.spend.output_key())
    }

    /// Exact delayed program for signing the fixed continuation transaction.
    #[must_use]
    pub fn continuation_script(&self) -> &Script {
        &self.continuation
    }

    /// Exact immediate program for signing a fixed-destination justice spend.
    #[must_use]
    pub fn justice_script(&self) -> &Script {
        &self.justice
    }

    /// Assemble either path's witness. Callers still verify signatures against
    /// the exact transaction; this helper only supplies script and control block.
    ///
    /// # Errors
    /// Rejects an impossible missing control block.
    pub fn witness(&self, justice: bool, elements: &[Vec<u8>]) -> Result<Witness, ContestError> {
        let script = if justice {
            &self.justice
        } else {
            &self.continuation
        };
        let control = self
            .spend
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or(ContestError::Taproot)?;
        let mut witness = Witness::from_slice(elements);
        witness.push(script.as_bytes());
        witness.push(control.serialize());
        Ok(witness)
    }
}
