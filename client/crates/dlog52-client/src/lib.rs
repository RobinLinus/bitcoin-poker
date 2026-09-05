#![forbid(unsafe_code)]
//! Fail-closed handoff from verified DLOG52 setup state to the regtest chain demo.

use bitcoin::Network;
use dlog52_bitcoin::{BitcoinError, RegtestGateManifest};
use dlog52_protocol::{
    AcceptedDeal, GameConfig, ProtocolError, VerifiedAcceptedDeal, VerifiedBundle,
    finalize_verified_attempt,
};
use thiserror::Error;

/// A deal that crossed both the cryptographic acceptance boundary and the
/// chain profile boundary.
pub struct AcceptedDealHandoff {
    accepted: VerifiedAcceptedDeal,
    gates: RegtestGateManifest,
}

impl AcceptedDealHandoff {
    /// Finalize a fully verified live attempt and compile its nine regtest card
    /// gates atomically.
    ///
    /// No API accepts a naked accepted descriptor, catalogue, or collection of
    /// x-only keys. The proof-verified bundles and exact stage-8 root are
    /// required, and non-regtest networks fail before a manifest is returned.
    pub fn finalize(
        network: Network,
        config: &GameConfig,
        bundle_a: &VerifiedBundle,
        bundle_b: &VerifiedBundle,
        verification_root: [u8; 32],
        deal: AcceptedDeal,
    ) -> Result<Self, HandoffError> {
        dlog52_bitcoin::require_regtest(network)?;
        let accepted =
            finalize_verified_attempt(config, bundle_a, bundle_b, verification_root, deal)?;
        let gates = dlog52_bitcoin::build_regtest_gate(&accepted)?;
        Ok(Self { accepted, gates })
    }

    /// Borrow the chain-authoritative accepted deal.
    #[must_use]
    pub const fn accepted(&self) -> &VerifiedAcceptedDeal {
        &self.accepted
    }

    /// Borrow the deterministically compiled card gates.
    #[must_use]
    pub const fn gates(&self) -> &RegtestGateManifest {
        &self.gates
    }
}

/// Failure before the client can enter chain setup.
#[derive(Debug, Error)]
pub enum HandoffError {
    /// The DLOG52 accepted descriptor or proof-verified setup was invalid.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// The requested chain profile or Taproot gate construction was invalid.
    #[error(transparent)]
    Bitcoin(#[from] BitcoinError),
}
