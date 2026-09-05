//! Wallet contracts.

/// Purpose for a newly allocated wallet script.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletScriptPurpose {
    /// Change from the jointly constructed origin transaction.
    FundingChange,
    /// Player's exact output in the pre-activation abort refund.
    OriginRefund,
    /// Terminal payout destination.
    TerminalPayout,
}

/// Funding-wallet capability kept separate from chain observation.
pub trait FundingWallet {
    /// Wallet-specific redacted failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Allocate a fresh consensus scriptPubKey for one purpose.
    ///
    /// # Errors
    ///
    /// Returns a wallet policy, custody, or storage failure.
    fn fresh_script(
        &mut self,
        profile_id: [u8; 32],
        purpose: WalletScriptPurpose,
    ) -> Result<Vec<u8>, Self::Error>;
    /// Select coins and populate a bounded unsigned PSBT supplied by the
    /// origin-package coordinator.
    ///
    /// # Errors
    ///
    /// Returns insufficient funds or a wallet policy/custody failure.
    fn select_funding(
        &mut self,
        profile_id: [u8; 32],
        required_value_sat: u64,
        unsigned_psbt: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
    /// Sign only inputs owned by this wallet without changing PSBT globals,
    /// inputs, or outputs.
    ///
    /// # Errors
    ///
    /// Returns a malformed request or wallet policy/custody failure.
    fn sign_owned_inputs(
        &mut self,
        profile_id: [u8; 32],
        fixed_psbt: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}
