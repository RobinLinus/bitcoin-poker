//! Funding amounts derived from a chosen gameplay budget.
use crate::{FundingError, MAX_MONEY_SAT, P2WSH_MIN_NON_DUST_SAT};

/// Validated balanced contributions, fees, and refund deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FundingTerms {
    contribution_sat: u64,
    funding_fee_sat: u64,
    activation_fee_sat: u64,
    refund_fee_sat: u64,
    refund_delay_blocks: u16,
}

impl FundingTerms {
    /// Derive equal contributions for an exact gameplay output budget.
    ///
    /// # Errors
    /// Rejects overflow, nonpositive fees/delay, dust, or amounts that cannot
    /// split exactly between two equal contributions and two equal refunds.
    pub fn from_gameplay_budget(
        gameplay_value_sat: u64,
        funding_fee_sat: u64,
        activation_fee_sat: u64,
        refund_fee_sat: u64,
        refund_delay_blocks: u16,
    ) -> Result<Self, FundingError> {
        let total = gameplay_value_sat
            .checked_add(funding_fee_sat)
            .and_then(|v| v.checked_add(activation_fee_sat))
            .ok_or(FundingError::InvalidFundingTerms)?;
        let origin = total
            .checked_sub(funding_fee_sat)
            .ok_or(FundingError::InvalidFundingTerms)?;
        let refund = origin
            .checked_sub(refund_fee_sat)
            .ok_or(FundingError::InvalidFundingTerms)?;
        if total > MAX_MONEY_SAT
            || total % 2 != 0
            || refund % 2 != 0
            || gameplay_value_sat < P2WSH_MIN_NON_DUST_SAT
            || refund / 2 < P2WSH_MIN_NON_DUST_SAT
            || funding_fee_sat == 0
            || activation_fee_sat == 0
            || refund_fee_sat == 0
            || refund_delay_blocks == 0
        {
            return Err(FundingError::InvalidFundingTerms);
        }
        Ok(Self {
            contribution_sat: total / 2,
            funding_fee_sat,
            activation_fee_sat,
            refund_fee_sat,
            refund_delay_blocks,
        })
    }
    /// Fixed values used only by the funding diagnostic bridge and test vectors.
    #[must_use]
    pub const fn diagnostic() -> Self {
        Self {
            contribution_sat: 27_000,
            funding_fee_sat: 500,
            activation_fee_sat: 500,
            refund_fee_sat: 500,
            refund_delay_blocks: 144,
        }
    }
    /// Per-player contribution before funding fees.
    #[must_use]
    pub const fn contribution_sat(self) -> u64 {
        self.contribution_sat
    }
    /// Exact shared escrow amount.
    #[must_use]
    pub const fn origin_value_sat(self) -> u64 {
        self.contribution_sat * 2 - self.funding_fee_sat
    }
    /// Exact gameplay output amount after activation fees.
    #[must_use]
    pub const fn gameplay_value_sat(self) -> u64 {
        self.origin_value_sat() - self.activation_fee_sat
    }
    /// Equal per-player delayed-refund amount.
    #[must_use]
    pub const fn refund_value_sat(self) -> u64 {
        (self.origin_value_sat() - self.refund_fee_sat) / 2
    }
    /// Relative refund delay in blocks.
    #[must_use]
    pub const fn refund_delay_blocks(self) -> u16 {
        self.refund_delay_blocks
    }
    /// Fee for the optional direct-close experiment.
    #[must_use]
    pub const fn cooperative_close_fee_sat(self) -> u64 {
        self.refund_fee_sat
    }
}
