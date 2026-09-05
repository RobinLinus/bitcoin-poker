//! Deterministic prototype fee policies.

use poker_settlement_types::Role;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Maximum post-activation gameplay transactions in the fixed-limit profile.
pub const MAX_EXECUTED_PATH: u64 = 33;

/// The transaction class presented to a fee policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum FeeClass {
    /// A betting action transaction.
    Betting = 0,
    /// A private or public card-share reveal transaction.
    Reveal = 1,
    /// Alice's score-certificate transaction.
    AliceShowdown = 2,
    /// Bob's combined showdown and payout transaction.
    BobPayout = 3,
    /// A relative-timelocked timeout transaction.
    Timeout = 4,
    /// Any other fixed state transition.
    Transition = 5,
}

/// Failure while applying the fixed-fee policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FeeError {
    /// The configured fee is zero.
    #[error("the fixed transaction fee must be nonzero")]
    ZeroFee,
    /// The dust threshold is zero.
    #[error("the dust threshold must be nonzero")]
    ZeroDustThreshold,
    /// Multiplication or addition overflowed `u64`.
    #[error("fee arithmetic overflow")]
    ArithmeticOverflow,
    /// The fee reserve is insufficient for the requested transition.
    #[error("fee reserve {available} is smaller than required fee {required}")]
    InsufficientReserve {
        /// Remaining reserve.
        available: u64,
        /// Required fee.
        required: u64,
    },
    /// A nonzero terminal output would be dust.
    #[error("nonzero output {value} is below dust threshold {dust_threshold}")]
    DustOutput {
        /// Rejected output amount.
        value: u64,
        /// Active threshold.
        dust_threshold: u64,
    },
}

/// Exact fee behavior used by the deterministic compiler.
pub trait FeePolicy: Send + Sync {
    /// Returns the policy identifier committed by the descriptor.
    fn policy_id(&self) -> [u8; 32];

    /// Returns the exact fee for one transaction class.
    ///
    /// # Errors
    ///
    /// Returns a policy-specific error when the class has no valid fee or its
    /// amount cannot be represented.
    fn fee_for(&self, class: FeeClass) -> Result<u64, FeeError>;

    /// Returns the policy's nonzero-output dust threshold.
    fn dust_threshold(&self) -> u64;

    /// Deterministically assigns unused terminal reserve.
    fn split_unused_reserve(&self, remaining: u64, remainder_recipient: Role) -> (u64, u64);
}

/// Version-one fixed-fee policy used for logical tests and regtest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedFeePolicy {
    fee_sat: u64,
    dust_threshold_sat: u64,
}

/// Deterministic absolute fees selected independently for each executable
/// transaction class.
///
/// This policy is useful for a small-value graph whose showdown witnesses are
/// much larger than its betting and reveal witnesses. Charging the showdown
/// ceiling to every transaction would otherwise consume the stack before a
/// complete path can execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassFeePolicy {
    betting: u64,
    reveal: u64,
    alice_showdown: u64,
    bob_payout: u64,
    timeout: u64,
    dust_threshold: u64,
}

impl ClassFeePolicy {
    /// Creates a class-specific absolute-fee policy.
    ///
    /// # Errors
    ///
    /// Rejects a zero executable-class fee, a zero dust threshold, or
    /// overflow in the 33-transaction profile-path bound.
    pub fn new(
        betting_sat: u64,
        reveal_sat: u64,
        alice_showdown_sat: u64,
        bob_payout_sat: u64,
        timeout_sat: u64,
        dust_threshold_sat: u64,
    ) -> Result<Self, FeeError> {
        if [
            betting_sat,
            reveal_sat,
            alice_showdown_sat,
            bob_payout_sat,
            timeout_sat,
        ]
        .contains(&0)
        {
            return Err(FeeError::ZeroFee);
        }
        if dust_threshold_sat == 0 {
            return Err(FeeError::ZeroDustThreshold);
        }
        let policy = Self {
            betting: betting_sat,
            reveal: reveal_sat,
            alice_showdown: alice_showdown_sat,
            bob_payout: bob_payout_sat,
            timeout: timeout_sat,
            dust_threshold: dust_threshold_sat,
        };
        policy.maximum_reference_path_fee()?;
        Ok(policy)
    }

    /// Returns the conservative fee bound for the 33-transaction profile route.
    ///
    /// Compilers should reserve their exact descriptor-derived maximum; this
    /// value remains useful as an overflow-checked upper bound.
    ///
    /// # Errors
    ///
    /// Returns an overflow error if the class fees cannot be accumulated.
    pub fn maximum_reference_path_fee(self) -> Result<u64, FeeError> {
        let betting = self
            .betting
            .checked_mul(23)
            .ok_or(FeeError::ArithmeticOverflow)?;
        let reveals = self
            .reveal
            .checked_mul(8)
            .ok_or(FeeError::ArithmeticOverflow)?;
        betting
            .checked_add(reveals)
            .and_then(|total| total.checked_add(self.alice_showdown))
            .and_then(|total| total.checked_add(self.bob_payout.max(self.timeout)))
            .ok_or(FeeError::ArithmeticOverflow)
    }
}

impl FixedFeePolicy {
    /// Creates a fixed-fee policy.
    ///
    /// # Errors
    ///
    /// Rejects zero values and arithmetic overflow in the maximum-path check.
    pub fn new(fee_sat: u64, dust_threshold_sat: u64) -> Result<Self, FeeError> {
        if fee_sat == 0 {
            return Err(FeeError::ZeroFee);
        }
        if dust_threshold_sat == 0 {
            return Err(FeeError::ZeroDustThreshold);
        }
        fee_sat
            .checked_mul(MAX_EXECUTED_PATH)
            .ok_or(FeeError::ArithmeticOverflow)?;
        Ok(Self {
            fee_sat,
            dust_threshold_sat,
        })
    }

    /// Returns the reserve covering the fixed-limit profile's maximum path.
    ///
    /// # Errors
    ///
    /// Returns an overflow error if the configured fee cannot be multiplied
    /// by the fixed maximum path length.
    pub fn minimum_reserve(self) -> Result<u64, FeeError> {
        self.fee_sat
            .checked_mul(MAX_EXECUTED_PATH)
            .ok_or(FeeError::ArithmeticOverflow)
    }

    /// Debits one exact fee from a reserve.
    ///
    /// # Errors
    ///
    /// Returns [`FeeError::InsufficientReserve`] when `remaining` is too small.
    pub fn debit(self, remaining: u64, class: FeeClass) -> Result<u64, FeeError> {
        let fee = self.fee_for(class)?;
        remaining
            .checked_sub(fee)
            .ok_or(FeeError::InsufficientReserve {
                available: remaining,
                required: fee,
            })
    }

    /// Checks that a nonzero output is not dust.
    ///
    /// # Errors
    ///
    /// Rejects values in `1..dust_threshold`.
    pub fn validate_output(self, value: u64) -> Result<(), FeeError> {
        if value != 0 && value < self.dust_threshold_sat {
            return Err(FeeError::DustOutput {
                value,
                dust_threshold: self.dust_threshold_sat,
            });
        }
        Ok(())
    }
}

impl FeePolicy for FixedFeePolicy {
    fn policy_id(&self) -> [u8; 32] {
        const TAG: &[u8] = b"BP52/fixed-fee-policy/v1";
        let tag_hash = Sha256::digest(TAG);
        let mut hash = Sha256::new();
        hash.update(tag_hash);
        hash.update(tag_hash);
        hash.update([1_u8]);
        hash.update(self.fee_sat.to_le_bytes());
        hash.update(self.dust_threshold_sat.to_le_bytes());
        hash.update([0_u8]); // v1 disposition: equal split, named remainder.
        hash.finalize().into()
    }

    fn fee_for(&self, _class: FeeClass) -> Result<u64, FeeError> {
        Ok(self.fee_sat)
    }

    fn dust_threshold(&self) -> u64 {
        self.dust_threshold_sat
    }

    fn split_unused_reserve(&self, remaining: u64, remainder_recipient: Role) -> (u64, u64) {
        let half = remaining / 2;
        let remainder = remaining % 2;
        match remainder_recipient {
            Role::Alice => (half + remainder, half),
            Role::Bob => (half, half + remainder),
        }
    }
}

impl FeePolicy for ClassFeePolicy {
    fn policy_id(&self) -> [u8; 32] {
        const TAG: &[u8] = b"BP52/class-fee-policy/v1";
        let tag_hash = Sha256::digest(TAG);
        let mut hash = Sha256::new();
        hash.update(tag_hash);
        hash.update(tag_hash);
        hash.update([1_u8]);
        hash.update(self.betting.to_le_bytes());
        hash.update(self.reveal.to_le_bytes());
        hash.update(self.alice_showdown.to_le_bytes());
        hash.update(self.bob_payout.to_le_bytes());
        hash.update(self.timeout.to_le_bytes());
        hash.update(self.dust_threshold.to_le_bytes());
        hash.update([0_u8]); // v1 disposition: equal split, named remainder.
        hash.finalize().into()
    }

    fn fee_for(&self, class: FeeClass) -> Result<u64, FeeError> {
        Ok(match class {
            FeeClass::Betting => self.betting,
            FeeClass::Reveal => self.reveal,
            FeeClass::AliceShowdown => self.alice_showdown,
            FeeClass::BobPayout => self.bob_payout,
            FeeClass::Timeout => self.timeout,
            FeeClass::Transition => 0,
        })
    }

    fn dust_threshold(&self) -> u64 {
        self.dust_threshold
    }

    fn split_unused_reserve(&self, remaining: u64, remainder_recipient: Role) -> (u64, u64) {
        let half = remaining / 2;
        let remainder = remaining % 2;
        match remainder_recipient {
            Role::Alice => (half + remainder, half),
            Role::Bob => (half, half + remainder),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ClassFeePolicy, FeeClass, FeeError, FeePolicy, FixedFeePolicy, MAX_EXECUTED_PATH};
    use poker_settlement_types::Role;

    #[test]
    fn fixed_policy_is_deterministic_and_covers_maximum_path() -> Result<(), FeeError> {
        let policy = FixedFeePolicy::new(200, 330)?;
        assert_eq!(policy.minimum_reserve()?, 200 * MAX_EXECUTED_PATH);
        assert_eq!(policy.fee_for(FeeClass::Betting)?, 200);
        assert_eq!(policy.debit(201, FeeClass::Reveal)?, 1);
        assert_eq!(policy.split_unused_reserve(5, Role::Alice), (3, 2));
        assert_eq!(policy.split_unused_reserve(5, Role::Bob), (2, 3));
        assert_ne!(policy.policy_id(), [0_u8; 32]);
        Ok(())
    }

    #[test]
    fn invalid_fee_and_dust_are_rejected() -> Result<(), FeeError> {
        assert_eq!(FixedFeePolicy::new(0, 330), Err(FeeError::ZeroFee));
        assert_eq!(FixedFeePolicy::new(1, 0), Err(FeeError::ZeroDustThreshold));
        let policy = FixedFeePolicy::new(200, 330)?;
        assert!(matches!(
            policy.validate_output(329),
            Err(FeeError::DustOutput { .. })
        ));
        Ok(())
    }

    #[test]
    fn class_policy_prices_large_showdowns_without_overcharging_actions() -> Result<(), FeeError> {
        let policy = ClassFeePolicy::new(224, 264, 2_203, 3_089, 232, 330)?;
        assert_eq!(policy.fee_for(FeeClass::Betting)?, 224);
        assert_eq!(policy.fee_for(FeeClass::Reveal)?, 264);
        assert_eq!(policy.fee_for(FeeClass::AliceShowdown)?, 2_203);
        assert_eq!(policy.fee_for(FeeClass::BobPayout)?, 3_089);
        assert_eq!(policy.fee_for(FeeClass::Timeout)?, 232);
        assert_eq!(policy.fee_for(FeeClass::Transition)?, 0);
        assert_eq!(policy.maximum_reference_path_fee()?, 12_556);
        assert_eq!(policy.split_unused_reserve(5, Role::Alice), (3, 2));
        assert_ne!(policy.policy_id(), [0; 32]);
        Ok(())
    }

    #[test]
    fn class_policy_rejects_zero_and_overflow() {
        assert_eq!(
            ClassFeePolicy::new(0, 1, 1, 1, 1, 330),
            Err(FeeError::ZeroFee)
        );
        assert_eq!(
            ClassFeePolicy::new(1, 1, 1, 1, 1, 0),
            Err(FeeError::ZeroDustThreshold)
        );
        assert_eq!(
            ClassFeePolicy::new(u64::MAX, 1, 1, 1, 1, 330),
            Err(FeeError::ArithmeticOverflow)
        );
    }
}
