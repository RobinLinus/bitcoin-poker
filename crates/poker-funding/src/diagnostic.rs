//! Fixed historical funding vectors for diagnostics only.
//! These values are not a supported funded browser deployment.

/// Amount contributed by each staging input.
pub const CONTRIBUTION_SAT: u64 = 27_000;
/// Fee paid by the funding transaction.
pub const FUNDING_FEE_SAT: u64 = 500;
/// Value locked in the shared origin output.
pub const ORIGIN_VALUE_SAT: u64 = CONTRIBUTION_SAT * 2 - FUNDING_FEE_SAT;
/// Relative block delay on the fair-refund transaction.
pub const REFUND_DELAY_BLOCKS: u16 = 144;
/// Amount returned to each participant by the fair refund.
pub const REFUND_VALUE_PER_PARTICIPANT_SAT: u64 = 26_500;
/// Fee paid by the fair-refund transaction.
pub const REFUND_FEE_SAT: u64 = ORIGIN_VALUE_SAT - REFUND_VALUE_PER_PARTICIPANT_SAT * 2;
/// Fee paid by the origin-to-gameplay-root activation transaction.
pub const ACTIVATION_FEE_SAT: u64 = 500;
/// Fee paid by a cooperative close that settles directly from the origin.
pub const COOPERATIVE_CLOSE_FEE_SAT: u64 = 500;
/// Exact value of the first gameplay state output.
pub const GAMEPLAY_ROOT_VALUE_SAT: u64 = ORIGIN_VALUE_SAT - ACTIVATION_FEE_SAT;
