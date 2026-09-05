//! Pure reducer policies that can be exercised without constructing cryptographic fixtures.

use std::num::NonZeroU16;

use bp52_client_ports::BlockRef;

use crate::event::SessionEvent;

/// Coarse durable lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    /// Waiting for the exact origin output.
    AwaitingOrigin,
    /// Running or retrying the 16-flight DEAL protocol.
    Dealing,
    /// Waiting for both accepted-deal signatures.
    AcceptingDeal,
    /// Waiting for both descriptor signatures.
    SigningDescriptor,
    /// Building and exchanging graph-bound public material.
    PreparingGraph,
    /// Waiting for local secret inventory and origin activation signatures.
    AuthorizingActivation,
    /// Waiting for activation confirmation.
    AwaitingActivation,
    /// A confirmed nonterminal gameplay state is active.
    Active,
    /// A terminal settlement is confirmed.
    Settled,
    /// An authenticated conflict or irreversible validation failure occurred.
    Halted,
}

/// Trusted ingress boundary for a session event.
///
/// The classification prevents a relay peer from impersonating the chain
/// observer, local wallet, or secret-bearing runtime. It is checked before an
/// event can enter the durable journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EventSource {
    /// Authenticated best-chain observer.
    Chain = 0,
    /// Capability-authenticated two-party exchange.
    Exchange = 1,
    /// Local secret-bearing protocol runtime.
    LocalRuntime = 2,
    /// Local funding/identity wallet.
    LocalWallet = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventIngress {
    Chain,
    Exchange,
    LocalRuntime,
    WalletOrExchange,
}

/// Whether an event is permitted to cross a particular trusted boundary.
pub(crate) const fn event_accepts_source(event: &SessionEvent, source: EventSource) -> bool {
    let ingress = match event {
        SessionEvent::OriginConfirmed(_)
        | SessionEvent::TipObserved(_)
        | SessionEvent::SpendConfirmed(_) => EventIngress::Chain,
        SessionEvent::DealEnvelope(_)
        | SessionEvent::AcceptedDealSignature { .. }
        | SessionEvent::DealRetrySignature { .. }
        | SessionEvent::DescriptorSignature { .. } => EventIngress::Exchange,
        SessionEvent::DealVerificationAttested(_)
        | SessionEvent::GraphPrepared(_)
        | SessionEvent::RuntimeAuthorized(_)
        | SessionEvent::StateConfirmed(_)
        | SessionEvent::StateAdvancedOffchain(_) => EventIngress::LocalRuntime,
        SessionEvent::ActivationAuthorized(_) => EventIngress::WalletOrExchange,
    };
    matches!(
        (ingress, source),
        (EventIngress::Chain, EventSource::Chain)
            | (EventIngress::Exchange, EventSource::Exchange)
            | (EventIngress::LocalRuntime, EventSource::LocalRuntime)
            | (
                EventIngress::WalletOrExchange,
                EventSource::LocalWallet | EventSource::Exchange
            )
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfirmationError {
    InvalidBlockRelation,
    Overflow,
    InsufficientDepth,
}

/// Validate the block relationship and count the containing block as the
/// first confirmation.
pub(crate) fn validate_confirmation(
    confirmed_in: BlockRef,
    observed_tip: BlockRef,
    required_depth: NonZeroU16,
) -> Result<u32, ConfirmationError> {
    if confirmed_in.hash == [0; 32]
        || observed_tip.hash == [0; 32]
        || observed_tip.height < confirmed_in.height
        || (observed_tip.height == confirmed_in.height && observed_tip.hash != confirmed_in.hash)
    {
        return Err(ConfirmationError::InvalidBlockRelation);
    }
    let confirmations = observed_tip
        .height
        .checked_sub(confirmed_in.height)
        .and_then(|distance| distance.checked_add(1))
        .ok_or(ConfirmationError::Overflow)?;
    if confirmations < u32::from(required_depth.get()) {
        return Err(ConfirmationError::InsufficientDepth);
    }
    Ok(confirmations)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TipRelation {
    First,
    Duplicate,
    Advance,
    Regression,
    SameHeightReplacement,
}

/// Classify a tip update without mutating reducer or monitor state.
pub(crate) fn classify_tip(previous: Option<BlockRef>, next: BlockRef) -> TipRelation {
    let Some(previous) = previous else {
        return TipRelation::First;
    };
    match next.height.cmp(&previous.height) {
        std::cmp::Ordering::Less => TipRelation::Regression,
        std::cmp::Ordering::Equal if next.hash == previous.hash => TipRelation::Duplicate,
        std::cmp::Ordering::Equal => TipRelation::SameHeightReplacement,
        std::cmp::Ordering::Greater => TipRelation::Advance,
    }
}

pub(crate) fn journal_link_is_contiguous(
    expected_index: usize,
    expected_previous_hash: [u8; 32],
    actual_sequence: u64,
    actual_previous_hash: [u8; 32],
) -> bool {
    actual_sequence == u64::try_from(expected_index).unwrap_or(u64::MAX)
        && actual_previous_hash == expected_previous_hash
}

#[cfg(test)]
mod tests {
    use bp52_chain_types::Role;
    use bp52_client_ports::OutPointRef;

    use crate::event::{ChainSpend, ConfirmedOrigin, TipFact};

    use super::*;

    const SOURCES: [EventSource; 4] = [
        EventSource::Chain,
        EventSource::Exchange,
        EventSource::LocalRuntime,
        EventSource::LocalWallet,
    ];

    const fn block(height: u32, marker: u8) -> BlockRef {
        BlockRef {
            height,
            hash: [marker; 32],
        }
    }

    fn dummy_origin() -> ConfirmedOrigin {
        ConfirmedOrigin {
            profile_id: [1; 32],
            outpoint: OutPointRef {
                txid: [2; 32],
                vout: 0,
            },
            value_sat: 1,
            script_pubkey: vec![1],
            creating_txid: [2; 32],
            creating_transaction: vec![1],
            confirmed_in: block(1, 3),
            observed_tip: block(1, 3),
        }
    }

    fn dummy_spend() -> ChainSpend {
        ChainSpend {
            profile_id: [1; 32],
            spent_outpoint: OutPointRef {
                txid: [2; 32],
                vout: 0,
            },
            spending_txid: [4; 32],
            spending_transaction: vec![1],
            input_index: 0,
            confirmed_in: block(2, 5),
            observed_tip: block(2, 5),
        }
    }

    #[test]
    fn confirmation_policy_is_inclusive_and_checks_boundaries() -> Result<(), &'static str> {
        let one = NonZeroU16::MIN;
        let two = NonZeroU16::new(2).ok_or("two must be nonzero")?;
        assert_eq!(validate_confirmation(block(7, 1), block(7, 1), one), Ok(1));
        assert_eq!(
            validate_confirmation(block(7, 1), block(7, 1), two),
            Err(ConfirmationError::InsufficientDepth)
        );
        assert_eq!(validate_confirmation(block(7, 1), block(8, 2), two), Ok(2));
        assert_eq!(
            validate_confirmation(block(8, 1), block(7, 2), one),
            Err(ConfirmationError::InvalidBlockRelation)
        );
        assert_eq!(
            validate_confirmation(block(7, 1), block(7, 2), one),
            Err(ConfirmationError::InvalidBlockRelation)
        );
        assert_eq!(
            validate_confirmation(block(0, 1), block(u32::MAX, 2), one),
            Err(ConfirmationError::Overflow)
        );
        assert_eq!(
            validate_confirmation(block(7, 0), block(7, 0), one),
            Err(ConfirmationError::InvalidBlockRelation)
        );
        Ok(())
    }

    #[test]
    fn tip_policy_distinguishes_replay_advance_and_reorg_shapes() {
        let current = block(10, 1);
        assert_eq!(classify_tip(None, current), TipRelation::First);
        assert_eq!(classify_tip(Some(current), current), TipRelation::Duplicate);
        assert_eq!(
            classify_tip(Some(current), block(11, 2)),
            TipRelation::Advance
        );
        assert_eq!(
            classify_tip(Some(current), block(9, 3)),
            TipRelation::Regression
        );
        assert_eq!(
            classify_tip(Some(current), block(10, 4)),
            TipRelation::SameHeightReplacement
        );
    }

    #[test]
    fn every_event_variant_has_an_explicit_ingress_policy() {
        let origin = dummy_origin();
        let spend = dummy_spend();
        let events_and_sources = [
            (
                SessionEvent::OriginConfirmed(origin),
                &[EventSource::Chain][..],
            ),
            (
                SessionEvent::DealEnvelope(vec![]),
                &[EventSource::Exchange][..],
            ),
            (
                SessionEvent::DealVerificationAttested(vec![]),
                &[EventSource::LocalRuntime][..],
            ),
            (
                SessionEvent::AcceptedDealSignature {
                    role: Role::Alice,
                    signature: [0; 64],
                },
                &[EventSource::Exchange][..],
            ),
            (
                SessionEvent::DealRetrySignature {
                    next_attempt: 1,
                    role: Role::Alice,
                    signature: [0; 64],
                },
                &[EventSource::Exchange][..],
            ),
            (
                SessionEvent::DescriptorSignature {
                    role: Role::Alice,
                    descriptor: vec![],
                    signature: [0; 64],
                },
                &[EventSource::Exchange][..],
            ),
            (
                SessionEvent::GraphPrepared(vec![]),
                &[EventSource::LocalRuntime][..],
            ),
            (
                SessionEvent::ActivationAuthorized(vec![]),
                &[EventSource::Exchange, EventSource::LocalWallet][..],
            ),
            (
                SessionEvent::TipObserved(TipFact {
                    profile_id: [1; 32],
                    block: block(1, 1),
                }),
                &[EventSource::Chain][..],
            ),
            (
                SessionEvent::RuntimeAuthorized(vec![]),
                &[EventSource::LocalRuntime][..],
            ),
            (
                SessionEvent::SpendConfirmed(spend),
                &[EventSource::Chain][..],
            ),
            (
                SessionEvent::StateConfirmed(vec![]),
                &[EventSource::LocalRuntime][..],
            ),
        ];

        for (event, accepted_sources) in events_and_sources {
            for source in SOURCES {
                assert_eq!(
                    event_accepts_source(&event, source),
                    accepted_sources.contains(&source),
                    "wrong ingress policy for {event:?} from {source:?}"
                );
            }
        }
    }

    #[test]
    fn journal_link_policy_rejects_sequence_and_hash_discontinuities() {
        assert!(journal_link_is_contiguous(3, [7; 32], 3, [7; 32]));
        assert!(!journal_link_is_contiguous(3, [7; 32], 4, [7; 32]));
        assert!(!journal_link_is_contiguous(3, [7; 32], 3, [8; 32]));
    }
}
