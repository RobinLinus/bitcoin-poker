//! Fail-closed local funding-readiness report and authorization token.

use core::marker::PhantomData;

use bitcoin::Network;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash;
use bp52_chain_types::{
    ChainGameDescriptor, RevealOrder, Role, TimeoutKind, TimeoutSettlementPolicy, chain_game_id,
};
use bp52_lamport::LamportSecretKey;
use bp52_protocol::contribution::RetainedPreimages;

use crate::{
    CompilerError, GraphManifest, REFERENCE_MAX_PATH_LENGTH, REFERENCE_TOTAL_NODE_COUNT,
    REFERENCE_TRANSACTION_COUNT, exchange::PrivateRuntimeSignatureBundle,
};

/// One descriptor-bound timeout rule reported before funding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeoutRule {
    /// Obligation class.
    pub kind: TimeoutKind,
    /// Exact BIP68 block-height delay.
    pub csv: u16,
}

/// Precomputed runtime-signature class retained locally but never exchanged.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RuntimeSignatureKind {
    /// Bob selects and signs one exact branch-specific showdown payout.
    BobTerminalPayout,
    /// A nondefaulting beneficiary retains its half of a timeout authorization.
    /// The opponent's exact-template signature is exchanged before activation.
    Timeout,
}

/// Count of private retained signatures for one role and class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeSignatureIntent {
    /// Participant retaining the live signing capability.
    pub role: Role,
    /// Why these signatures must not be pre-exchanged.
    pub kind: RuntimeSignatureKind,
    /// Number of graph edges covered by this inventory row.
    pub count: u32,
}

/// Counts carried by a graph- and role-bound local runtime-material proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalRuntimeInventorySummary {
    role: Role,
    lamport_secret_keys: u32,
    retained_preimages: u8,
    runtime_signatures: u32,
}

impl LocalRuntimeInventorySummary {
    pub(crate) const fn verified(
        role: Role,
        lamport_secret_keys: u32,
        retained_preimages: u8,
        runtime_signatures: u32,
    ) -> Self {
        Self {
            role,
            lamport_secret_keys,
            retained_preimages,
            runtime_signatures,
        }
    }

    /// Return the local participant whose material was verified.
    #[must_use]
    pub const fn role(self) -> Role {
        self.role
    }

    /// Return `(fresh Lamport keys, retained preimages, private signatures)`.
    #[must_use]
    pub const fn counts(self) -> (u32, u8, u32) {
        (
            self.lamport_secret_keys,
            self.retained_preimages,
            self.runtime_signatures,
        )
    }
}

/// Opaque ownership proof for every role-local capability needed after funding.
///
/// The token intentionally implements neither `Clone` nor `Debug`. It keeps
/// the exact fresh Lamport keys, nine accepted share preimages, and verified
/// private runtime signatures alive for as long as a readiness report or
/// future funding capability borrows it. It does not precompute action
/// signatures; descriptor authentication establishes identity-key control,
/// and the runtime requests one signature only after an action is selected.
pub struct VerifiedLocalRuntimeInventory {
    pub(crate) chain_game_id: [u8; 32],
    pub(crate) graph_root: [u8; 32],
    pub(crate) role: Role,
    pub(crate) lamport_secret_keys: Vec<LamportSecretKey>,
    pub(crate) retained_preimages: RetainedPreimages,
    pub(crate) runtime_signatures: PrivateRuntimeSignatureBundle,
    pub(crate) runtime_signature_intents: Vec<RuntimeSignatureIntent>,
    pub(crate) summary: LocalRuntimeInventorySummary,
}

impl VerifiedLocalRuntimeInventory {
    /// Return the local role bound into this proof.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Return exact verified local-material counts.
    #[must_use]
    pub const fn summary(&self) -> LocalRuntimeInventorySummary {
        self.summary
    }

    /// Borrow the accepted local card-share preimages without copying them.
    #[must_use]
    pub const fn retained_preimages(&self) -> &RetainedPreimages {
        &self.retained_preimages
    }

    /// Borrow all fresh local one-time keys in canonical graph order.
    #[must_use]
    pub fn lamport_secret_keys(&self) -> &[LamportSecretKey] {
        &self.lamport_secret_keys
    }

    /// Borrow the graph-verified private runtime-signature owner.
    #[must_use]
    pub const fn private_runtime_signatures(&self) -> &PrivateRuntimeSignatureBundle {
        &self.runtime_signatures
    }

    /// Consume the proof and release its zeroizing owners for runtime use.
    ///
    /// Rust's borrow checker prevents this while a readiness report or
    /// `FundingReady` capability still borrows the proof.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Vec<LamportSecretKey>,
        RetainedPreimages,
        PrivateRuntimeSignatureBundle,
    ) {
        (
            self.lamport_secret_keys,
            self.retained_preimages,
            self.runtime_signatures,
        )
    }
}

/// Unresolved condition that forbids funding through the safe API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadinessBlocker {
    /// One or both roles supplied fewer valid preauthorizations than the exact request sets.
    MissingPreauthorizations {
        /// Required exact request count.
        required: u32,
        /// Successfully verified count.
        verified: u32,
    },
    /// One or both exact showdown predicates lack executable consensus script.
    ConsensusShowdownProgramsUnavailable,
    /// V1 does not define origin-escrow creation, two-party contribution and
    /// authorization, or the surrounding refund package.
    FundingConstructionUndefined,
    /// Real-funds construction is deliberately disabled.
    MainnetDisabled,
}

/// Human- and machine-readable funding gate report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FundingReadinessReport<'inventory> {
    /// Mutually agreed deterministic graph root.
    graph_root: [u8; 32],
    /// Corrected number of logical nodes including the gameplay root.
    node_count: u32,
    /// Corrected number of post-activation gameplay transactions.
    transaction_count: u32,
    /// Longest post-activation gameplay path to settlement.
    maximum_path_length: u16,
    /// Descriptor's complete funding value.
    total_locked_value_sat: u64,
    /// Dedicated fee reserve, never silently taken from poker stacks.
    fee_reserve_sat: u64,
    /// Action, reveal, and showdown timeouts in fixed order.
    timeouts: [TimeoutRule; 3],
    /// Independently signed first-revealer choice for every community street.
    reveal_order: RevealOrder,
    /// Signed timeout settlement policy; validated v1 reports always carry `PotOnly`.
    timeout_policy: TimeoutSettlementPolicy,
    /// Signatures from both roles verified against their exact BIP341 digests.
    verified_preauthorizations: u32,
    /// Complete number required from both roles.
    required_preauthorizations: u32,
    /// Bitcoin signatures intentionally retained for runtime branch control.
    runtime_signatures_not_exchanged: Vec<RuntimeSignatureIntent>,
    /// Exact verified role-local capability counts.
    local_runtime_inventory: LocalRuntimeInventorySummary,
    /// Conditions that keep the opaque funding token unavailable.
    blockers: Vec<ReadinessBlocker>,
    /// Prevent the report and any funding capability from outliving the owned
    /// local runtime material that was checked to create it.
    inventory_lifetime: PhantomData<&'inventory ()>,
}

impl FundingReadinessReport<'_> {
    /// Return whether the safe API may authorize non-mainnet funding.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.blockers.is_empty()
    }

    /// Return the mutually agreed graph root.
    #[must_use]
    pub const fn graph_root(&self) -> [u8; 32] {
        self.graph_root
    }

    /// Return `(nodes, post-activation gameplay transactions, maximum path)`.
    #[must_use]
    pub const fn graph_shape(&self) -> (u32, u32, u16) {
        (
            self.node_count,
            self.transaction_count,
            self.maximum_path_length,
        )
    }

    /// Return `(total locked value, dedicated fee reserve)` in satoshis.
    #[must_use]
    pub const fn funding_amounts(&self) -> (u64, u64) {
        (self.total_locked_value_sat, self.fee_reserve_sat)
    }

    /// Return action, reveal, and showdown timeout rules.
    #[must_use]
    pub const fn timeouts(&self) -> &[TimeoutRule; 3] {
        &self.timeouts
    }

    /// Return the signed community reveal order.
    #[must_use]
    pub const fn reveal_order(&self) -> RevealOrder {
        self.reveal_order
    }

    /// Return the signed pot-only timeout settlement policy.
    #[must_use]
    pub const fn timeout_policy(&self) -> TimeoutSettlementPolicy {
        self.timeout_policy
    }

    /// Return `(verified, required)` complete two-role signature counts.
    #[must_use]
    pub const fn preauthorizations(&self) -> (u32, u32) {
        (
            self.verified_preauthorizations,
            self.required_preauthorizations,
        )
    }

    /// Return live Bitcoin signature capabilities intentionally not exchanged.
    #[must_use]
    pub fn runtime_signatures_not_exchanged(&self) -> &[RuntimeSignatureIntent] {
        &self.runtime_signatures_not_exchanged
    }

    /// Return the role and exact counts proven by the local inventory token.
    #[must_use]
    pub const fn local_runtime_inventory(&self) -> LocalRuntimeInventorySummary {
        self.local_runtime_inventory
    }

    /// Return every unresolved funding blocker.
    #[must_use]
    pub fn blockers(&self) -> &[ReadinessBlocker] {
        &self.blockers
    }
}

/// Opaque proof that all locally checkable funding gates passed.
#[derive(Debug)]
pub struct FundingReady<'inventory> {
    report: FundingReadinessReport<'inventory>,
}

impl FundingReady<'_> {
    /// Borrow the immutable report that authorized funding.
    #[must_use]
    pub const fn report(&self) -> &FundingReadinessReport<'_> {
        &self.report
    }
}

/// Build the exact readiness report after graph and bundle verification.
///
/// `consensus_showdown_programs_available` must come from the finalized graph
/// materializer, not from an untrusted peer. It is explicit so the logical
/// graph remains testable while unsupported consensus predicates fail closed.
///
/// # Errors
///
/// Rejects descriptor/manifest/profile mismatches, impossible signature
/// counts, empty live-signature inventory, or arithmetic overflow.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_funding_readiness_report<'inventory>(
    descriptor: &ChainGameDescriptor,
    manifest: &GraphManifest,
    agreed_graph_root: [u8; 32],
    verified_preauthorizations: u32,
    required_preauthorizations: u32,
    expected_local_lamport_keys: u32,
    inventory: &'inventory VerifiedLocalRuntimeInventory,
    consensus_showdown_programs_available: bool,
) -> Result<FundingReadinessReport<'inventory>, CompilerError> {
    let actual_summary = LocalRuntimeInventorySummary::verified(
        inventory.role,
        u32::try_from(inventory.lamport_secret_keys.len()).map_err(|_| {
            CompilerError::LocalRuntimeInventoryMismatch {
                reason: "local Lamport key count exceeds readiness field width",
            }
        })?,
        u8::try_from(inventory.retained_preimages.len()).map_err(|_| {
            CompilerError::LocalRuntimeInventoryMismatch {
                reason: "local retained-preimage count exceeds readiness field width",
            }
        })?,
        u32::try_from(inventory.runtime_signatures.len()).map_err(|_| {
            CompilerError::LocalRuntimeInventoryMismatch {
                reason: "local runtime-signature count exceeds readiness field width",
            }
        })?,
    );
    if inventory.chain_game_id != manifest.chain_game_id
        || inventory.graph_root != manifest.graph_root
        || inventory.runtime_signatures.chain_game_id != manifest.chain_game_id
        || inventory.runtime_signatures.graph_root != manifest.graph_root
        || inventory.runtime_signatures.role != inventory.role
        || inventory.summary != actual_summary
    {
        return Err(CompilerError::LocalRuntimeInventoryMismatch {
            reason: "local inventory is bound to another game, graph, or role",
        });
    }
    let summary = actual_summary;
    build_funding_readiness_report_from_summary(
        descriptor,
        manifest,
        agreed_graph_root,
        verified_preauthorizations,
        required_preauthorizations,
        expected_local_lamport_keys,
        inventory.runtime_signature_intents.clone(),
        summary,
        consensus_showdown_programs_available,
        PhantomData,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_funding_readiness_report_from_summary<'inventory>(
    descriptor: &ChainGameDescriptor,
    manifest: &GraphManifest,
    agreed_graph_root: [u8; 32],
    verified_preauthorizations: u32,
    required_preauthorizations: u32,
    expected_local_lamport_keys: u32,
    runtime_signatures_not_exchanged: Vec<RuntimeSignatureIntent>,
    local_runtime_inventory: LocalRuntimeInventorySummary,
    consensus_showdown_programs_available: bool,
    inventory_lifetime: PhantomData<&'inventory ()>,
) -> Result<FundingReadinessReport<'inventory>, CompilerError> {
    bp52_chain_types::validate_chain_descriptor(descriptor)?;
    if manifest.chain_game_id != chain_game_id(descriptor)?
        || manifest.graph_root != agreed_graph_root
        || manifest.compiler_id != descriptor.compiler_id
        || manifest.fee_policy_id != descriptor.fee_policy_id
    {
        return Err(CompilerError::InvalidReadinessReport {
            reason: "manifest does not match descriptor and agreed graph root",
        });
    }
    if manifest.node_count == 0
        || manifest.transaction_count == 0
        || manifest.node_count.checked_sub(1) != Some(manifest.transaction_count)
        || usize::try_from(manifest.node_count)
            .map_or(true, |count| count > REFERENCE_TOTAL_NODE_COUNT)
        || usize::try_from(manifest.transaction_count)
            .map_or(true, |count| count > REFERENCE_TRANSACTION_COUNT)
        || manifest.maximum_path_length == 0
        || manifest.maximum_path_length > REFERENCE_MAX_PATH_LENGTH
    {
        return Err(CompilerError::ProfileMismatch {
            reason: "readiness manifest has an invalid descriptor-derived tree shape",
        });
    }
    if agreed_graph_root == [0; 32]
        || manifest.alice_lamport_bundle_root == [0; 32]
        || manifest.bob_lamport_bundle_root == [0; 32]
    {
        return Err(CompilerError::InvalidReadinessReport {
            reason: "readiness manifest contains a zero commitment",
        });
    }
    if verified_preauthorizations > required_preauthorizations {
        return Err(CompilerError::InvalidReadinessReport {
            reason: "verified preauthorization count exceeds the request set",
        });
    }
    if runtime_signatures_not_exchanged.is_empty()
        || runtime_signatures_not_exchanged.iter().any(|intent| {
            intent.count == 0
                || intent.role != local_runtime_inventory.role()
                || (intent.kind == RuntimeSignatureKind::BobTerminalPayout
                    && intent.role != Role::Bob)
        })
    {
        return Err(CompilerError::InvalidReadinessReport {
            reason: "runtime signature inventory is empty or contains a zero count",
        });
    }
    let (lamport_keys, retained_preimages, runtime_signatures) = local_runtime_inventory.counts();
    let expected_preimage_count = u8::try_from(bp52_protocol::N_SLOTS).map_err(|_| {
        CompilerError::InvalidReadinessReport {
            reason: "protocol preimage count exceeds readiness field width",
        }
    })?;
    let reported_runtime_signatures = runtime_signatures_not_exchanged
        .iter()
        .try_fold(0_u32, |count, intent| count.checked_add(intent.count));
    if retained_preimages != expected_preimage_count
        || reported_runtime_signatures != Some(runtime_signatures)
        || runtime_signatures == 0
        || expected_local_lamport_keys == 0
        || lamport_keys != expected_local_lamport_keys
    {
        return Err(CompilerError::InvalidReadinessReport {
            reason: "verified local runtime-material counts are inconsistent",
        });
    }

    let mut blockers = Vec::new();
    if verified_preauthorizations != required_preauthorizations {
        blockers.push(ReadinessBlocker::MissingPreauthorizations {
            required: required_preauthorizations,
            verified: verified_preauthorizations,
        });
    }
    if !consensus_showdown_programs_available {
        blockers.push(ReadinessBlocker::ConsensusShowdownProgramsUnavailable);
    }
    // Compiler profile v6 treats the descriptor outpoint as a pre-existing
    // origin and verifies one exact origin-to-root activation. That does not
    // establish how both players contributed and authorized their complete
    // stacks in the origin, nor define the surrounding refund package. Never
    // mint a funding capability until a ratified protocol defines those facts.
    blockers.push(ReadinessBlocker::FundingConstructionUndefined);
    if is_mainnet_genesis(descriptor.network_id) {
        blockers.push(ReadinessBlocker::MainnetDisabled);
    }

    Ok(FundingReadinessReport {
        graph_root: agreed_graph_root,
        node_count: manifest.node_count,
        transaction_count: manifest.transaction_count,
        maximum_path_length: manifest.maximum_path_length,
        total_locked_value_sat: descriptor.total_locked_value()?,
        fee_reserve_sat: descriptor.fee_reserve_sat,
        timeouts: [
            TimeoutRule {
                kind: TimeoutKind::Action,
                csv: descriptor.action_csv,
            },
            TimeoutRule {
                kind: TimeoutKind::Reveal,
                csv: descriptor.reveal_csv,
            },
            TimeoutRule {
                kind: TimeoutKind::Showdown,
                csv: descriptor.showdown_csv,
            },
        ],
        reveal_order: descriptor.reveal_order,
        timeout_policy: descriptor.timeout_policy,
        verified_preauthorizations,
        required_preauthorizations,
        runtime_signatures_not_exchanged,
        local_runtime_inventory,
        blockers,
        inventory_lifetime,
    })
}

/// Consume a complete report and mint the only safe funding capability.
///
/// # Errors
///
/// Returns [`CompilerError::FundingNotReady`] if any blocker remains.
pub fn authorize_funding(
    report: FundingReadinessReport<'_>,
) -> Result<FundingReady<'_>, CompilerError> {
    if report.is_ready() {
        Ok(FundingReady { report })
    } else {
        Err(CompilerError::FundingNotReady)
    }
}

fn is_mainnet_genesis(network_id: [u8; 32]) -> bool {
    network_id == genesis_block(Network::Bitcoin).block_hash().to_byte_array()
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use super::{
        LocalRuntimeInventorySummary, ReadinessBlocker, RuntimeSignatureIntent,
        RuntimeSignatureKind, authorize_funding, build_funding_readiness_report_from_summary,
    };
    use crate::{
        GraphManifest, REFERENCE_MAX_PATH_LENGTH, REFERENCE_TOTAL_NODE_COUNT,
        REFERENCE_TRANSACTION_COUNT, test_support::descriptor_fixture,
    };

    #[test]
    #[allow(clippy::too_many_lines)]
    fn readiness_is_fail_closed_until_every_gate_passes() -> Result<(), Box<dyn std::error::Error>>
    {
        let descriptor = descriptor_fixture()?;
        let graph_root = [0x71; 32];
        let manifest = GraphManifest {
            chain_game_id: bp52_chain_types::chain_game_id(&descriptor)?,
            graph_root,
            alice_lamport_bundle_root: [0x72; 32],
            bob_lamport_bundle_root: [0x73; 32],
            compiler_id: descriptor.compiler_id,
            fee_policy_id: descriptor.fee_policy_id,
            node_count: u32::try_from(REFERENCE_TOTAL_NODE_COUNT)?,
            transaction_count: u32::try_from(REFERENCE_TRANSACTION_COUNT)?,
            maximum_path_length: REFERENCE_MAX_PATH_LENGTH,
        };
        let intents = vec![RuntimeSignatureIntent {
            role: bp52_chain_types::Role::Bob,
            kind: RuntimeSignatureKind::BobTerminalPayout,
            count: 1,
        }];
        let summary = LocalRuntimeInventorySummary {
            role: bp52_chain_types::Role::Bob,
            lamport_secret_keys: u32::try_from(crate::REFERENCE_BOB_LAMPORT_ENTRIES)?,
            retained_preimages: u8::try_from(bp52_protocol::N_SLOTS)?,
            runtime_signatures: 1,
        };
        let blocked = build_funding_readiness_report_from_summary(
            &descriptor,
            &manifest,
            graph_root,
            9,
            10,
            summary.lamport_secret_keys,
            intents.clone(),
            summary,
            false,
            PhantomData,
        )?;
        assert_eq!(
            blocked.blockers,
            [
                ReadinessBlocker::MissingPreauthorizations {
                    required: 10,
                    verified: 9
                },
                ReadinessBlocker::ConsensusShowdownProgramsUnavailable,
                ReadinessBlocker::FundingConstructionUndefined,
            ]
        );
        assert!(authorize_funding(blocked).is_err());

        let funding_undefined = build_funding_readiness_report_from_summary(
            &descriptor,
            &manifest,
            graph_root,
            10,
            10,
            summary.lamport_secret_keys,
            intents,
            summary,
            true,
            PhantomData,
        )?;
        assert_eq!(
            funding_undefined.blockers,
            [ReadinessBlocker::FundingConstructionUndefined]
        );
        assert_eq!(
            funding_undefined.local_runtime_inventory().role(),
            bp52_chain_types::Role::Bob
        );
        assert_eq!(
            funding_undefined.local_runtime_inventory().counts(),
            (u32::try_from(crate::REFERENCE_BOB_LAMPORT_ENTRIES)?, 9, 1)
        );
        assert!(authorize_funding(funding_undefined).is_err());

        let wrong_role_intents = vec![RuntimeSignatureIntent {
            role: bp52_chain_types::Role::Alice,
            kind: RuntimeSignatureKind::Timeout,
            count: 1,
        }];
        assert!(
            build_funding_readiness_report_from_summary(
                &descriptor,
                &manifest,
                graph_root,
                10,
                10,
                summary.lamport_secret_keys,
                wrong_role_intents,
                summary,
                true,
                PhantomData,
            )
            .is_err()
        );

        let mut short_manifest = manifest;
        short_manifest.node_count = 100;
        short_manifest.transaction_count = 99;
        short_manifest.maximum_path_length = 12;
        let short_summary = LocalRuntimeInventorySummary {
            role: bp52_chain_types::Role::Bob,
            lamport_secret_keys: 17,
            retained_preimages: u8::try_from(bp52_protocol::N_SLOTS)?,
            runtime_signatures: 1,
        };
        let short_intents = vec![RuntimeSignatureIntent {
            role: bp52_chain_types::Role::Bob,
            kind: RuntimeSignatureKind::BobTerminalPayout,
            count: 1,
        }];
        let dynamic = build_funding_readiness_report_from_summary(
            &descriptor,
            &short_manifest,
            graph_root,
            10,
            10,
            17,
            short_intents.clone(),
            short_summary,
            true,
            PhantomData,
        )?;
        assert_eq!(dynamic.graph_shape(), (100, 99, 12));
        assert!(
            build_funding_readiness_report_from_summary(
                &descriptor,
                &short_manifest,
                graph_root,
                10,
                10,
                18,
                short_intents,
                short_summary,
                true,
                PhantomData,
            )
            .is_err()
        );
        Ok(())
    }
}
