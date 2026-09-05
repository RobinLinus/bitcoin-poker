//! Small-value deployment profiles built from the generic chain compiler.

use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut};
use bp52_chain_bitcoin::{
    ClassFeePolicy, FeeError, FeePolicy, outpoint_consensus_bytes, validate_network_identity,
};
use bp52_chain_types::{
    AcceptedDeal, ChainGameDescriptor, RevealOrder, Role, TimeoutSettlementPolicy,
};

use crate::graph::LogicalGraphPlan;
use crate::materialize::{CompiledGraph, PreparedChainGraph};
use crate::oracle::CompiledGraphSummary;
use crate::{CompilerError, reference_compiler_id};

/// Exact role-local material required by one audited heads-up session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadsUpInventory {
    /// Alice score-certificate keys required by the graph.
    pub alice_lamport_keys: u32,
    /// Bob score-certificate keys required by the graph.
    pub bob_lamport_keys: u32,
    /// Opponent/predicate preauthorizations Alice exchanges before activation.
    pub alice_preauthorizations: u32,
    /// Opponent/predicate preauthorizations Bob exchanges before activation.
    pub bob_preauthorizations: u32,
    /// Live payout/timeout signatures Alice retains locally.
    pub alice_runtime_signatures: u32,
    /// Live payout/timeout signatures Bob retains locally.
    pub bob_runtime_signatures: u32,
    /// Deal-share preimages retained by each participant.
    pub deal_preimages_per_player: u8,
}

/// Role-local material inventory for the current fixed-limit profile.
pub type HeadsUpFixedLimitV1Inventory = HeadsUpInventory;

/// Executable two-player heads-up economics and exact graph inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadsUpProfile {
    /// Canonical chain descriptor wire version selected by this profile.
    pub chain_protocol_version: u16,
    /// Exact staging contribution required from each participant.
    pub deposit_per_player_sat: u64,
    /// Fee paid by the surrounding two-input origin-funding transaction.
    pub origin_funding_fee_sat: u64,
    /// Value of the jointly controlled pre-activation origin output.
    pub origin_value_sat: u64,
    /// Fee paid by the origin-to-gameplay-root activation transaction.
    pub activation_fee_sat: u64,
    /// Value tracked by the chain descriptor and its gameplay root.
    pub gameplay_root_value_sat: u64,
    /// Fixed-limit small blind.
    pub unit_sat: u64,
    /// Maximum total wagers on one street, including its opening bet.
    pub max_bets_per_street: u8,
    /// Poker stack assigned to each participant, excluding fee reserve.
    pub stack_per_player_sat: u64,
    /// Shared reserve covering every executable path in the pruned graph.
    pub fee_reserve_sat: u64,
    /// Relative block delay for every timeout class.
    pub csv_blocks: u16,
    /// Standard P2TR dust threshold at the audited dust relay feerate.
    pub dust_threshold_sat: u64,
    /// Assumed minimum relay feerate used for the absolute fees.
    pub relay_sat_per_vbyte: u64,
    /// Largest permitted betting transaction in virtual bytes.
    pub betting_vbytes: u64,
    /// Largest permitted reveal transaction in virtual bytes.
    pub reveal_vbytes: u64,
    /// Largest permitted Alice-showdown transaction in virtual bytes.
    pub alice_showdown_vbytes: u64,
    /// Largest permitted Bob-payout transaction in virtual bytes.
    pub bob_payout_vbytes: u64,
    /// Largest permitted timeout transaction in virtual bytes.
    pub timeout_vbytes: u64,
    /// Exact longest executed gameplay path after activation.
    pub maximum_path_length: u16,
    /// Exact maximum fee consumed by an executed gameplay path.
    pub maximum_path_fee_sat: u64,
    /// Exact logical-node count in the pruned graph.
    pub node_count: u32,
    /// Exact gameplay transaction-template count in the pruned graph.
    pub transaction_count: u32,
    /// Exact inventory when Alice is the button and preflop actor.
    pub alice_button_inventory: HeadsUpInventory,
    /// Exact inventory when Bob is the button and preflop actor.
    pub bob_button_inventory: HeadsUpInventory,
}

/// Current fixed-limit profile type.
pub type HeadsUpFixedLimitV1Profile = HeadsUpProfile;

/// Session-specific inputs shared by audited heads-up profiles.
///
/// Economics, timeout, fee-policy, and compiler fields are filled by
/// [`HeadsUpProfile::descriptor`]. Exact consensus-domain and Bitcoin
/// parameter-family identities remain deployment/session inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadsUpSession {
    /// Exact descriptor consensus-domain identifier.
    pub network_id: [u8; 32],
    /// Bitcoin transaction/address parameter family for this deployment.
    pub bitcoin_network: Network,
    /// Mutually signed, archive-verified deal certificate.
    pub deal: AcceptedDeal,
    /// Jointly controlled origin output committed by the accepted deal.
    pub funding_outpoint: OutPoint,
    /// Session nonce used when deriving the deal's game identifier.
    pub deal_session_nonce: [u8; 32],
    /// Canonical Alice x-only identity key.
    pub alice_xonly_pk: [u8; 32],
    /// Canonical Bob x-only identity key.
    pub bob_xonly_pk: [u8; 32],
    /// Dealer/button role; this participant posts the small blind.
    pub button: Role,
    /// Session-selected first revealer for each community street.
    pub reveal_order: RevealOrder,
    /// Recipient of an odd satoshi in a split pot.
    pub split_remainder_recipient: Role,
}

/// Session-specific inputs for the current fixed-limit profile.
pub type HeadsUpFixedLimitV1Session = HeadsUpSession;

/// Audited 100/200-satoshi heads-up fixed-limit profile.
///
/// Each participant contributes 27,000 satoshis and plays a 20,000-satoshi
/// stack: exactly 100 big blinds. The remaining 13,000 satoshis fund every
/// gameplay path: the exhaustive worst case consumes 12,556 satoshis, leaving
/// 444 satoshis. Every intermediate and terminal output remains above dust.
/// Each street permits the complete protocol limit of four wagers.
pub const HEADS_UP_FIXED_LIMIT_V1_PROFILE: HeadsUpFixedLimitV1Profile = HeadsUpProfile {
    chain_protocol_version: bp52_chain_types::CHAIN_PROTOCOL_VERSION,
    deposit_per_player_sat: 27_000,
    origin_funding_fee_sat: 500,
    origin_value_sat: 53_500,
    activation_fee_sat: 500,
    gameplay_root_value_sat: 53_000,
    unit_sat: 100,
    max_bets_per_street: bp52_chain_types::MAX_BETS_PER_STREET,
    stack_per_player_sat: 20_000,
    fee_reserve_sat: 13_000,
    csv_blocks: 144,
    dust_threshold_sat: 330,
    relay_sat_per_vbyte: 1,
    betting_vbytes: 224,
    reveal_vbytes: 264,
    alice_showdown_vbytes: 2_203,
    bob_payout_vbytes: 3_089,
    timeout_vbytes: 232,
    maximum_path_length: 33,
    maximum_path_fee_sat: 12_556,
    node_count: 56_132,
    transaction_count: 56_131,
    alice_button_inventory: HeadsUpInventory {
        alice_lamport_keys: 1,
        bob_lamport_keys: 1,
        alice_preauthorizations: 24_877,
        bob_preauthorizations: 14_671,
        alice_runtime_signatures: 8_930,
        bob_runtime_signatures: 24_239,
        deal_preimages_per_player: 9,
    },
    bob_button_inventory: HeadsUpInventory {
        alice_lamport_keys: 1,
        bob_lamport_keys: 1,
        alice_preauthorizations: 24_877,
        bob_preauthorizations: 14_671,
        alice_runtime_signatures: 8_930,
        bob_runtime_signatures: 24_239,
        deal_preimages_per_player: 9,
    },
};

impl HeadsUpProfile {
    /// Wrap a session's jointly controlled script in the exact origin value.
    ///
    /// This does not establish joint control or prove that the output exists;
    /// those remain origin-protocol and backend responsibilities.
    #[must_use]
    pub fn origin_output(self, script_pubkey: ScriptBuf) -> TxOut {
        TxOut {
            value: Amount::from_sat(self.origin_value_sat),
            script_pubkey,
        }
    }

    /// Build the unsigned chain descriptor without duplicating profile values.
    ///
    /// The returned value still requires both chain-descriptor signatures and
    /// normal [`bp52_chain_types::verify_signed_chain_descriptor`] validation.
    /// The accepted deal must already bind the same network, outpoint,
    /// identities, and nonce supplied here.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed fee schedule cannot be represented or the
    /// resulting descriptor no longer matches this named profile.
    pub fn descriptor(self, session: HeadsUpSession) -> Result<ChainGameDescriptor, CompilerError> {
        validate_network_identity(session.network_id, session.bitcoin_network)?;
        let descriptor = ChainGameDescriptor {
            chain_protocol_version: self.chain_protocol_version,
            deal: session.deal,
            network_id: session.network_id,
            funding_outpoint: outpoint_consensus_bytes(session.funding_outpoint),
            deal_session_nonce: session.deal_session_nonce,
            alice_xonly_pk: session.alice_xonly_pk,
            bob_xonly_pk: session.bob_xonly_pk,
            button: session.button,
            unit_sat: self.unit_sat,
            max_bets_per_street: self.max_bets_per_street,
            alice_starting_stack_sat: self.stack_per_player_sat,
            bob_starting_stack_sat: self.stack_per_player_sat,
            fee_reserve_sat: self.fee_reserve_sat,
            action_csv: self.csv_blocks,
            reveal_csv: self.csv_blocks,
            showdown_csv: self.csv_blocks,
            reveal_order: session.reveal_order,
            timeout_policy: TimeoutSettlementPolicy::PotOnly,
            split_remainder_recipient: session.split_remainder_recipient,
            fee_policy_id: self.fee_policy()?.policy_id(),
            compiler_id: self.compiler_id(),
        };
        self.validate_descriptor(&descriptor)?;
        Ok(descriptor)
    }

    /// Return every exact role-local count for the selected button.
    #[must_use]
    pub const fn inventory(self, button: Role) -> HeadsUpInventory {
        match button {
            Role::Alice => self.alice_button_inventory,
            Role::Bob => self.bob_button_inventory,
        }
    }

    /// Return the exact number of Lamport score keys required from one role.
    #[must_use]
    pub const fn lamport_key_count(self, button: Role, role: Role) -> u32 {
        let inventory = self.inventory(button);
        match role {
            Role::Alice => inventory.alice_lamport_keys,
            Role::Bob => inventory.bob_lamport_keys,
        }
    }

    /// Return the exact opponent/predicate preauthorization count for one role.
    #[must_use]
    pub const fn preauthorization_count(self, button: Role, role: Role) -> u32 {
        let inventory = self.inventory(button);
        match role {
            Role::Alice => inventory.alice_preauthorizations,
            Role::Bob => inventory.bob_preauthorizations,
        }
    }

    /// Return the exact locally retained live-signature count for one role.
    #[must_use]
    pub const fn runtime_signature_count(self, button: Role, role: Role) -> u32 {
        let inventory = self.inventory(button);
        match role {
            Role::Alice => inventory.alice_runtime_signatures,
            Role::Bob => inventory.bob_runtime_signatures,
        }
    }

    /// Builds the exact class-specific absolute-fee policy.
    ///
    /// # Errors
    ///
    /// Returns an arithmetic error only if the compile-time profile constants
    /// cease to form a valid policy.
    pub fn fee_policy(self) -> Result<ClassFeePolicy, FeeError> {
        ClassFeePolicy::new(
            self.betting_vbytes
                .checked_mul(self.relay_sat_per_vbyte)
                .ok_or(FeeError::ArithmeticOverflow)?,
            self.reveal_vbytes
                .checked_mul(self.relay_sat_per_vbyte)
                .ok_or(FeeError::ArithmeticOverflow)?,
            self.alice_showdown_vbytes
                .checked_mul(self.relay_sat_per_vbyte)
                .ok_or(FeeError::ArithmeticOverflow)?,
            self.bob_payout_vbytes
                .checked_mul(self.relay_sat_per_vbyte)
                .ok_or(FeeError::ArithmeticOverflow)?,
            self.timeout_vbytes
                .checked_mul(self.relay_sat_per_vbyte)
                .ok_or(FeeError::ArithmeticOverflow)?,
            self.dust_threshold_sat,
        )
    }

    /// Return the compiler identifier bound by this profile.
    #[must_use]
    pub fn compiler_id(self) -> [u8; 32] {
        reference_compiler_id()
    }

    /// Fully validates an unsigned chain descriptor and checks that it selects
    /// this exact deployment profile before either participant signs it.
    ///
    /// Button, reveal order, split-remainder recipient, identities, deal, and
    /// funding outpoint remain session inputs and are intentionally not fixed.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed profile error on the first incompatible field.
    pub fn validate_descriptor(
        self,
        descriptor: &ChainGameDescriptor,
    ) -> Result<(), CompilerError> {
        bp52_chain_types::validate_chain_descriptor(descriptor)?;
        let policy = self.fee_policy()?;
        if descriptor.network_id == [0; 32] {
            return Err(profile_mismatch("descriptor network identifier is zero"));
        }
        if descriptor.chain_protocol_version != self.chain_protocol_version
            || descriptor.unit_sat != self.unit_sat
            || descriptor.max_bets_per_street != self.max_bets_per_street
            || descriptor.alice_starting_stack_sat != self.stack_per_player_sat
            || descriptor.bob_starting_stack_sat != self.stack_per_player_sat
            || descriptor.fee_reserve_sat != self.fee_reserve_sat
        {
            return Err(profile_mismatch(
                "descriptor amounts or betting cap differ from the selected heads-up profile",
            ));
        }
        if descriptor.total_locked_value()? != self.gameplay_root_value_sat {
            return Err(profile_mismatch(
                "descriptor does not fund the exact gameplay root",
            ));
        }
        if descriptor.action_csv != self.csv_blocks
            || descriptor.reveal_csv != self.csv_blocks
            || descriptor.showdown_csv != self.csv_blocks
        {
            return Err(profile_mismatch(
                "descriptor timeout delay differs from the selected heads-up profile",
            ));
        }
        if descriptor.timeout_policy != TimeoutSettlementPolicy::PotOnly {
            return Err(profile_mismatch(
                "descriptor does not use pot-only timeout settlement",
            ));
        }
        if descriptor.fee_policy_id != policy.policy_id() {
            return Err(profile_mismatch(
                "descriptor fee policy differs from the selected heads-up profile",
            ));
        }
        if descriptor.compiler_id != self.compiler_id() {
            return Err(profile_mismatch(
                "descriptor compiler differs from the audited profile",
            ));
        }
        Ok(())
    }

    /// Validate a prepared graph and return its exact gameplay-root output.
    ///
    /// The output script commits to the session-specific descriptor, deal,
    /// Lamport keys, graph, and hidden logical state; callers must not attempt
    /// to construct it from profile constants.
    ///
    /// # Errors
    ///
    /// Rejects a descriptor, origin value, root value, fee, graph shape, or
    /// score-key inventory that differs from this named profile.
    pub fn gameplay_root_output(
        self,
        prepared: &PreparedChainGraph,
    ) -> Result<&TxOut, CompilerError> {
        self.validate_prepared_graph(prepared)?;
        Ok(prepared.expected_root_state_output())
    }

    /// Construct the exact origin-to-root activation transaction template.
    ///
    /// # Errors
    ///
    /// Rejects any prepared graph outside this profile or an activation shape
    /// that cannot be represented by the generic transaction backend.
    pub fn activation_template(
        self,
        prepared: &PreparedChainGraph,
    ) -> Result<bp52_chain_bitcoin::TransactionTemplate, CompilerError> {
        self.validate_prepared_graph(prepared)?;
        prepared.canonical_activation_template()
    }

    /// Validate every public inventory count and economic parameter after
    /// activation and descendant materialization.
    ///
    /// # Errors
    ///
    /// Rejects any graph, fee, value, or inventory deviation from the named
    /// profile.
    pub fn validate_compiled_graph(self, graph: &CompiledGraph) -> Result<(), CompilerError> {
        self.validate_descriptor(graph.descriptor())?;
        self.validate_plan(graph.descriptor().button, graph.logical_plan())?;
        if graph.origin_output().value.to_sat() != self.origin_value_sat
            || graph.root_state_output().value.to_sat() != self.gameplay_root_value_sat
            || graph.activation_template().fee_sat() != self.activation_fee_sat
        {
            return Err(profile_mismatch(
                "materialized origin, root, or activation fee differs from the selected heads-up profile",
            ));
        }
        let inventory = self.inventory(graph.descriptor().button);
        if graph.signature_requests(Role::Alice).len()
            != usize_from_u32(inventory.alice_preauthorizations)?
            || graph.signature_requests(Role::Bob).len()
                != usize_from_u32(inventory.bob_preauthorizations)?
            || graph.runtime_signature_requests(Role::Alice).len()
                != usize_from_u32(inventory.alice_runtime_signatures)?
            || graph.runtime_signature_requests(Role::Bob).len()
                != usize_from_u32(inventory.bob_runtime_signatures)?
        {
            return Err(profile_mismatch(
                "materialized signature inventory differs from the selected heads-up profile",
            ));
        }
        Ok(())
    }

    /// Validate the compact result of the streaming graph compiler.
    ///
    /// # Errors
    ///
    /// Rejects any descriptor, manifest count, value, fee, path-length, or
    /// signature inventory deviation from the selected profile.
    pub fn validate_graph_summary(
        self,
        summary: &CompiledGraphSummary,
    ) -> Result<(), CompilerError> {
        self.validate_descriptor(summary.descriptor())?;
        let inventory = self.inventory(summary.descriptor().button);
        if summary.origin_output().value.to_sat() != self.origin_value_sat
            || summary.root_state_output().value.to_sat() != self.gameplay_root_value_sat
            || summary.activation_template().fee_sat() != self.activation_fee_sat
            || summary.manifest().node_count != self.node_count
            || summary.manifest().transaction_count != self.transaction_count
            || summary.manifest().maximum_path_length != self.maximum_path_length
            || summary.preauthorization_count(Role::Alice) != inventory.alice_preauthorizations
            || summary.preauthorization_count(Role::Bob) != inventory.bob_preauthorizations
            || summary.runtime_signature_count(Role::Alice) != inventory.alice_runtime_signatures
            || summary.runtime_signature_count(Role::Bob) != inventory.bob_runtime_signatures
            || summary.lamport_count(Role::Alice) != inventory.alice_lamport_keys
            || summary.lamport_count(Role::Bob) != inventory.bob_lamport_keys
        {
            return Err(profile_mismatch(
                "streamed graph summary differs from the selected heads-up profile",
            ));
        }
        Ok(())
    }

    fn validate_prepared_graph(self, prepared: &PreparedChainGraph) -> Result<(), CompilerError> {
        self.validate_descriptor(prepared.descriptor())?;
        self.validate_plan(prepared.descriptor().button, prepared.logical_plan())?;
        if prepared.origin_output().value.to_sat() != self.origin_value_sat
            || prepared.expected_root_state_output().value.to_sat() != self.gameplay_root_value_sat
            || prepared.activation_fee_sat() != self.activation_fee_sat
        {
            return Err(profile_mismatch(
                "prepared origin, root, or activation fee differs from the selected heads-up profile",
            ));
        }
        Ok(())
    }

    fn validate_plan(self, button: Role, plan: &LogicalGraphPlan) -> Result<(), CompilerError> {
        let inventory = self.inventory(button);
        if plan.nodes.len() != usize_from_u32(self.node_count)?
            || plan.transaction_count() != usize_from_u32(self.transaction_count)?
            || plan.maximum_path_length != self.maximum_path_length
            || plan.maximum_path_fee_sat != self.maximum_path_fee_sat
            || plan.expected_alice_lamport.len() != usize_from_u32(inventory.alice_lamport_keys)?
            || plan.expected_bob_lamport.len() != usize_from_u32(inventory.bob_lamport_keys)?
        {
            return Err(profile_mismatch(
                "compiled graph shape or Lamport inventory differs from the selected heads-up profile",
            ));
        }
        Ok(())
    }
}

const fn profile_mismatch(reason: &'static str) -> CompilerError {
    CompilerError::ProfileMismatch { reason }
}

fn usize_from_u32(value: u32) -> Result<usize, CompilerError> {
    usize::try_from(value).map_err(|_| profile_mismatch("profile count exceeds usize"))
}

#[cfg(test)]
mod tests {
    use bp52_chain_bitcoin::{FeeClass, FeePolicy};
    use bp52_chain_types::{AuthorizationPolicy, RevealOrder, Role};

    use super::HEADS_UP_FIXED_LIMIT_V1_PROFILE;
    use crate::{graph::compile_logical_graph_descriptor, test_support::descriptor_fixture};

    #[test]
    fn fixed_limit_profile_economics_are_exact_and_deep_enough()
    -> Result<(), Box<dyn std::error::Error>> {
        let profile = HEADS_UP_FIXED_LIMIT_V1_PROFILE;
        assert_eq!(profile.deposit_per_player_sat, 27_000);
        assert_eq!(profile.origin_value_sat, 53_500);
        assert_eq!(profile.gameplay_root_value_sat, 53_000);
        assert_eq!(
            2 * profile.deposit_per_player_sat - profile.origin_funding_fee_sat,
            profile.origin_value_sat
        );
        assert_eq!(
            profile.origin_value_sat - profile.activation_fee_sat,
            profile.gameplay_root_value_sat
        );
        assert_eq!(profile.unit_sat, 100);
        assert_eq!(
            profile.max_bets_per_street,
            bp52_chain_types::MAX_BETS_PER_STREET
        );
        assert_eq!(profile.stack_per_player_sat, 20_000);
        assert_eq!(profile.fee_reserve_sat, 13_000);
        assert_eq!(profile.stack_per_player_sat, 100 * 2 * profile.unit_sat);
        assert_eq!(
            2 * profile.stack_per_player_sat + profile.fee_reserve_sat,
            profile.gameplay_root_value_sat
        );

        let fees = profile.fee_policy()?;
        let longest_showdown_path = 2 * fees.fee_for(FeeClass::Reveal)?
            + 23 * fees.fee_for(FeeClass::Betting)?
            + 6 * fees.fee_for(FeeClass::Reveal)?
            + fees.fee_for(FeeClass::AliceShowdown)?
            + fees.fee_for(FeeClass::BobPayout)?;
        assert_eq!(longest_showdown_path, profile.maximum_path_fee_sat);
        assert_eq!(profile.fee_reserve_sat - longest_showdown_path, 444);
        Ok(())
    }

    #[test]
    #[ignore = "exhaustive 56,132-node profile campaign"]
    fn fixed_limit_profile_exhaustively_matches_graph_and_inventory()
    -> Result<(), Box<dyn std::error::Error>> {
        let profile = HEADS_UP_FIXED_LIMIT_V1_PROFILE;
        let policy = profile.fee_policy()?;
        for button in [Role::Alice, Role::Bob] {
            for flop_first in [Role::Alice, Role::Bob] {
                for turn_first in [Role::Alice, Role::Bob] {
                    for river_first in [Role::Alice, Role::Bob] {
                        let mut descriptor = descriptor_fixture()?;
                        descriptor.chain_protocol_version = profile.chain_protocol_version;
                        descriptor.button = button;
                        descriptor.unit_sat = profile.unit_sat;
                        descriptor.max_bets_per_street = profile.max_bets_per_street;
                        descriptor.alice_starting_stack_sat = profile.stack_per_player_sat;
                        descriptor.bob_starting_stack_sat = profile.stack_per_player_sat;
                        descriptor.fee_reserve_sat = profile.fee_reserve_sat;
                        descriptor.action_csv = profile.csv_blocks;
                        descriptor.reveal_csv = profile.csv_blocks;
                        descriptor.showdown_csv = profile.csv_blocks;
                        descriptor.reveal_order = RevealOrder {
                            flop_first,
                            turn_first,
                            river_first,
                        };
                        descriptor.fee_policy_id = policy.policy_id();
                        descriptor.compiler_id = profile.compiler_id();
                        profile.validate_descriptor(&descriptor)?;
                        let plan = compile_logical_graph_descriptor(
                            &descriptor,
                            &descriptor.deal,
                            &policy,
                        )?;
                        profile.validate_plan(button, &plan)?;
                        let mut preauthorizations = [0_u32; 2];
                        for edge in plan.nodes.iter().flat_map(|node| &node.edges) {
                            let owner = match edge.authorization {
                                AuthorizationPolicy::BothPresigned => {
                                    return Err(
                                        "fixed-limit profile contains a both-presigned edge".into(),
                                    );
                                }
                                AuthorizationPolicy::BettingAction { .. } => continue,
                                AuthorizationPolicy::RevealPreimages { revealer } => {
                                    revealer.other()
                                }
                                AuthorizationPolicy::AliceScore => Role::Bob,
                                AuthorizationPolicy::BobLivePayout => Role::Alice,
                                AuthorizationPolicy::Timeout { beneficiary } => beneficiary.other(),
                            };
                            preauthorizations[usize::from(owner == Role::Bob)] += 1;
                        }
                        let inventory = profile.inventory(button);
                        assert_eq!(
                            preauthorizations,
                            [
                                inventory.alice_preauthorizations,
                                inventory.bob_preauthorizations,
                            ]
                        );
                        assert_eq!(
                            preauthorizations.into_iter().sum::<u32>()
                                + plan
                                    .nodes
                                    .iter()
                                    .flat_map(|node| &node.edges)
                                    .filter(|edge| matches!(
                                        edge.authorization,
                                        AuthorizationPolicy::BettingAction { .. }
                                    ))
                                    .count() as u32,
                            plan.transaction_count() as u32
                        );
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn profile_vbyte_ceilings_cover_maximum_witness_shapes() {
        let profile = HEADS_UP_FIXED_LIMIT_V1_PROFILE;
        assert_eq!(vsize(137, &[64, 64, 111, 97]), 223);
        assert_eq!(
            vsize(94, &[64, 64, 67, 67, 67, 243, 97]),
            profile.reveal_vbytes
        );

        let mut alice = maximum_score_certificate();
        alice.extend([64, 64]);
        alice.extend([1; 16]);
        alice.push(1);
        alice.extend([67; 14]);
        alice.extend([6_371, 97]);
        assert_eq!(vsize(94, &alice), profile.alice_showdown_vbytes);

        let mut bob = maximum_score_certificate();
        bob.extend(maximum_score_certificate());
        bob.extend([64, 64]);
        bob.extend([1; 16]);
        bob.push(1);
        bob.extend([67; 14]);
        bob.extend([8_863, 129]);
        assert_eq!(vsize(137, &bob), profile.bob_payout_vbytes);

        assert_eq!(vsize(137, &[64, 64, 116, 129]), profile.timeout_vbytes);
        assert!(profile.betting_vbytes > 223);
    }

    fn maximum_score_certificate() -> Vec<u64> {
        let mut elements = vec![4];
        for _ in 0..24 {
            elements.extend([32, 1]);
        }
        elements
    }

    fn vsize(stripped_bytes: u64, witness_elements: &[u64]) -> u64 {
        let witness_bytes = 2
            + compact_size(u64::try_from(witness_elements.len()).unwrap_or(u64::MAX))
            + witness_elements
                .iter()
                .map(|length| compact_size(*length) + length)
                .sum::<u64>();
        (stripped_bytes * 4 + witness_bytes).div_ceil(4)
    }

    const fn compact_size(value: u64) -> u64 {
        if value < 253 {
            1
        } else if value <= u16::MAX as u64 {
            3
        } else if value <= u32::MAX as u64 {
            5
        } else {
            9
        }
    }
}
