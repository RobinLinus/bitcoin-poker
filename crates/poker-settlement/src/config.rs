//! Authenticated settlement configuration.
use crate::settlement::{
    CompilerError, Hash, HashSet, Network, OutPoint, PokerRules, VerifiedAcceptedDeal,
    XOnlyPublicKey, accepted_body_hash, invalid, tagged_sha256, validate_network_identity,
};

/// Pre-deal application parameters committed by the authenticated rules hash.
#[derive(Clone, Debug)]
pub struct SettlementConfig {
    /// Regtest or Signet address/transaction family.
    pub network: Network,
    /// Genesis identifier, or full-challenge-bound custom Signet identifier.
    pub network_id: [u8; 32],
    /// Pre-existing origin escrow, not the later gameplay root.
    pub origin: OutPoint,
    /// Optional fresh next-hand context for dealing before the final funding outpoint exists.
    pub predeal_anchor: Option<[u8; 32]>,
    /// Poker amounts and deadlines.
    pub rules: PokerRules,
    /// Exact fee policy identifier.
    pub fee_policy_id: [u8; 32],
    /// Opponent-controlled adaptor authorizers indexed by revealer then slot.
    pub reveal_keys: [[[u8; 32]; 9]; 2],
}

impl SettlementConfig {
    /// Commit every pre-deal parameter using a fixed-width, versioned encoding.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn rules_hash(&self) -> Result<[u8; 32], CompilerError> {
        self.rules.validate()?;
        if !matches!(self.network, Network::Regtest | Network::Signet) {
            return Err(invalid("dlog on-chain profile requires regtest or Signet"));
        }
        validate_network_identity(self.network_id, self.network)?;
        if self.origin.is_null() || self.fee_policy_id == [0; 32] {
            return Err(invalid("missing dlog funding or fee binding"));
        }
        let r = self.rules;
        let mut bytes = self.network_id.to_vec();
        bytes.extend(bitcoin::consensus::serialize(&self.origin));
        bytes.extend(self.fee_policy_id);
        bytes.extend([
            r.button.code(),
            r.max_bets_per_street,
            r.reveal_order.flop_first.code(),
            r.reveal_order.turn_first.code(),
            r.reveal_order.river_first.code(),
            r.timeout_policy.code(),
            r.split_remainder_recipient.code(),
        ]);
        for value in [
            r.unit_sat,
            r.alice_starting_stack_sat,
            r.bob_starting_stack_sat,
            r.fee_reserve_sat,
        ] {
            bytes.extend(value.to_le_bytes());
        }
        for value in [r.action_csv, r.reveal_csv, r.showdown_csv] {
            bytes.extend(value.to_le_bytes());
        }
        let mut seen = HashSet::new();
        for role in self.reveal_keys {
            for key in role {
                XOnlyPublicKey::from_slice(&key)
                    .map_err(|_| invalid("invalid dlog reveal authorizer"))?;
                if !seen.insert(key) {
                    return Err(invalid("reused dlog reveal authorizer"));
                }
                bytes.extend(key);
            }
        }
        Ok(tagged_sha256("DLOG52/onchain-poker-rules/v1", &bytes))
    }

    /// Session anchor binds dealing to the already-known escrow outpoint.
    #[must_use]
    pub fn session_anchor(&self) -> [u8; 32] {
        if let Some(anchor) = self.predeal_anchor {
            return tagged_sha256("DLOG52/onchain-predeal/v1", &anchor);
        }
        tagged_sha256(
            "DLOG52/onchain-origin/v1",
            &bitcoin::consensus::serialize(&self.origin),
        )
    }

    /// Bind the deck to a fresh hand and static rules. The settlement context
    /// binds funding, total value and fee policy; terminal signatures bind the
    /// exact balance split for reusable deep-stack future hands.
    pub fn dealing_rules_hash(&self) -> Result<[u8; 32], CompilerError> {
        if self.predeal_anchor.is_none() {
            return self.rules_hash();
        }
        if self.predeal_anchor == Some([0; 32]) {
            return Err(invalid("missing predeal anchor"));
        }
        let mut normalized = self.clone();
        normalized.predeal_anchor = None;
        normalized.origin = OutPoint::new(bitcoin::Txid::from_byte_array([1; 32]), 0);
        normalized.fee_policy_id = [1; 32];
        normalized.rules.alice_starting_stack_sat = 20_000;
        normalized.rules.bob_starting_stack_sat = 20_000;
        normalized.rules.fee_reserve_sat = 45_000;
        Ok(tagged_sha256(
            "DLOG52/onchain-predeal-rules/v1",
            &normalized.rules_hash()?,
        ))
    }

    /// Both seats can cover every capped wager without triggering an all-in.
    pub fn balance_independent(&self) -> Result<bool, CompilerError> {
        self.rules.validate()?;
        let maximum = self.rules.unit_sat.checked_mul(12)
            .and_then(|v| v.checked_mul(u64::from(self.rules.max_bets_per_street)))
            .ok_or_else(|| invalid("maximum wager overflow"))?;
        Ok(self.rules.alice_starting_stack_sat > maximum
            && self.rules.bob_starting_stack_sat > maximum)
    }

    /// Derive the game context before constructing its root-bound score keys.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn chain_id(&self, deal: &VerifiedAcceptedDeal) -> Result<[u8; 32], CompilerError> {
        // Deep-stack future hands share topology and total locked value. The exact
        // split is authorized by terminal transaction signatures at handover.
        let mut context = self.clone();
        if self.predeal_anchor.is_some() && self.balance_independent()? {
            let total = self.rules.alice_starting_stack_sat + self.rules.bob_starting_stack_sat;
            context.rules.alice_starting_stack_sat = total / 2;
            context.rules.bob_starting_stack_sat = total - total / 2;
        }
        let rules_hash = context.rules_hash()?;
        let config = deal.game_config();
        if config.rules_hash != self.dealing_rules_hash()?
            || config.session_anchor != self.session_anchor()
            || config.network_genesis
                != bitcoin::blockdata::constants::genesis_block(self.network)
                    .block_hash()
                    .to_byte_array()
        {
            return Err(invalid(
                "dlog accepted deal does not bind these chain parameters",
            ));
        }
        let mut forbidden: HashSet<_> =
            [config.identity_a, config.identity_b].into_iter().collect();
        for slot in &deal.catalogue().keys {
            for point in slot {
                forbidden.insert(
                    dealer_protocol::point_xonly(point)
                        .map_err(|_| invalid("invalid dlog catalogue"))?,
                );
            }
        }
        if self
            .reveal_keys
            .iter()
            .flatten()
            .any(|key| forbidden.contains(key))
        {
            return Err(invalid(
                "reveal authorizer overlaps an identity or candidate key",
            ));
        }
        let mut bytes = accepted_body_hash(&deal.as_deal().body).to_vec();
        bytes.extend(rules_hash);
        Ok(tagged_sha256("DLOG52/onchain-poker-game/v1", &bytes))
    }
}
