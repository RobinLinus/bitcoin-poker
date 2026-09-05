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
        tagged_sha256(
            "DLOG52/onchain-origin/v1",
            &bitcoin::consensus::serialize(&self.origin),
        )
    }

    /// Derive the game context before constructing its root-bound score keys.
    ///
    /// # Errors
    ///
    /// Rejects invalid inputs or a mismatch with the verified protocol/transaction context.
    pub fn chain_id(&self, deal: &VerifiedAcceptedDeal) -> Result<[u8; 32], CompilerError> {
        let rules_hash = self.rules_hash()?;
        let config = deal.game_config();
        if config.rules_hash != rules_hash
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
