//! Public deployment configuration shared by servers, browser adapters, and Wasm engines.

use bitcoin::Network;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash;
use http::Uri;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{BlockRef, ChainProfile};

/// Version of the browser deployment configuration schema.
pub const DEPLOYMENT_SCHEMA_VERSION: u16 = 2;
const JAVASCRIPT_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const DEPLOYMENT_DIGEST_TAG: &[u8] = b"BP52/browser-deployment/v1";

/// A deployment loaded from JSON by the application server.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentConfig {
    /// Configuration schema version.
    pub schema_version: u16,
    /// Stable lowercase deployment identifier used only for storage/display namespacing.
    pub deployment_id: String,
    /// Selected Rust protocol profile selected by this deployment.
    pub protocol_profile: ProtocolProfileName,
    /// Relay-facing browser configuration.
    pub relay: RelayBrowserConfig,
    /// Chain backend and consensus identity.
    pub chain: ChainDeploymentConfig,
    /// Public game and origin economics.
    pub game: GameDeploymentConfig,
}

impl DeploymentConfig {
    /// Validate public deployment settings, derive the challenge-bound profile identifier, and
    /// return the exact object served to browsers.
    ///
    /// # Errors
    ///
    /// Rejects unknown schema versions, malformed identifiers/hex, contradictory chain data,
    /// unsafe broadcast settings, invalid URLs, duplicate relay kinds, or inconsistent values.
    pub fn resolve_for_profile(
        &self,
        expected_profile: ProtocolProfileName,
        expected_game: &GameDeploymentConfig,
    ) -> Result<BrowserDeploymentConfig, DeploymentConfigError> {
        if self.schema_version != DEPLOYMENT_SCHEMA_VERSION
            || self.protocol_profile != ProtocolProfileName::HeadsUpFixedLimitV1
        {
            return Err(DeploymentConfigError::Invalid("unsupported schema version"));
        }
        validate_deployment_id(&self.deployment_id)?;
        if self.protocol_profile != expected_profile || &self.game != expected_game {
            return Err(DeploymentConfigError::Invalid(
                "deployment differs from the selected expected protocol profile",
            ));
        }
        self.relay.validate()?;
        self.game.validate()?;
        let (chain, chain_profile) = self.chain.resolve_browser_config()?;
        let mut resolved = BrowserDeploymentConfig {
            schema_version: self.schema_version,
            deployment_id: self.deployment_id.clone(),
            protocol_profile: self.protocol_profile,
            protocol_profile_code: self.protocol_profile.wasm_code(),
            deployment_digest_hex: String::new(),
            relay: self.relay.clone(),
            chain,
            game: self.game.clone(),
            chain_profile,
        };
        resolved.deployment_digest_hex = encode_hex(&resolved.deployment_digest());
        Ok(resolved)
    }

    /// Resolve only the chain configuration needed by diagnostic tools.
    ///
    /// This validates the schema version, deployment identifier, endpoint URLs,
    /// exact chain identity, confirmation policy, and the mainnet broadcast
    /// prohibition. It deliberately does not validate or authorize relay
    /// settings, protocol selection, or game economics; applications that use
    /// those terms must call [`Self::resolve_for_profile`] instead.
    ///
    /// # Errors
    ///
    /// Rejects malformed deployment identity or any unsafe/inconsistent chain
    /// configuration.
    pub fn resolve_chain_for_diagnostics(
        &self,
    ) -> Result<(BrowserChainConfig, ChainProfile), DeploymentConfigError> {
        if self.schema_version != DEPLOYMENT_SCHEMA_VERSION {
            return Err(DeploymentConfigError::Invalid("unsupported schema version"));
        }
        validate_deployment_id(&self.deployment_id)?;
        self.chain.resolve_browser_config()
    }
}

/// Selected protocol/economics bundle selected by an operator deployment.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProtocolProfileName {
    /// Four-street 100/200-satoshi fixed-limit profile with four wagers per street.
    HeadsUpFixedLimitV1,
}

impl ProtocolProfileName {
    const fn wasm_code(self) -> u8 {
        match self {
            Self::HeadsUpFixedLimitV1 => 1,
        }
    }
}

/// Browser-safe resolved deployment configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserDeploymentConfig {
    /// Configuration schema version.
    pub schema_version: u16,
    /// Stable deployment identifier.
    pub deployment_id: String,
    /// Selected protocol profile selector.
    pub protocol_profile: ProtocolProfileName,
    /// Stable selector consumed by the Rust/Wasm protocol boundaries.
    pub protocol_profile_code: u8,
    /// Canonical Rust digest binding every resolved public deployment term.
    pub deployment_digest_hex: String,
    /// Relay configuration and the single authoritative relay-kind table.
    pub relay: RelayBrowserConfig,
    /// Resolved chain configuration including the derived profile identifier.
    pub chain: BrowserChainConfig,
    /// Public game economics.
    pub game: GameDeploymentConfig,
    /// Validated Rust chain profile, omitted from browser JSON.
    #[serde(skip)]
    pub chain_profile: ChainProfile,
}

impl BrowserDeploymentConfig {
    fn deployment_digest(&self) -> [u8; 32] {
        let mut writer = DigestWriter::new();
        writer.u16(self.schema_version);
        writer.string(&self.deployment_id);
        writer.u8(self.protocol_profile.wasm_code());
        self.relay.write_digest(&mut writer);
        self.chain.write_digest(&mut writer);
        self.game.write_digest(&mut writer);
        writer.finish()
    }
}

/// Relay settings consumed by browser code.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayBrowserConfig {
    /// Same-origin API prefix.
    pub api_base_path: String,
    /// Short-poll cadence.
    pub poll_interval_ms: u32,
    /// HTTP request deadline.
    pub request_timeout_ms: u32,
    /// Largest base64 payload accepted by the browser relay client.
    pub max_payload_base64_bytes: u32,
    /// Canonical routing names.
    pub kinds: RelayKinds,
}

impl RelayBrowserConfig {
    /// Validate relay limits, route, and message-kind configuration.
    ///
    /// # Errors
    /// Rejects invalid bounds, paths, or duplicate kinds.
    pub fn validate(&self) -> Result<(), DeploymentConfigError> {
        if !self.api_base_path.starts_with('/') || self.api_base_path.ends_with('/') {
            return Err(DeploymentConfigError::Invalid(
                "relay API path is not canonical",
            ));
        }
        if self.poll_interval_ms == 0
            || self.request_timeout_ms == 0
            || self.max_payload_base64_bytes == 0
        {
            return Err(DeploymentConfigError::Invalid(
                "relay limits are inconsistent",
            ));
        }
        self.kinds.validate()
    }

    fn write_digest(&self, writer: &mut DigestWriter) {
        writer.string(&self.api_base_path);
        writer.u32(self.poll_interval_ms);
        writer.u32(self.request_timeout_ms);
        writer.u32(self.max_payload_base64_bytes);
        self.kinds.write_digest(writer);
    }
}

/// Canonical relay routing names. These are defined once in deployment JSON and checked in Rust.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayKinds {
    /// Seat-ready message.
    pub ready: String,
    /// Session nonce commitment.
    pub nonce_commit: String,
    /// Session nonce reveal.
    pub nonce_reveal: String,
    /// Session nonce agreement acknowledgement.
    pub nonce_ready: String,
    /// Confirmed staging-input announcement.
    pub staging_funding: String,
    /// Origin package agreement.
    pub origin_package: String,
    /// Origin refund signature.
    pub origin_refund_signature: String,
    /// Origin funding signature.
    pub origin_funding_signature: String,
    /// Public game reducer exchange.
    pub game_exchange: String,
    /// Secret chain runtime exchange.
    pub chain_exchange: String,
}

impl RelayKinds {
    fn validate(&self) -> Result<(), DeploymentConfigError> {
        let values = [
            &self.ready,
            &self.nonce_commit,
            &self.nonce_reveal,
            &self.nonce_ready,
            &self.staging_funding,
            &self.origin_package,
            &self.origin_refund_signature,
            &self.origin_funding_signature,
            &self.game_exchange,
            &self.chain_exchange,
        ];
        for (index, value) in values.iter().enumerate() {
            if value.is_empty()
                || value.len() > 32
                || !value.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'.'
                        || byte == b'-'
                })
            {
                return Err(DeploymentConfigError::Invalid(
                    "relay kind is not canonical",
                ));
            }
            if values[..index].contains(value) {
                return Err(DeploymentConfigError::Invalid("relay kinds must be unique"));
            }
        }
        Ok(())
    }

    fn write_digest(&self, writer: &mut DigestWriter) {
        for value in [
            &self.ready,
            &self.nonce_commit,
            &self.nonce_reveal,
            &self.nonce_ready,
            &self.staging_funding,
            &self.origin_package,
            &self.origin_refund_signature,
            &self.origin_funding_signature,
            &self.game_exchange,
            &self.chain_exchange,
        ] {
            writer.string(value);
        }
    }
}

/// Supported chain backend family.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ChainBackendName {
    /// Esplora-compatible HTTP API.
    Esplora,
}

/// Supported Bitcoin network encoding.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkName {
    /// Bitcoin mainnet.
    Bitcoin,
    /// Public testnet3.
    Testnet,
    /// A challenge-bound Signet.
    Signet,
    /// Local regtest.
    Regtest,
}

impl NetworkName {
    const fn bitcoin(self) -> Network {
        match self {
            Self::Bitcoin => Network::Bitcoin,
            Self::Testnet => Network::Testnet,
            Self::Signet => Network::Signet,
            Self::Regtest => Network::Regtest,
        }
    }

    const fn expected_hrp(self) -> &'static str {
        match self {
            Self::Bitcoin => "bc",
            Self::Testnet | Self::Signet => "tb",
            Self::Regtest => "bcrt",
        }
    }

    const fn bitcoin_wasm_code(self) -> u8 {
        match self {
            Self::Bitcoin => 0,
            Self::Testnet => 1,
            Self::Signet => 2,
            Self::Regtest => 3,
        }
    }

    const fn wallet_wasm_code(self) -> u8 {
        match self {
            Self::Bitcoin => 0,
            Self::Testnet | Self::Signet => 1,
            Self::Regtest => 2,
        }
    }
}

/// Stable checkpoint in explorer/display byte order.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckpointConfig {
    /// Block height.
    pub height: u32,
    /// Display-order block hash.
    pub display_hash_hex: String,
}

/// Confirmation depths required by the browser coordinator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationConfig {
    /// Origin confirmations required before DEAL begins.
    pub origin: u16,
    /// Gameplay confirmations required before advancing state.
    pub gameplay: u16,
}

/// Unresolved chain deployment loaded from JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChainDeploymentConfig {
    /// Backend protocol.
    pub backend: ChainBackendName,
    /// Esplora API root.
    pub esplora_url: String,
    /// Human-facing explorer root.
    pub explorer_url: String,
    /// Bitcoin address/transaction network.
    pub network: NetworkName,
    /// Display-order genesis hash.
    pub genesis_display_hash_hex: String,
    /// Exact Signet challenge script in hex, required only for Signet.
    pub signet_challenge_hex: Option<String>,
    /// Stable chain checkpoint.
    pub checkpoint: Option<CheckpointConfig>,
    /// Whether this deployment permits transaction submission.
    pub allow_broadcast: bool,
    /// Expected Bech32 human-readable prefix.
    pub address_hrp: String,
    /// Confirmation policy.
    pub confirmations: ConfirmationConfig,
    /// Highest fee floor supported by the immutable prototype graph.
    pub fee_floor_sat_per_vbyte: u64,
}

impl ChainDeploymentConfig {
    /// Validate network configuration and derive its public browser representation.
    ///
    /// # Errors
    /// Rejects contradictory network settings, invalid URLs, and unsupported policies.
    pub fn resolve_browser_config(
        &self,
    ) -> Result<(BrowserChainConfig, ChainProfile), DeploymentConfigError> {
        let (profile, profile_id_hex) = self.resolve_profile()?;
        Ok((
            BrowserChainConfig {
                backend: self.backend,
                esplora_url: normalize_url(&self.esplora_url)?.to_owned(),
                explorer_url: normalize_url(&self.explorer_url)?.to_owned(),
                network: self.network,
                bitcoin_network_code: self.network.bitcoin_wasm_code(),
                wallet_network_code: self.network.wallet_wasm_code(),
                profile_id_hex,
                genesis_display_hash_hex: self.genesis_display_hash_hex.clone(),
                signet_challenge_hex: self.signet_challenge_hex.clone(),
                checkpoint: self.checkpoint.clone(),
                allow_broadcast: self.allow_broadcast,
                address_hrp: self.address_hrp.clone(),
                confirmations: self.confirmations,
                fee_floor_sat_per_vbyte: self.fee_floor_sat_per_vbyte,
            },
            profile,
        ))
    }

    fn resolve_profile(&self) -> Result<(ChainProfile, String), DeploymentConfigError> {
        normalize_url(&self.esplora_url)?;
        normalize_url(&self.explorer_url)?;
        if self.address_hrp != self.network.expected_hrp() {
            return Err(DeploymentConfigError::Invalid(
                "address HRP differs from network",
            ));
        }
        if self.confirmations.origin == 0
            || self.confirmations.gameplay == 0
            || self.fee_floor_sat_per_vbyte == 0
            || self.fee_floor_sat_per_vbyte > JAVASCRIPT_MAX_SAFE_INTEGER
        {
            return Err(DeploymentConfigError::Invalid("chain policy contains zero"));
        }
        let genesis_hash = decode_display_hash(&self.genesis_display_hash_hex)?;
        let expected_genesis = genesis_block(self.network.bitcoin())
            .block_hash()
            .to_byte_array();
        if genesis_hash != expected_genesis {
            return Err(DeploymentConfigError::Invalid(
                "genesis hash differs from network",
            ));
        }
        let checkpoint = self
            .checkpoint
            .as_ref()
            .map(|value| {
                Ok(BlockRef {
                    height: value.height,
                    hash: decode_display_hash(&value.display_hash_hex)?,
                })
            })
            .transpose()?;
        let profile = if self.network == NetworkName::Signet {
            ChainProfile::custom_signet(
                genesis_hash,
                decode_hex(self.signet_challenge_hex.as_deref().ok_or(
                    DeploymentConfigError::Invalid("Signet challenge is missing"),
                )?)?,
                checkpoint,
            )
        } else {
            if self.signet_challenge_hex.is_some() {
                return Err(DeploymentConfigError::Invalid(
                    "non-Signet chain contains a Signet challenge",
                ));
            }
            ChainProfile::standard(genesis_hash, checkpoint)
        }
        .map_err(|_| DeploymentConfigError::Invalid("chain profile is invalid"))?;
        if profile.is_mainnet() && self.allow_broadcast {
            return Err(DeploymentConfigError::Invalid(
                "mainnet broadcast must be disabled",
            ));
        }
        Ok((profile.clone(), encode_hex(&profile.profile_id())))
    }
}

/// Resolved chain settings serialized to the browser.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserChainConfig {
    /// Backend protocol.
    pub backend: ChainBackendName,
    /// Esplora API root.
    pub esplora_url: String,
    /// Explorer UI root.
    pub explorer_url: String,
    /// Bitcoin network.
    pub network: NetworkName,
    /// Stable selector consumed by the Rust/Wasm protocol boundaries.
    pub bitcoin_network_code: u8,
    /// Stable selector consumed by the wallet address Wasm boundary.
    pub wallet_network_code: u8,
    /// Challenge-derived profile identifier in consensus byte order.
    pub profile_id_hex: String,
    /// Display-order genesis hash.
    pub genesis_display_hash_hex: String,
    /// Exact Signet challenge script, if any.
    pub signet_challenge_hex: Option<String>,
    /// Stable checkpoint.
    pub checkpoint: Option<CheckpointConfig>,
    /// Whether transaction publication is enabled.
    pub allow_broadcast: bool,
    /// Address HRP.
    pub address_hrp: String,
    /// Confirmation policy.
    pub confirmations: ConfirmationConfig,
    /// Immutable graph fee-floor assumption.
    pub fee_floor_sat_per_vbyte: u64,
}

impl BrowserChainConfig {
    /// Return a validated `scheme://authority` suitable for the CSP `connect-src` directive.
    ///
    /// # Errors
    ///
    /// Returns an error only if this resolved value was constructed outside the resolver.
    pub fn esplora_origin(&self) -> Result<String, DeploymentConfigError> {
        parsed_origin(&self.esplora_url)
    }

    fn write_digest(&self, writer: &mut DigestWriter) {
        writer.u8(match self.backend {
            ChainBackendName::Esplora => 0,
        });
        writer.string(&self.esplora_url);
        writer.string(&self.explorer_url);
        writer.u8(self.network.bitcoin_wasm_code());
        writer.string(&self.profile_id_hex);
        writer.string(&self.genesis_display_hash_hex);
        match &self.signet_challenge_hex {
            Some(value) => {
                writer.u8(1);
                writer.string(value);
            }
            None => writer.u8(0),
        }
        match &self.checkpoint {
            Some(value) => {
                writer.u8(1);
                writer.u32(value.height);
                writer.string(&value.display_hash_hex);
            }
            None => writer.u8(0),
        }
        writer.u8(u8::from(self.allow_broadcast));
        writer.string(&self.address_hrp);
        writer.u16(self.confirmations.origin);
        writer.u16(self.confirmations.gameplay);
        writer.u64(self.fee_floor_sat_per_vbyte);
    }
}

/// Player role used by deployment defaults.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RoleName {
    /// Canonical Alice role.
    Alice,
    /// Canonical Bob role.
    Bob,
}

/// Timeout settlement behavior supported by the browser profile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TimeoutPolicyName {
    /// Award committed pot value to the beneficiary and refund uncommitted remainders.
    PotOnly,
}

/// Default first revealer on each street.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevealOrderConfig {
    /// First flop-share revealer.
    pub flop_first: RoleName,
    /// First turn-share revealer.
    pub turn_first: RoleName,
    /// First river-share revealer.
    pub river_first: RoleName,
}

/// Absolute fee assigned to each transaction class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FeeScheduleConfig {
    /// Betting-edge fee.
    pub betting_sat: u64,
    /// Share-reveal fee.
    pub reveal_sat: u64,
    /// Alice-showdown fee.
    pub alice_showdown_sat: u64,
    /// Bob-payout fee.
    pub bob_payout_sat: u64,
    /// Timeout fee.
    pub timeout_sat: u64,
}

/// Public game/origin profile loaded from deployment JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GameDeploymentConfig {
    /// Exact staging amount reserved from each participant.
    pub staging_contribution_sat: u64,
    /// Origin funding transaction fee.
    pub origin_funding_fee_sat: u64,
    /// Joint origin output value.
    pub origin_value_sat: u64,
    /// Activation fee.
    pub activation_fee_sat: u64,
    /// First gameplay state value.
    pub gameplay_root_value_sat: u64,
    /// Fair abort-refund fee.
    pub origin_refund_fee_sat: u64,
    /// Abort-refund value per participant.
    pub refund_output_sat: u64,
    /// Abort relative timelock.
    pub refund_csv_blocks: u16,
    /// Fixed-limit unit/small blind.
    pub unit_sat: u64,
    /// Maximum total wagers on one street, including its opening bet.
    pub max_bets_per_street: u8,
    /// Starting poker stack per participant.
    pub starting_stack_sat: u64,
    /// Shared gameplay fee reserve.
    pub fee_reserve_sat: u64,
    /// Dust threshold used by descriptor validation.
    pub dust_threshold_sat: u64,
    /// Absolute transaction-class fees.
    pub fees: FeeScheduleConfig,
    /// Default dealer/button.
    pub button: RoleName,
    /// Default community reveal order.
    pub reveal_order: RevealOrderConfig,
    /// Default odd-satoshi split recipient.
    pub split_remainder_recipient: RoleName,
    /// Timeout settlement policy.
    pub timeout_policy: TimeoutPolicyName,
}

impl GameDeploymentConfig {
    fn validate(&self) -> Result<(), DeploymentConfigError> {
        let staged = self
            .staging_contribution_sat
            .checked_mul(2)
            .and_then(|value| value.checked_sub(self.origin_funding_fee_sat));
        let root = self
            .starting_stack_sat
            .checked_mul(2)
            .and_then(|value| value.checked_add(self.fee_reserve_sat));
        let refund = self
            .refund_output_sat
            .checked_mul(2)
            .and_then(|value| value.checked_add(self.origin_refund_fee_sat));
        if staged != Some(self.origin_value_sat)
            || root != Some(self.gameplay_root_value_sat)
            || self
                .gameplay_root_value_sat
                .checked_add(self.activation_fee_sat)
                != Some(self.origin_value_sat)
            || refund != Some(self.origin_value_sat)
        {
            return Err(DeploymentConfigError::Invalid(
                "game value equations do not balance",
            ));
        }
        if self.unit_sat == 0
            || self.max_bets_per_street == 0
            || self.max_bets_per_street > 4
            || self.starting_stack_sat < self.unit_sat.saturating_mul(2)
            || self.refund_csv_blocks == 0
            || self.dust_threshold_sat == 0
            || self.refund_output_sat < self.dust_threshold_sat
            || self.timeout_policy != TimeoutPolicyName::PotOnly
        {
            return Err(DeploymentConfigError::Invalid("game policy is unsupported"));
        }
        let fees = [
            self.fees.betting_sat,
            self.fees.reveal_sat,
            self.fees.alice_showdown_sat,
            self.fees.bob_payout_sat,
            self.fees.timeout_sat,
        ];
        if fees.contains(&0) {
            return Err(DeploymentConfigError::Invalid(
                "game fee schedule contains zero",
            ));
        }
        let integers = [
            self.staging_contribution_sat,
            self.origin_funding_fee_sat,
            self.origin_value_sat,
            self.activation_fee_sat,
            self.gameplay_root_value_sat,
            self.origin_refund_fee_sat,
            self.refund_output_sat,
            self.unit_sat,
            self.starting_stack_sat,
            self.fee_reserve_sat,
            self.dust_threshold_sat,
            self.fees.betting_sat,
            self.fees.reveal_sat,
            self.fees.alice_showdown_sat,
            self.fees.bob_payout_sat,
            self.fees.timeout_sat,
        ];
        if integers
            .iter()
            .any(|value| *value > JAVASCRIPT_MAX_SAFE_INTEGER)
        {
            return Err(DeploymentConfigError::Invalid(
                "game integer exceeds JavaScript safe range",
            ));
        }
        Ok(())
    }

    fn write_digest(&self, writer: &mut DigestWriter) {
        writer.u64(self.staging_contribution_sat);
        writer.u64(self.origin_funding_fee_sat);
        writer.u64(self.origin_value_sat);
        writer.u64(self.activation_fee_sat);
        writer.u64(self.gameplay_root_value_sat);
        writer.u64(self.origin_refund_fee_sat);
        writer.u64(self.refund_output_sat);
        writer.u16(self.refund_csv_blocks);
        writer.u64(self.unit_sat);
        writer.u8(self.max_bets_per_street);
        writer.u64(self.starting_stack_sat);
        writer.u64(self.fee_reserve_sat);
        writer.u64(self.dust_threshold_sat);
        writer.u64(self.fees.betting_sat);
        writer.u64(self.fees.reveal_sat);
        writer.u64(self.fees.alice_showdown_sat);
        writer.u64(self.fees.bob_payout_sat);
        writer.u64(self.fees.timeout_sat);
        writer.u8(role_code(self.button));
        writer.u8(role_code(self.reveal_order.flop_first));
        writer.u8(role_code(self.reveal_order.turn_first));
        writer.u8(role_code(self.reveal_order.river_first));
        writer.u8(role_code(self.split_remainder_recipient));
        writer.u8(match self.timeout_policy {
            TimeoutPolicyName::PotOnly => 0,
        });
    }
}

const fn role_code(role: RoleName) -> u8 {
    match role {
        RoleName::Alice => 0,
        RoleName::Bob => 1,
    }
}

struct DigestWriter(Sha256);

impl DigestWriter {
    fn new() -> Self {
        let tag_hash = Sha256::digest(DEPLOYMENT_DIGEST_TAG);
        let mut hasher = Sha256::new();
        hasher.update(tag_hash);
        hasher.update(tag_hash);
        Self(hasher)
    }

    fn u8(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn u16(&mut self, value: u16) {
        self.0.update(value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.0.update(value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.update(value.to_le_bytes());
    }

    fn string(&mut self, value: &str) {
        self.u32(u32::try_from(value.len()).unwrap_or(u32::MAX));
        self.0.update(value.as_bytes());
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

/// Invalid deployment configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum DeploymentConfigError {
    /// A public configuration invariant failed.
    #[error("invalid deployment configuration: {0}")]
    Invalid(&'static str),
}

fn validate_deployment_id(value: &str) -> Result<(), DeploymentConfigError> {
    if value.is_empty()
        || value.len() > 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(DeploymentConfigError::Invalid(
            "deployment id is not canonical",
        ));
    }
    Ok(())
}

fn normalize_url(value: &str) -> Result<&str, DeploymentConfigError> {
    if value.len() > 2_048 {
        return Err(DeploymentConfigError::Invalid("deployment URL is too long"));
    }
    let uri: Uri = value
        .parse()
        .map_err(|_| DeploymentConfigError::Invalid("deployment URL is invalid"))?;
    let scheme = uri.scheme_str().ok_or(DeploymentConfigError::Invalid(
        "deployment URL has no scheme",
    ))?;
    let authority = uri.authority().ok_or(DeploymentConfigError::Invalid(
        "deployment URL has no authority",
    ))?;
    let host = authority.host();
    let loopback = host == "localhost" || host == "127.0.0.1" || host == "[::1]";
    if value.ends_with('/')
        || authority.as_str().contains('@')
        || uri.query().is_some()
        || !uri.path().starts_with('/')
        || !matches!(scheme, "https" | "http")
        || (scheme == "http" && !loopback)
    {
        return Err(DeploymentConfigError::Invalid("deployment URL is invalid"));
    }
    Ok(value)
}

fn parsed_origin(value: &str) -> Result<String, DeploymentConfigError> {
    normalize_url(value)?;
    let uri: Uri = value
        .parse()
        .map_err(|_| DeploymentConfigError::Invalid("deployment URL is invalid"))?;
    let scheme = uri.scheme_str().ok_or(DeploymentConfigError::Invalid(
        "deployment URL has no scheme",
    ))?;
    let authority = uri.authority().ok_or(DeploymentConfigError::Invalid(
        "deployment URL has no authority",
    ))?;
    Ok(format!("{scheme}://{authority}"))
}

fn decode_display_hash(value: &str) -> Result<[u8; 32], DeploymentConfigError> {
    let mut bytes: [u8; 32] = decode_hex(value)?
        .try_into()
        .map_err(|_| DeploymentConfigError::Invalid("hash must contain 32 bytes"))?;
    bytes.reverse();
    Ok(bytes)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, DeploymentConfigError> {
    if value.is_empty()
        || value.len() % 2 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DeploymentConfigError::Invalid(
            "hex value is not canonical lowercase",
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Result<u8, DeploymentConfigError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(DeploymentConfigError::Invalid(
            "hex value contains an invalid digit",
        )),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Result<DeploymentConfig, Box<dyn std::error::Error>> {
        Ok(serde_json::from_str(include_str!(
            "../tests/fixtures/funding-diagnostic.json"
        ))?)
    }

    #[test]
    fn mutinynet_fixture_resolves_without_stored_profile_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = fixture()?;
        let game = value.game.clone();
        let resolved =
            value.resolve_for_profile(ProtocolProfileName::HeadsUpFixedLimitV1, &game)?;
        assert_eq!(resolved.deployment_id, "mutinynet");
        assert_eq!(resolved.protocol_profile_code, 1);
        assert_eq!(resolved.chain.bitcoin_network_code, 2);
        assert_eq!(resolved.chain.wallet_network_code, 1);
        assert_eq!(
            resolved.chain.profile_id_hex,
            "e3bc9730af93197380e11b43ca00d6b516d83321f46b8b9f53a22a4fae89e680"
        );
        assert_eq!(resolved.game.gameplay_root_value_sat, 53_000);
        assert_eq!(resolved.deployment_digest_hex.len(), 64);
        let browser_json = serde_json::to_value(&resolved)?;
        assert_eq!(browser_json["protocolProfileCode"], 1);
        assert_eq!(browser_json["chain"]["bitcoinNetworkCode"], 2);
        assert_eq!(browser_json["chain"]["walletNetworkCode"], 1);
        Ok(())
    }

    #[test]
    fn contradictory_value_equations_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut value = fixture()?;
        value.game.origin_value_sat -= 1;
        let game = value.game.clone();
        assert!(
            value
                .resolve_for_profile(ProtocolProfileName::HeadsUpFixedLimitV1, &game)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn duplicate_relay_kinds_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut value = fixture()?;
        value.relay.kinds.chain_exchange = value.relay.kinds.game_exchange.clone();
        let game = value.game.clone();
        assert!(
            value
                .resolve_for_profile(ProtocolProfileName::HeadsUpFixedLimitV1, &game)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn wasm_selectors_are_derived_and_cannot_be_overridden_by_json()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = include_str!("../tests/fixtures/funding-diagnostic.json");
        let mut top_level: serde_json::Value = serde_json::from_str(source)?;
        top_level["protocolProfileCode"] = serde_json::json!(0);
        assert!(serde_json::from_value::<DeploymentConfig>(top_level).is_err());

        let mut chain_level: serde_json::Value = serde_json::from_str(source)?;
        chain_level["chain"]["bitcoinNetworkCode"] = serde_json::json!(0);
        assert!(serde_json::from_value::<DeploymentConfig>(chain_level).is_err());
        Ok(())
    }

    #[test]
    fn selected_profile_terms_must_match_the_expected_rust_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = fixture()?;
        let mut expected = value.game.clone();
        expected.unit_sat += 1;
        assert!(
            value
                .resolve_for_profile(ProtocolProfileName::HeadsUpFixedLimitV1, &expected)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn diagnostic_chain_resolution_does_not_authorize_game_or_relay_terms()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut value = fixture()?;
        value.game.origin_value_sat -= 1;
        value.relay.kinds.chain_exchange = value.relay.kinds.game_exchange.clone();
        let (chain, profile) = value.resolve_chain_for_diagnostics()?;
        assert_eq!(chain.profile_id_hex, encode_hex(&profile.profile_id()));
        assert!(
            value
                .resolve_for_profile(ProtocolProfileName::HeadsUpFixedLimitV1, &value.game)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn diagnostic_chain_resolution_keeps_mainnet_broadcast_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut value = fixture()?;
        value.chain.network = NetworkName::Bitcoin;
        value.chain.genesis_display_hash_hex =
            genesis_block(Network::Bitcoin).block_hash().to_string();
        value.chain.signet_challenge_hex = None;
        value.chain.checkpoint = None;
        value.chain.address_hrp = "bc".to_owned();
        value.chain.allow_broadcast = true;
        assert!(value.resolve_chain_for_diagnostics().is_err());
        Ok(())
    }
}
