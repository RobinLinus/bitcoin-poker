//! Versioned configuration for the practice application.
use crate::RelayBuildError;
use poker_client_ports::{BrowserChainConfig, ChainDeploymentConfig, RelayBrowserConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Supported application mode. Funded browser integration is not implemented.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ApplicationMode {
    /// Play with practice chips and no transaction publication.
    Practice,
}

/// Operator configuration, separate from funded-game economics.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentConfig {
    /// Application configuration schema; currently 3.
    pub schema_version: u16,
    /// Deployment storage/display namespace.
    pub deployment_id: String,
    /// Enabled application behavior.
    pub mode: ApplicationMode,
    /// Relay transport limits and endpoints.
    pub relay: RelayBrowserConfig,
    /// Diagnostic network observation settings.
    pub chain: ChainDeploymentConfig,
}

/// Configuration served to browsers. It deliberately has no funding terms.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserDeploymentConfig {
    /// Application schema version.
    pub schema_version: u16,
    /// Deployment storage/display namespace.
    pub deployment_id: String,
    /// Enabled application behavior.
    pub mode: ApplicationMode,
    /// Configuration identity for application storage.
    pub deployment_digest_hex: String,
    /// Relay transport settings.
    pub relay: RelayBrowserConfig,
    /// Validated diagnostic network settings.
    pub chain: BrowserChainConfig,
}

pub(super) fn resolve_deployment(
    value: &DeploymentConfig,
) -> Result<BrowserDeploymentConfig, RelayBuildError> {
    if value.schema_version != 3
        || value.chain.allow_broadcast
        || value.deployment_id.is_empty()
        || value.deployment_id.len() > 64
        || !value
            .deployment_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(RelayBuildError::Configuration);
    }
    value
        .relay
        .validate()
        .map_err(|_| RelayBuildError::Configuration)?;
    let (chain, _) = value
        .chain
        .resolve_browser_config()
        .map_err(|_| RelayBuildError::Configuration)?;
    let bytes = serde_json::to_vec(value).map_err(|_| RelayBuildError::Configuration)?;
    let hash = Sha256::digest(bytes);
    let deployment_digest_hex = crate::encode_hex(hash.into());
    Ok(BrowserDeploymentConfig {
        schema_version: value.schema_version,
        deployment_id: value.deployment_id.clone(),
        mode: value.mode,
        deployment_digest_hex,
        relay: value.relay.clone(),
        chain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn practice_configuration_cannot_enable_broadcasting() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut config: DeploymentConfig =
            serde_json::from_str(include_str!("../../../deployments/mutinynet/client.json"))?;
        assert!(resolve_deployment(&config).is_ok());
        config.chain.allow_broadcast = true;
        assert!(resolve_deployment(&config).is_err());
        let old = include_str!(
            "../../../crates/poker-client-ports/tests/fixtures/funding-diagnostic.json"
        );
        assert!(serde_json::from_str::<DeploymentConfig>(old).is_err());
        Ok(())
    }
}
