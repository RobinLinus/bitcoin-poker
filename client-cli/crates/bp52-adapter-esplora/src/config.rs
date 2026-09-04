use bp52_client_ports::ChainProfile;

use crate::EsploraError;

/// Configuration for one Esplora endpoint and its expected chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EsploraConfig {
    pub(crate) base_url: String,
    pub(crate) profile: ChainProfile,
    pub(crate) allow_broadcast: bool,
}

impl EsploraConfig {
    /// Construct a checked HTTPS Esplora configuration.
    ///
    /// # Errors
    ///
    /// Rejects an insecure endpoint or mainnet transaction submission.
    pub fn new(
        base_url: impl Into<String>,
        profile: ChainProfile,
        allow_broadcast: bool,
    ) -> Result<Self, EsploraError> {
        let base_url = normalize_base_url(base_url.into())?;
        if profile.is_mainnet() && allow_broadcast {
            return Err(EsploraError::MainnetBroadcastDisabled);
        }
        Ok(Self {
            base_url,
            profile,
            allow_broadcast,
        })
    }

    /// Return the configured endpoint without a trailing slash.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Return the exact configured chain profile.
    #[must_use]
    pub const fn profile(&self) -> &ChainProfile {
        &self.profile
    }

    /// Return whether this non-mainnet endpoint permits transaction broadcast.
    #[must_use]
    pub const fn allows_broadcast(&self) -> bool {
        self.allow_broadcast
    }
}

fn normalize_base_url(mut url: String) -> Result<String, EsploraError> {
    if !url.starts_with("https://")
        || url.len() <= "https://".len()
        || url.bytes().any(|byte| byte.is_ascii_control())
        || url.contains(['?', '#'])
    {
        return Err(EsploraError::InvalidConfiguration(
            "endpoint must be an HTTPS URL without query or fragment",
        ));
    }
    let authority_end = url["https://".len()..]
        .find('/')
        .map_or(url.len(), |index| index + "https://".len());
    if url["https://".len()..authority_end].contains('@')
        || url.contains("/../")
        || url.ends_with("/..")
    {
        return Err(EsploraError::InvalidConfiguration(
            "endpoint contains user information or a parent path",
        ));
    }
    while url.ends_with('/') {
        url.pop();
    }
    Ok(url)
}
