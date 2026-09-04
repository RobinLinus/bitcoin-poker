//! Esplora HTTP adapter for the backend-neutral BP52 client ports.
//!
//! The adapter returns raw Bitcoin transactions and block references. It never
//! interprets poker actions or decides which protocol transition is valid.

#![forbid(unsafe_code)]

mod client;
mod config;
mod transport;
mod wire;

pub use client::{AddressUtxo, EsploraClient};
pub use config::EsploraConfig;

use bp52_client_ports::PortError;

/// Esplora adapter failures without response bodies or remote internals.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EsploraError {
    /// Adapter configuration is malformed.
    #[error("invalid Esplora configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// Chain-profile construction or verification failed.
    #[error("invalid or mismatched chain profile")]
    Profile(#[source] PortError),
    /// The requested object was not found.
    #[error("Esplora object was not found")]
    NotFound,
    /// The endpoint returned a transport or HTTP failure.
    #[error("Esplora request failed")]
    Transport,
    /// The response exceeded the endpoint-specific bound.
    #[error("Esplora response exceeded {maximum} bytes")]
    ResponseTooLarge {
        /// Maximum permitted response size.
        maximum: usize,
    },
    /// The endpoint returned malformed or inconsistent data.
    #[error("Esplora returned malformed or inconsistent data: {0}")]
    InvalidResponse(&'static str),
    /// The endpoint is not serving the configured chain.
    #[error("Esplora endpoint does not match the configured chain identity")]
    ChainIdentityMismatch,
    /// Mainnet transaction submission is deliberately unavailable.
    #[error("mainnet broadcast is disabled")]
    MainnetBroadcastDisabled,
    /// Transaction submission was disabled for this configuration.
    #[error("transaction broadcast is disabled for this Esplora profile")]
    BroadcastDisabled,
}

#[cfg(test)]
mod tests;
