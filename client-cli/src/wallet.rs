//! Durable native Bitcoin identity and staging-wallet key custody.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, Network, PublicKey as BitcoinPublicKey, ScriptBuf};
use bp52_origin::CompactSignature;
use rand::rngs::OsRng;

/// One durable identity used for DEAL authentication and Bitcoin staging.
pub struct NativeWallet {
    secret: SecretKey,
}

impl NativeWallet {
    /// Load a key or atomically generate it when the file does not exist.
    pub fn load_or_create(path: &Path) -> Result<Self, String> {
        match fs::read(path) {
            Ok(bytes) => Self::from_bytes(&bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let secret = SecretKey::new(&mut OsRng);
                if let Some(parent) = path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                {
                    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
                }
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.mode(0o600);
                }
                match options.open(path) {
                    Ok(mut file) => {
                        file.write_all(&secret.secret_bytes())
                            .and_then(|()| file.sync_all())
                            .map_err(|error| error.to_string())?;
                        Ok(Self { secret })
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        Self::from_bytes(&fs::read(path).map_err(|error| error.to_string())?)
                    }
                    Err(error) => Err(error.to_string()),
                }
            }
            Err(error) => Err(error.to_string()),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let secret =
            SecretKey::from_slice(bytes).map_err(|_| "invalid native wallet key".to_owned())?;
        Ok(Self { secret })
    }

    /// Secret bytes for initializing the native DEAL runtime.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.secret_bytes()
    }

    /// X-only BIP340 identity bytes.
    pub fn xonly_public_key(&self) -> [u8; 32] {
        let secp = Secp256k1::new();
        Keypair::from_secret_key(&secp, &self.secret)
            .x_only_public_key()
            .0
            .serialize()
    }

    /// Compressed public key used by the staging P2WSH output.
    pub fn compressed_public_key(&self) -> [u8; 33] {
        PublicKey::from_secret_key(&Secp256k1::new(), &self.secret).serialize()
    }

    /// Produce a canonical low-S compact ECDSA signature over one BIP143 digest.
    pub fn sign_compact(&self, digest: [u8; 32]) -> Result<CompactSignature, String> {
        let signature = Secp256k1::new().sign_ecdsa(&Message::from_digest(digest), &self.secret);
        CompactSignature::new(signature.serialize_compact()).map_err(|error| error.to_string())
    }

    /// Exact native P2WSH staging witness script.
    pub fn staging_witness_script(&self) -> ScriptBuf {
        let key =
            BitcoinPublicKey::new(PublicKey::from_secret_key(&Secp256k1::new(), &self.secret));
        Builder::new()
            .push_key(&key)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    /// Mutinynet/signetwork staging address.
    pub fn staging_address(&self) -> Address {
        Address::p2wsh(&self.staging_witness_script(), Network::Signet)
    }
}
