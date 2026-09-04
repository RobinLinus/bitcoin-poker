//! Prototype command-line diagnostics for a resolved BP52 deployment.

#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::future::Future;
use std::io::{self, BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::str::FromStr;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::{BlockHash, Transaction, Txid};
use bp52_adapter_esplora::{EsploraClient, EsploraConfig};
use bp52_client_core::{ChainFollower, OutpointObservation};
use bp52_client_ports::{
    BrowserChainConfig, ChainProfile, ChainReader, DeploymentConfig, OutPointRef, RawTransaction,
    TransactionPublisher, TransactionStatus,
};
use bp52_store_sqlite::SqliteSessionStore;
use bp52_transport_libp2p::{Invite, TransportError};
use libp2p::Multiaddr;

mod deal;
mod game;
mod origin_native;
mod origin_network;
mod peer;
mod wallet;

const MUTINYNET_DEPLOYMENT: &[u8] = include_bytes!("../deployments/mutinynet/client.json");

fn main() {
    if let Err(error) = run(env::args().skip(1)) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(mut arguments: impl Iterator<Item = String>) -> Result<(), CliError> {
    let Some(command) = arguments.next() else {
        return interactive_wizard();
    };
    match command.as_str() {
        "peer-host" => {
            let relay = parse_multiaddr(&required(&mut arguments, "relay multiaddress")?)?;
            reject_extra(arguments)?;
            run_async(peer::host(relay))
        }
        "peer-join" => {
            let invite = Invite::decode(&required(&mut arguments, "invite")?)?;
            reject_extra(arguments)?;
            run_async(peer::join(invite))
        }
        "deal-host" => {
            let relay = parse_multiaddr(&required(&mut arguments, "relay multiaddress")?)?;
            let outpoint = parse_outpoint(&required(&mut arguments, "origin txid:vout")?)?;
            reject_extra(arguments)?;
            let profile = configured_esplora()?.deployment.chain_profile;
            run_async_game(game::host(
                relay,
                profile.profile_id(),
                consensus_outpoint(outpoint),
            ))
        }
        "deal-join" => {
            let invite = Invite::decode(&required(&mut arguments, "invite")?)?;
            let outpoint = parse_outpoint(&required(&mut arguments, "origin txid:vout")?)?;
            reject_extra(arguments)?;
            let profile = configured_esplora()?.deployment.chain_profile;
            run_async_game(game::join(
                invite,
                profile.profile_id(),
                consensus_outpoint(outpoint),
            ))
        }
        "funded-host" => {
            let relay = parse_multiaddr(&required(&mut arguments, "relay multiaddress")?)?;
            reject_extra(arguments)?;
            let configured = configured_esplora()?;
            run_async_game(game::funded_host(
                relay,
                configured.client,
                configured.deployment.chain_profile,
            ))
        }
        "funded-join" => {
            let invite = Invite::decode(&required(&mut arguments, "invite")?)?;
            reject_extra(arguments)?;
            let configured = configured_esplora()?;
            run_async_game(game::funded_join(
                invite,
                configured.client,
                configured.deployment.chain_profile,
            ))
        }
        "resume-host" => {
            let relay = parse_multiaddr(&required(&mut arguments, "relay multiaddress")?)?;
            reject_extra(arguments)?;
            let configured = configured_esplora()?;
            run_async_game(game::resume_host(
                relay,
                configured.client,
                configured.deployment.chain_profile,
            ))
        }
        "resume-join" => {
            let invite = Invite::decode(&required(&mut arguments, "invite")?)?;
            reject_extra(arguments)?;
            let configured = configured_esplora()?;
            run_async_game(game::resume_join(
                invite,
                configured.client,
                configured.deployment.chain_profile,
            ))
        }
        "doctor" => {
            reject_extra(arguments)?;
            doctor()
        }
        "tip" => {
            reject_extra(arguments)?;
            tip()
        }
        "tx" => {
            let txid = parse_txid(&required(&mut arguments, "txid")?)?;
            reject_extra(arguments)?;
            transaction_status(txid)
        }
        "outpoint" => {
            let outpoint = parse_outpoint(&required(&mut arguments, "txid:vout")?)?;
            reject_extra(arguments)?;
            outpoint_status(outpoint)
        }
        "broadcast" => {
            let transaction = parse_transaction(&required(&mut arguments, "transaction hex")?)?;
            reject_extra(arguments)?;
            broadcast(&transaction)
        }
        "db-check" => {
            let path = required(&mut arguments, "database path")?;
            reject_extra(arguments)?;
            SqliteSessionStore::open(path).map_err(|_| CliError::Storage)?;
            println!("database ready");
            Ok(())
        }
        "deal-self-test" => {
            reject_extra(arguments)?;
            deal::self_test().map_err(CliError::NativeDeal)?;
            println!("native DEAL completed and both participants accepted the same certificate");
            Ok(())
        }
        "address" => {
            let player = required(&mut arguments, "player (host or guest)")?;
            reject_extra(arguments)?;
            let filename = match player.as_str() {
                "host" => "host-wallet.key",
                "guest" => "guest-wallet.key",
                _ => return Err(CliError::Usage("player must be host or guest")),
            };
            let wallet = wallet::NativeWallet::load_or_create(&Path::new(".bp52").join(filename))
                .map_err(CliError::Wallet)?;
            println!("{}", wallet.staging_address());
            Ok(())
        }
        "origin-self-test" => {
            reject_extra(arguments)?;
            origin_native::self_test(Path::new(".bp52")).map_err(CliError::Origin)?;
            println!("native origin refund and funding packages verified");
            Ok(())
        }
        "chain-self-test" => {
            reject_extra(arguments)?;
            let profile = configured_esplora()?.deployment.chain_profile;
            game::self_test(&profile).map_err(CliError::Game)
        }
        "help" | "--help" | "-h" => {
            reject_extra(arguments)?;
            print_help();
            Ok(())
        }
        _ => Err(CliError::Usage("unknown command")),
    }
}

fn interactive_wizard() -> Result<(), CliError> {
    println!("BP52 Poker — two humans on Mutinynet\n");
    println!("1. Host a new game");
    println!("2. Join a game");
    println!("3. Resume as host");
    println!("4. Resume as guest");
    let choice = prompt("Choose 1–4: ")?;
    match choice.trim() {
        "1" => interactive_host(false),
        "2" => interactive_join(false),
        "3" => interactive_host(true),
        "4" => interactive_join(true),
        _ => Err(CliError::Interactive("choose 1, 2, 3, or 4".to_owned())),
    }
}

fn interactive_host(resume: bool) -> Result<(), CliError> {
    if !resume {
        show_funding_address("host", "host-wallet.key")?;
        let _ = prompt("Press Enter after sending ₿27,000 on Mutinynet: ")?;
    }
    let relay_input =
        prompt("Relay address (press Enter for an automatic relay on this computer): ")?;
    let mut local_relay = None;
    let relay = if relay_input.trim().is_empty() {
        let spawned = LocalRelay::start()?;
        let address = spawned.address.clone();
        local_relay = Some(spawned);
        println!("Local relay ready.");
        address
    } else {
        parse_multiaddr(relay_input.trim())?
    };
    let configured = interactive_esplora()?;
    let result = if resume {
        run_async_game(game::resume_host(
            relay,
            configured.client,
            configured.deployment.chain_profile,
        ))
    } else {
        run_async_game(game::funded_host(
            relay,
            configured.client,
            configured.deployment.chain_profile,
        ))
    };
    drop(local_relay);
    result
}

fn interactive_join(resume: bool) -> Result<(), CliError> {
    if !resume {
        show_funding_address("guest", "guest-wallet.key")?;
        println!("Send ₿27,000 on Mutinynet to that address.");
    }
    let invite = prompt("Paste the private invite from the host: ")?;
    let invite = Invite::decode(invite.trim())?;
    let configured = interactive_esplora()?;
    if resume {
        run_async_game(game::resume_join(
            invite,
            configured.client,
            configured.deployment.chain_profile,
        ))
    } else {
        run_async_game(game::funded_join(
            invite,
            configured.client,
            configured.deployment.chain_profile,
        ))
    }
}

fn show_funding_address(player: &str, filename: &str) -> Result<(), CliError> {
    let wallet = wallet::NativeWallet::load_or_create(&Path::new(".bp52").join(filename))
        .map_err(CliError::Wallet)?;
    println!(
        "\n{player} funding address:\n{}\n",
        wallet.staging_address()
    );
    Ok(())
}

fn prompt(message: &str) -> Result<String, CliError> {
    print!("{message}");
    io::stdout()
        .flush()
        .map_err(|error| CliError::Interactive(error.to_string()))?;
    let mut input = String::new();
    if io::stdin()
        .read_line(&mut input)
        .map_err(|error| CliError::Interactive(error.to_string()))?
        == 0
    {
        return Err(CliError::Interactive("input closed".to_owned()));
    }
    Ok(input)
}

struct LocalRelay {
    child: Child,
    _stdout: BufReader<ChildStdout>,
    address: Multiaddr,
}

impl LocalRelay {
    fn start() -> Result<Self, CliError> {
        let executable = env::current_exe()
            .map_err(|error| CliError::Interactive(error.to_string()))?
            .with_file_name(format!("bp52-p2p-relay{}", env::consts::EXE_SUFFIX));
        let mut child = Command::new(executable)
            .arg("/ip4/127.0.0.1/tcp/0")
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|error| {
                CliError::Interactive(format!(
                    "could not start the bundled relay; build bp52-p2p-relay first: {error}"
                ))
            })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            CliError::Interactive("bundled relay did not expose its address".to_owned())
        })?;
        let mut stdout = BufReader::new(stdout);
        let mut line = String::new();
        if stdout
            .read_line(&mut line)
            .map_err(|error| CliError::Interactive(error.to_string()))?
            == 0
        {
            return Err(CliError::Interactive(
                "bundled relay exited before listening".to_owned(),
            ));
        }
        let address = line
            .trim()
            .strip_prefix("relay: ")
            .ok_or_else(|| {
                CliError::Interactive("bundled relay returned an invalid address".to_owned())
            })?
            .parse()
            .map_err(|_| {
                CliError::Interactive("bundled relay returned an invalid address".to_owned())
            })?;
        Ok(Self {
            child,
            _stdout: stdout,
            address,
        })
    }
}

impl Drop for LocalRelay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run_async(future: impl Future<Output = Result<(), TransportError>>) -> Result<(), CliError> {
    tokio::runtime::Runtime::new()
        .map_err(|_| CliError::Runtime)?
        .block_on(future)
        .map_err(CliError::Transport)
}

fn run_async_game(future: impl Future<Output = Result<(), String>>) -> Result<(), CliError> {
    tokio::runtime::Runtime::new()
        .map_err(|_| CliError::Runtime)?
        .block_on(future)
        .map_err(CliError::Game)
}

fn consensus_outpoint(outpoint: OutPointRef) -> [u8; 36] {
    let mut bytes = [0_u8; 36];
    bytes[..32].copy_from_slice(&outpoint.txid);
    bytes[32..].copy_from_slice(&outpoint.vout.to_le_bytes());
    bytes
}

fn parse_multiaddr(value: &str) -> Result<Multiaddr, CliError> {
    value
        .parse()
        .map_err(|_| CliError::Usage("invalid relay multiaddress"))
}

struct ConfiguredEsplora {
    client: EsploraClient,
    deployment: ResolvedChainDeployment,
}

struct ResolvedChainDeployment {
    deployment_id: String,
    chain: BrowserChainConfig,
    chain_profile: ChainProfile,
}

fn deployment_config_path() -> Result<PathBuf, CliError> {
    deployment_config_path_from(env::var_os("BP52_DEPLOYMENT_CONFIG"))
}

fn deployment_config_path_from(value: Option<OsString>) -> Result<PathBuf, CliError> {
    value
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .ok_or(CliError::MissingDeploymentConfig)
}

fn configured_esplora() -> Result<ConfiguredEsplora, CliError> {
    let path = deployment_config_path()?;
    let deployment = load_deployment(&path)?;
    configured_esplora_for(deployment)
}

fn interactive_esplora() -> Result<ConfiguredEsplora, CliError> {
    let deployment = resolve_deployment(MUTINYNET_DEPLOYMENT)?;
    configured_esplora_for(deployment)
}

fn configured_esplora_for(
    deployment: ResolvedChainDeployment,
) -> Result<ConfiguredEsplora, CliError> {
    let endpoint_override = match env::var("BP52_ESPLORA_URL") {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => return Err(CliError::InvalidEnvironment),
    };
    let config = esplora_config(&deployment, endpoint_override)?;
    Ok(ConfiguredEsplora {
        client: EsploraClient::new(config),
        deployment,
    })
}

fn load_deployment(path: &Path) -> Result<ResolvedChainDeployment, CliError> {
    let bytes = fs::read(path).map_err(|_| CliError::DeploymentRead)?;
    resolve_deployment(&bytes)
}

fn resolve_deployment(bytes: &[u8]) -> Result<ResolvedChainDeployment, CliError> {
    let deployment: DeploymentConfig =
        serde_json::from_slice(bytes).map_err(|_| CliError::DeploymentParse)?;
    let (chain, chain_profile) = deployment
        .resolve_chain_for_diagnostics()
        .map_err(CliError::Deployment)?;
    Ok(ResolvedChainDeployment {
        deployment_id: deployment.deployment_id,
        chain,
        chain_profile,
    })
}

fn esplora_config(
    deployment: &ResolvedChainDeployment,
    endpoint_override: Option<String>,
) -> Result<EsploraConfig, CliError> {
    let endpoint = endpoint_override.unwrap_or_else(|| deployment.chain.esplora_url.clone());
    EsploraConfig::new(
        endpoint,
        deployment.chain_profile.clone(),
        deployment.chain.allow_broadcast,
    )
    .map_err(CliError::Adapter)
}

fn doctor() -> Result<(), CliError> {
    let configured = configured_esplora()?;
    let identity = configured.client.verify_profile()?;
    println!("deployment: {}", configured.deployment.deployment_id);
    println!("endpoint: {}", configured.client.config().base_url());
    println!(
        "network-id: {}",
        identity.profile_id().to_lower_hex_string()
    );
    println!(
        "tip: {} {}",
        identity.checked_tip().height,
        display_block_hash(identity.checked_tip().hash)
    );
    if let Some(checkpoint) = identity.matched_checkpoint() {
        println!(
            "checkpoint: {} {}",
            checkpoint.height,
            display_block_hash(checkpoint.hash)
        );
    }
    println!(
        "broadcast: {}",
        if configured.client.config().allows_broadcast() {
            "enabled"
        } else {
            "disabled"
        }
    );
    Ok(())
}

fn tip() -> Result<(), CliError> {
    let ConfiguredEsplora {
        mut client,
        deployment,
    } = configured_esplora()?;
    let identity = client.verify_chain_identity(&deployment.chain_profile)?;
    let tip = ChainReader::tip(&mut client, &identity)?;
    println!(
        "{} {}",
        tip.block.height,
        display_block_hash(tip.block.hash)
    );
    Ok(())
}

fn transaction_status(txid: [u8; 32]) -> Result<(), CliError> {
    let ConfiguredEsplora {
        mut client,
        deployment,
    } = configured_esplora()?;
    let identity = client.verify_chain_identity(&deployment.chain_profile)?;
    let status = client.transaction_status(&identity, txid)?;
    print_transaction_status(status);
    Ok(())
}

fn outpoint_status(outpoint: OutPointRef) -> Result<(), CliError> {
    let ConfiguredEsplora {
        mut client,
        deployment,
    } = configured_esplora()?;
    let mut follower = ChainFollower::connect(&mut client, deployment.chain_profile)?;
    match follower.poll_outpoint(&mut client, outpoint)? {
        OutpointObservation::Unknown => println!("unknown"),
        OutpointObservation::CreatingTransactionUnconfirmed => {
            println!("creating transaction in mempool");
        }
        OutpointObservation::ConfirmedUnspent(confirmation) => println!(
            "unspent: {}, confirmed at {} {}",
            format_bip177(confirmation.output_value_sat),
            confirmation.confirmed_in.height,
            display_block_hash(confirmation.confirmed_in.hash)
        ),
        OutpointObservation::MempoolSpend { txid } => {
            println!("spent in mempool by {}", display_txid(txid));
        }
        OutpointObservation::ConfirmedSpend(spend) => println!(
            "spent by {} input {} at {} {}",
            display_txid(spend.spending_transaction.txid()),
            spend.input_index,
            spend.confirmed_in.height,
            display_block_hash(spend.confirmed_in.hash)
        ),
    }
    Ok(())
}

fn broadcast(transaction: &Transaction) -> Result<(), CliError> {
    let ConfiguredEsplora {
        mut client,
        deployment,
    } = configured_esplora()?;
    let identity = client.verify_chain_identity(&deployment.chain_profile)?;
    let txid = transaction.compute_txid().to_byte_array();
    let raw = RawTransaction::new(txid, bitcoin::consensus::serialize(transaction))?;
    let reported = TransactionPublisher::broadcast(&mut client, &identity, &raw)?;
    println!("{}", display_txid(reported));
    Ok(())
}

fn print_transaction_status(status: TransactionStatus) {
    match status {
        TransactionStatus::Unknown => println!("unknown"),
        TransactionStatus::Mempool => println!("mempool"),
        TransactionStatus::Confirmed { block } => println!(
            "confirmed at {} {}",
            block.height,
            display_block_hash(block.hash)
        ),
    }
}

fn parse_transaction(text: &str) -> Result<Transaction, CliError> {
    if text.len() > bp52_client_ports::MAX_RAW_OBJECT_BYTES.saturating_mul(2) {
        return Err(CliError::Usage("transaction hex is too large"));
    }
    let bytes =
        Vec::<u8>::from_hex(text).map_err(|_| CliError::Usage("invalid transaction hex"))?;
    deserialize(&bytes).map_err(|_| CliError::Usage("invalid Bitcoin transaction"))
}

fn parse_txid(text: &str) -> Result<[u8; 32], CliError> {
    Txid::from_str(text)
        .map(Hash::to_byte_array)
        .map_err(|_| CliError::Usage("invalid txid"))
}

fn parse_outpoint(text: &str) -> Result<OutPointRef, CliError> {
    let (txid, vout) = text
        .split_once(':')
        .ok_or(CliError::Usage("outpoint must be txid:vout"))?;
    let vout = vout
        .parse::<u32>()
        .map_err(|_| CliError::Usage("invalid output index"))?;
    Ok(OutPointRef {
        txid: parse_txid(txid)?,
        vout,
    })
}

fn display_txid(bytes: [u8; 32]) -> Txid {
    Txid::from_byte_array(bytes)
}

fn display_block_hash(bytes: [u8; 32]) -> BlockHash {
    BlockHash::from_byte_array(bytes)
}

fn format_bip177(value: u64) -> String {
    let digits = value.to_string();
    let mut formatted = String::with_capacity(digits.len() + digits.len() / 3 + 3);
    formatted.push('₿');
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            formatted.push(',');
        }
        formatted.push(digit);
    }
    formatted
}

fn required(
    arguments: &mut impl Iterator<Item = String>,
    name: &'static str,
) -> Result<String, CliError> {
    arguments.next().ok_or(CliError::MissingArgument(name))
}

fn reject_extra(mut arguments: impl Iterator<Item = String>) -> Result<(), CliError> {
    if arguments.next().is_some() {
        Err(CliError::Usage("too many arguments"))
    } else {
        Ok(())
    }
}

fn print_help() {
    println!(
        "bp52-client-cli — two-human Mutinynet poker\n\n\
         Usage:\n\
           bp52-client-cli                 Interactive game wizard\n\
           bp52-client-cli peer-host <relay-multiaddr>\n\
           bp52-client-cli peer-join <invite>\n\
           bp52-client-cli deal-host <relay-multiaddr> <origin-txid:vout>\n\
           bp52-client-cli deal-join <invite> <origin-txid:vout>\n\
           bp52-client-cli funded-host <relay-multiaddr>\n\
           bp52-client-cli funded-join <invite>\n\
           bp52-client-cli resume-host <relay-multiaddr>\n\
           bp52-client-cli resume-join <invite>\n\
         bp52-client-cli doctor\n\
           bp52-client-cli tip\n\
           bp52-client-cli tx <txid>\n\
           bp52-client-cli outpoint <txid:vout>\n\
           bp52-client-cli broadcast <transaction-hex>\n\
           bp52-client-cli db-check <path>\n\
           bp52-client-cli deal-self-test\n\n\
           bp52-client-cli address <host|guest>\n\n\
           bp52-client-cli origin-self-test\n\n\
           bp52-client-cli chain-self-test\n\n\
         The interactive wizard uses the built-in Mutinynet deployment.\n\
         Advanced subcommands require BP52_DEPLOYMENT_CONFIG to name a deployment JSON file.\n\
         BP52_ESPLORA_URL may replace only\n\
         its HTTP endpoint; the resolved chain identity remains mandatory.\n\
         Mainnet broadcast is always disabled."
    );
}

#[derive(Debug)]
enum CliError {
    MissingArgument(&'static str),
    Usage(&'static str),
    Adapter(bp52_adapter_esplora::EsploraError),
    Client(bp52_client_core::ClientError),
    Deployment(bp52_client_ports::DeploymentConfigError),
    DeploymentParse,
    DeploymentRead,
    MissingDeploymentConfig,
    InvalidEnvironment,
    Interactive(String),
    NativeDeal(String),
    Game(String),
    Origin(String),
    Wallet(String),
    Port(bp52_client_ports::PortError),
    Runtime,
    Storage,
    Transport(TransportError),
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingArgument(name) => write!(formatter, "missing {name}"),
            Self::Usage(reason) => formatter.write_str(reason),
            Self::Adapter(error) => write!(formatter, "{error}"),
            Self::Client(error) => write!(formatter, "{error}"),
            Self::Deployment(error) => write!(formatter, "{error}"),
            Self::DeploymentParse => formatter.write_str("deployment config is not valid JSON"),
            Self::DeploymentRead => formatter.write_str("deployment config could not be read"),
            Self::MissingDeploymentConfig => {
                formatter.write_str("BP52_DEPLOYMENT_CONFIG must name a deployment JSON file")
            }
            Self::InvalidEnvironment => {
                formatter.write_str("configuration environment variable is not valid Unicode")
            }
            Self::Interactive(error) => write!(formatter, "interactive setup failed: {error}"),
            Self::NativeDeal(error) => write!(formatter, "native DEAL failed: {error}"),
            Self::Game(error) => write!(formatter, "native game failed: {error}"),
            Self::Origin(error) => write!(formatter, "native origin failed: {error}"),
            Self::Wallet(error) => write!(formatter, "native wallet failed: {error}"),
            Self::Port(error) => write!(formatter, "{error}"),
            Self::Runtime => formatter.write_str("async runtime initialization failed"),
            Self::Storage => formatter.write_str("database initialization failed"),
            Self::Transport(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for CliError {}

impl From<bp52_adapter_esplora::EsploraError> for CliError {
    fn from(error: bp52_adapter_esplora::EsploraError) -> Self {
        Self::Adapter(error)
    }
}

impl From<bp52_client_core::ClientError> for CliError {
    fn from(error: bp52_client_core::ClientError) -> Self {
        Self::Client(error)
    }
}

impl From<bp52_client_ports::PortError> for CliError {
    fn from(error: bp52_client_ports::PortError) -> Self {
        Self::Port(error)
    }
}

impl From<TransportError> for CliError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MUTINYNET_FIXTURE: &[u8] = include_bytes!("../deployments/mutinynet/client.json");

    #[test]
    fn bip177_display_uses_integral_grouped_base_units() {
        assert_eq!(format_bip177(0), "₿0");
        assert_eq!(format_bip177(999), "₿999");
        assert_eq!(format_bip177(10_000), "₿10,000");
        assert_eq!(format_bip177(u64::MAX), "₿18,446,744,073,709,551,615");
    }

    #[test]
    fn deployment_path_is_always_explicit() {
        assert!(matches!(
            deployment_config_path_from(None),
            Err(CliError::MissingDeploymentConfig)
        ));
        assert!(matches!(
            deployment_config_path_from(Some(OsString::new())),
            Err(CliError::MissingDeploymentConfig)
        ));
        assert_eq!(
            deployment_config_path_from(Some(OsString::from("deployment.json")))
                .unwrap_or_else(|_| unreachable!()),
            PathBuf::from("deployment.json")
        );
    }

    #[test]
    fn deployment_fixture_resolves_through_shared_rust_validation() -> Result<(), Box<dyn Error>> {
        let deployment = resolve_deployment(MUTINYNET_FIXTURE)?;
        assert_eq!(deployment.deployment_id, "mutinynet");
        assert_eq!(
            deployment.chain.profile_id_hex,
            "e3bc9730af93197380e11b43ca00d6b516d83321f46b8b9f53a22a4fae89e680"
        );
        assert_eq!(
            deployment.chain_profile.profile_id().to_lower_hex_string(),
            deployment.chain.profile_id_hex
        );
        Ok(())
    }

    #[test]
    fn endpoint_override_cannot_replace_resolved_chain_identity() -> Result<(), Box<dyn Error>> {
        let deployment = resolve_deployment(MUTINYNET_FIXTURE)?;
        let expected_profile = deployment.chain_profile.clone();
        let config = esplora_config(&deployment, Some("https://example.test/esplora".to_owned()))?;
        assert_eq!(config.base_url(), "https://example.test/esplora");
        assert_eq!(config.profile(), &expected_profile);
        assert_eq!(config.allows_broadcast(), deployment.chain.allow_broadcast);
        Ok(())
    }
}
