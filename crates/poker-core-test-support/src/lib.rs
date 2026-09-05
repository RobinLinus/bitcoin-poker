#![forbid(unsafe_code)]
#![doc = "Workspace-private support for BP52 tests against a managed Bitcoin Core node."]

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::{Address, Amount, BlockHash, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid};

/// Error returned by the managed-Core test harness.
#[derive(Debug)]
pub struct CoreHarnessError {
    message: String,
}

impl CoreHarnessError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for CoreHarnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CoreHarnessError {}

impl From<io::Error> for CoreHarnessError {
    fn from(error: io::Error) -> Self {
        Self::new(error.to_string())
    }
}

/// Result type used by the managed-Core test harness.
pub type CoreResult<T> = Result<T, CoreHarnessError>;

/// A confirmed transaction output that can anchor the next path transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedOutput {
    outpoint: OutPoint,
    output: TxOut,
}

impl ConfirmedOutput {
    /// Construct an output after the caller has independently confirmed it.
    #[must_use]
    pub const fn new(outpoint: OutPoint, output: TxOut) -> Self {
        Self { outpoint, output }
    }

    /// Return the consensus outpoint.
    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    /// Return the amount and locking script committed by the output.
    #[must_use]
    pub const fn output(&self) -> &TxOut {
        &self.output
    }
}

/// One transaction confirmed by [`PathExecutor`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedPathStep {
    label: String,
    txid: Txid,
    spent: OutPoint,
    next: Option<ConfirmedOutput>,
    confirmation: ChainCheckpoint,
}

impl ConfirmedPathStep {
    /// Return the diagnostic label supplied by the test.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Return the confirmed transaction identifier.
    #[must_use]
    pub const fn txid(&self) -> Txid {
        self.txid
    }

    /// Return the path output consumed by this transition.
    #[must_use]
    pub const fn spent(&self) -> OutPoint {
        self.spent
    }

    /// Return the output selected as the next path state, if any.
    #[must_use]
    pub const fn next(&self) -> Option<&ConfirmedOutput> {
        self.next.as_ref()
    }

    /// Return the block hash and height that confirmed this transition.
    #[must_use]
    pub const fn confirmation(&self) -> &ChainCheckpoint {
        &self.confirmation
    }
}

/// An active-chain block suitable for deterministic rollback between paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainCheckpoint {
    block_hash: BlockHash,
    height: u64,
}

impl ChainCheckpoint {
    /// Return the active-chain block hash.
    #[must_use]
    pub const fn block_hash(self) -> BlockHash {
        self.block_hash
    }

    /// Return the active-chain block height.
    #[must_use]
    pub const fn height(self) -> u64 {
        self.height
    }
}

/// Command-line RPC client for the isolated node launched by the BP52 script.
///
/// Construction is intentionally gated by the launcher's private environment
/// contract. This prevents an ignored qualification test from accidentally
/// operating on an arbitrary node selected by ambient Bitcoin configuration.
pub struct CoreCli {
    program: OsString,
    prefix_arguments: Vec<OsString>,
    datadir: PathBuf,
    rpc_port: String,
    wallet: String,
}

impl CoreCli {
    /// Build a client from the managed-launcher environment.
    ///
    /// Returns `Ok(None)` when qualification was not requested. If
    /// `BP52_REQUIRE_BITCOIND=1`, absence of an active managed node is an
    /// error instead of a skip.
    ///
    /// # Errors
    ///
    /// Returns an error when required managed-launcher variables are absent.
    pub fn from_environment() -> CoreResult<Option<Self>> {
        if env::var("BP52_CORE_ACTIVE").as_deref() != Ok("1") {
            if env::var("BP52_REQUIRE_BITCOIND").as_deref() == Ok("1") {
                return Err(CoreHarnessError::new(
                    "BP52_REQUIRE_BITCOIND=1 but no managed regtest node is active; run scripts/bitcoin-core-regtest.sh --require",
                ));
            }
            eprintln!(
                "SKIP: real Bitcoin Core regtest is not active; run scripts/bitcoin-core-regtest.sh"
            );
            return Ok(None);
        }

        let (program, prefix_arguments, datadir) =
            if let Some(container) = env::var_os("BP52_CORE_DOCKER_CONTAINER") {
                let docker = env::var_os("BP52_DOCKER").unwrap_or_else(|| OsString::from("docker"));
                (
                    docker,
                    vec![
                        OsString::from("exec"),
                        OsString::from("--user"),
                        OsString::from("bitcoin:bitcoin"),
                        container,
                        OsString::from("bitcoin-cli"),
                    ],
                    PathBuf::from("/home/bitcoin/.bitcoin"),
                )
            } else {
                (
                    required_os("BP52_BITCOIN_CLI")?,
                    Vec::new(),
                    PathBuf::from(required_os("BP52_CORE_DATADIR")?),
                )
            };

        Ok(Some(Self {
            program,
            prefix_arguments,
            datadir,
            rpc_port: required_string("BP52_CORE_RPC_PORT")?,
            wallet: required_string("BP52_CORE_WALLET")?,
        }))
    }

    /// Invoke one wallet-scoped RPC and return its trimmed textual result.
    ///
    /// # Errors
    ///
    /// Returns an error when the command cannot run, Core rejects the RPC, or
    /// its standard output is not UTF-8.
    pub fn rpc(&self, method: &str, arguments: &[String]) -> CoreResult<String> {
        let mut command = Command::new(&self.program);
        command.args(&self.prefix_arguments).arg("-regtest");
        let output = command
            .arg(format!("-datadir={}", self.datadir.display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .arg(format!("-rpcwallet={}", self.wallet))
            .arg("-rpcwait")
            .arg(method)
            .args(arguments)
            .output()
            .map_err(|error| {
                CoreHarnessError::new(format!("could not execute bitcoin-cli {method}: {error}"))
            })?;
        if !output.status.success() {
            return Err(CoreHarnessError::new(format!(
                "bitcoin-cli {method} failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        String::from_utf8(output.stdout)
            .map(|stdout| stdout.trim().to_owned())
            .map_err(|error| {
                CoreHarnessError::new(format!("bitcoin-cli returned non-UTF-8: {error}"))
            })
    }

    /// Ask the isolated wallet for a fresh regtest Bech32m address.
    ///
    /// # Errors
    ///
    /// Returns an error when the wallet RPC fails.
    pub fn new_address(&self) -> CoreResult<String> {
        self.rpc("getnewaddress", &[String::new(), "bech32m".to_owned()])
    }

    /// Return the scriptPubKey for a fresh isolated-wallet address.
    ///
    /// # Errors
    ///
    /// Returns an error when the wallet RPC fails or returns an invalid or
    /// non-regtest address.
    pub fn new_script(&self) -> CoreResult<ScriptBuf> {
        let unchecked = Address::from_str(&self.new_address()?).map_err(|error| {
            CoreHarnessError::new(format!("wallet returned invalid address: {error}"))
        })?;
        Ok(unchecked
            .require_network(Network::Regtest)
            .map_err(|error| {
                CoreHarnessError::new(format!("wallet returned non-regtest address: {error}"))
            })?
            .script_pubkey())
    }

    /// Mine exactly `block_count` blocks to `address`.
    ///
    /// # Errors
    ///
    /// Returns an error when block generation fails or gives a malformed
    /// response.
    pub fn mine(&self, block_count: u16, address: &str) -> CoreResult<()> {
        let result = self.rpc(
            "generatetoaddress",
            &[block_count.to_string(), address.to_owned()],
        )?;
        if !result.starts_with('[') || !result.ends_with(']') {
            return Err(CoreHarnessError::new(
                "generatetoaddress returned non-array JSON",
            ));
        }
        Ok(())
    }

    /// Fail unless the managed RPC endpoint reports the regtest chain.
    ///
    /// # Errors
    ///
    /// Returns an error when the RPC fails or the endpoint is not regtest.
    pub fn assert_regtest(&self) -> CoreResult<()> {
        let compact = compact_json(&self.rpc("getblockchaininfo", &[])?);
        if !compact.contains("\"chain\":\"regtest\"") {
            return Err(CoreHarnessError::new(
                "bitcoin-cli is not connected to regtest",
            ));
        }
        Ok(())
    }

    /// Return the current active-chain block height.
    ///
    /// # Errors
    ///
    /// Returns an error when the RPC fails or returns a non-integer height.
    pub fn best_height(&self) -> CoreResult<u64> {
        self.rpc("getblockcount", &[])?
            .parse::<u64>()
            .map_err(|error| CoreHarnessError::new(format!("invalid block height: {error}")))
    }

    /// Capture the current active-chain tip as a reusable checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when the tip RPCs fail or Core returns an invalid hash
    /// or height.
    pub fn checkpoint(&self) -> CoreResult<ChainCheckpoint> {
        let block_hash = BlockHash::from_str(&self.rpc("getbestblockhash", &[])?)
            .map_err(|error| CoreHarnessError::new(format!("invalid best block hash: {error}")))?;
        Ok(ChainCheckpoint {
            block_hash,
            height: self.best_height()?,
        })
    }

    /// Create and confirm an exact-valued wallet output to `script_pubkey`.
    ///
    /// # Errors
    ///
    /// Returns an error when address conversion, wallet funding, decoding,
    /// mining, or active-UTXO verification fails.
    pub fn fund_script(
        &self,
        script_pubkey: &ScriptBuf,
        value: Amount,
        mining_address: &str,
    ) -> CoreResult<ConfirmedOutput> {
        let address = Address::from_script(script_pubkey, Network::Regtest).map_err(|error| {
            CoreHarnessError::new(format!("invalid regtest funding script: {error}"))
        })?;
        let txid_text = self.rpc(
            "sendtoaddress",
            &[address.to_string(), bitcoin_amount(value.to_sat())],
        )?;
        let raw = self.rpc("getrawtransaction", std::slice::from_ref(&txid_text))?;
        let transaction: Transaction = deserialize(&decode_hex(&raw)?).map_err(|error| {
            CoreHarnessError::new(format!("invalid funding transaction: {error}"))
        })?;
        let (vout, output) = transaction
            .output
            .iter()
            .enumerate()
            .find(|(_, output)| output.script_pubkey == *script_pubkey && output.value == value)
            .ok_or_else(|| {
                CoreHarnessError::new("wallet funding transaction omitted exact state output")
            })?;
        let vout = u32::try_from(vout)
            .map_err(|_| CoreHarnessError::new("funding output index exceeds u32"))?;
        let confirmed = ConfirmedOutput::new(
            OutPoint::new(transaction.compute_txid(), vout),
            output.clone(),
        );
        self.mine(1, mining_address)?;
        self.assert_unspent(&confirmed)?;
        Ok(confirmed)
    }

    /// Return Bitcoin Core's `testmempoolaccept` result for one transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the RPC invocation fails.
    pub fn mempool_result(&self, transaction: &Transaction) -> CoreResult<String> {
        self.mempool_package_result(std::slice::from_ref(transaction))
    }

    /// Return Bitcoin Core's `testmempoolaccept` result for an ordered package.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty package or a failed RPC invocation.
    pub fn mempool_package_result(&self, transactions: &[Transaction]) -> CoreResult<String> {
        if transactions.is_empty() {
            return Err(CoreHarnessError::new(
                "testmempoolaccept package must not be empty",
            ));
        }
        let mut argument = String::from("[");
        for (index, transaction) in transactions.iter().enumerate() {
            if index != 0 {
                argument.push(',');
            }
            argument.push('"');
            argument.push_str(&encode_hex(&serialize(transaction)));
            argument.push('"');
        }
        argument.push(']');
        self.rpc("testmempoolaccept", &[argument])
    }

    /// Require Bitcoin Core policy to reject `transaction`.
    ///
    /// # Errors
    ///
    /// Returns an error when the RPC fails or Core accepts the transaction.
    pub fn assert_rejected(&self, transaction: &Transaction, label: &str) -> CoreResult<()> {
        let response = self.mempool_result(transaction)?;
        if !compact_json(&response).contains("\"allowed\":false") {
            return Err(CoreHarnessError::new(format!(
                "Bitcoin Core unexpectedly accepted {label}: {response}"
            )));
        }
        Ok(())
    }

    /// Require Bitcoin Core policy to accept every transaction in a package.
    ///
    /// # Errors
    ///
    /// Returns an error when the RPC fails or Core rejects any transaction.
    pub fn assert_package_accepted(
        &self,
        transactions: &[Transaction],
        label: &str,
    ) -> CoreResult<()> {
        let response = self.mempool_package_result(transactions)?;
        let compact = compact_json(&response);
        let accepted = compact.matches("\"allowed\":true").count();
        if accepted != transactions.len() || compact.contains("\"allowed\":false") {
            return Err(CoreHarnessError::new(format!(
                "Bitcoin Core rejected valid {label}: {response}"
            )));
        }
        Ok(())
    }

    /// Broadcast a transaction after requiring policy acceptance.
    ///
    /// # Errors
    ///
    /// Returns an error when policy rejects the transaction, broadcasting
    /// fails, or Core returns a different transaction identifier.
    pub fn accept_and_broadcast(&self, transaction: &Transaction, label: &str) -> CoreResult<Txid> {
        self.assert_package_accepted(std::slice::from_ref(transaction), label)?;
        let expected_txid = transaction.compute_txid();
        let raw = encode_hex(&serialize(transaction));
        let returned = self.rpc("sendrawtransaction", &[raw])?;
        if returned != expected_txid.to_string() {
            return Err(CoreHarnessError::new(format!(
                "sendrawtransaction returned the wrong txid for {label}"
            )));
        }
        Ok(expected_txid)
    }

    /// Mine one block and require it to contain `txid`.
    ///
    /// # Errors
    ///
    /// Returns an error when mining or block RPCs fail, or when the freshly
    /// mined block does not include the transaction.
    pub fn mine_and_assert_included(
        &self,
        txid: Txid,
        mining_address: &str,
    ) -> CoreResult<ChainCheckpoint> {
        self.mine(1, mining_address)?;
        let checkpoint = self.checkpoint()?;
        let block = self.rpc(
            "getblock",
            &[checkpoint.block_hash.to_string(), "1".to_owned()],
        )?;
        if !compact_json(&block).contains(&format!("\"{txid}\"")) {
            return Err(CoreHarnessError::new(format!(
                "freshly mined block {} omitted transaction {txid}",
                checkpoint.block_hash
            )));
        }
        Ok(checkpoint)
    }

    /// Require a confirmed output to remain present in the active UTXO set.
    ///
    /// # Errors
    ///
    /// Returns an error when the RPC fails or the output is absent.
    pub fn assert_unspent(&self, output: &ConfirmedOutput) -> CoreResult<()> {
        let response = self.rpc(
            "gettxout",
            &[
                output.outpoint.txid.to_string(),
                output.outpoint.vout.to_string(),
                "true".to_owned(),
            ],
        )?;
        if response == "null" || response.is_empty() {
            return Err(CoreHarnessError::new(format!(
                "confirmed output {}:{} is absent from the active UTXO set",
                output.outpoint.txid, output.outpoint.vout
            )));
        }
        Ok(())
    }

    /// Require every output of a confirmed transaction to be unspent.
    ///
    /// # Errors
    ///
    /// Returns an error when an output index exceeds `u32`, an RPC fails, or
    /// any output is absent from the active UTXO set.
    pub fn assert_transaction_outputs_unspent(&self, transaction: &Transaction) -> CoreResult<()> {
        let txid = transaction.compute_txid();
        for (index, output) in transaction.output.iter().enumerate() {
            let vout = u32::try_from(index)
                .map_err(|_| CoreHarnessError::new("transaction output index exceeds u32"))?;
            self.assert_unspent(&ConfirmedOutput::new(
                OutPoint::new(txid, vout),
                output.clone(),
            ))?;
        }
        Ok(())
    }
}

/// Sequential executor for a single confirmed path through a transaction graph.
///
/// Each transition must have exactly one input and spend the executor's current
/// output. The executor checks value conservation locally, obtains a real Core
/// policy verdict, broadcasts, mines one block, verifies the selected child
/// output in the UTXO set, and only then advances its tip.
pub struct PathExecutor<'a> {
    core: &'a CoreCli,
    mining_address: &'a str,
    tip: Option<ConfirmedOutput>,
    confirmed_steps: Vec<ConfirmedPathStep>,
}

impl<'a> PathExecutor<'a> {
    /// Start at a state output after verifying it in Core's active UTXO set.
    ///
    /// # Errors
    ///
    /// Returns an error when Core cannot verify the output as unspent.
    pub fn from_confirmed(
        core: &'a CoreCli,
        mining_address: &'a str,
        tip: ConfirmedOutput,
    ) -> CoreResult<Self> {
        core.assert_unspent(&tip)?;
        Ok(Self {
            core,
            mining_address,
            tip: Some(tip),
            confirmed_steps: Vec::new(),
        })
    }

    /// Create and confirm the first output and start a path at it.
    ///
    /// # Errors
    ///
    /// Returns an error when funding or confirming the output fails.
    pub fn fund(
        core: &'a CoreCli,
        mining_address: &'a str,
        script_pubkey: &ScriptBuf,
        value: Amount,
    ) -> CoreResult<Self> {
        let tip = core.fund_script(script_pubkey, value, mining_address)?;
        Self::from_confirmed(core, mining_address, tip)
    }

    /// Return the current state output, or `None` after a terminal transition.
    #[must_use]
    pub const fn tip(&self) -> Option<&ConfirmedOutput> {
        self.tip.as_ref()
    }

    /// Return the ordered transitions this executor confirmed.
    #[must_use]
    pub fn confirmed_steps(&self) -> &[ConfirmedPathStep] {
        &self.confirmed_steps
    }

    /// Mine empty blocks before testing a relative-lock-time transition.
    ///
    /// # Errors
    ///
    /// Returns an error when block generation fails.
    pub fn mine_empty_blocks(&self, block_count: u16) -> CoreResult<()> {
        self.core.mine(block_count, self.mining_address)
    }

    /// Require Core to reject a candidate spending the current path tip.
    ///
    /// # Errors
    ///
    /// Returns an error when the transaction does not spend the current tip,
    /// the RPC fails, or Core accepts the transaction.
    pub fn assert_rejected(&self, transaction: &Transaction, label: &str) -> CoreResult<()> {
        self.assert_spends_tip(transaction, label)?;
        self.core.assert_rejected(transaction, label)
    }

    /// Confirm a non-terminal transition and select its `next_vout` as the new tip.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected output is absent or any path-shape,
    /// policy, broadcast, mining, or UTXO check fails.
    pub fn advance(
        &mut self,
        transaction: &Transaction,
        next_vout: u32,
        label: &str,
    ) -> CoreResult<&ConfirmedPathStep> {
        let output_index = usize::try_from(next_vout)
            .map_err(|_| CoreHarnessError::new("next output index exceeds usize"))?;
        let next_output = transaction
            .output
            .get(output_index)
            .cloned()
            .ok_or_else(|| {
                CoreHarnessError::new(format!("{label} omits selected output {next_vout}"))
            })?;
        self.confirm(transaction, Some((next_vout, next_output)), label)
    }

    /// Confirm a terminal transition and mark the path complete.
    ///
    /// # Errors
    ///
    /// Returns an error when any path-shape, policy, broadcast, or mining check
    /// fails.
    pub fn finish(
        &mut self,
        transaction: &Transaction,
        label: &str,
    ) -> CoreResult<&ConfirmedPathStep> {
        self.confirm(transaction, None, label)
    }

    fn confirm(
        &mut self,
        transaction: &Transaction,
        next: Option<(u32, TxOut)>,
        label: &str,
    ) -> CoreResult<&ConfirmedPathStep> {
        let spent = self.assert_spends_tip(transaction, label)?.outpoint;
        let txid_before_broadcast = transaction.compute_txid();
        let txid = self.core.accept_and_broadcast(transaction, label)?;
        if txid != txid_before_broadcast {
            return Err(CoreHarnessError::new(format!(
                "{label} txid changed while attaching or broadcasting witness"
            )));
        }
        let confirmation = self
            .core
            .mine_and_assert_included(txid, self.mining_address)?;

        let is_terminal = next.is_none();
        let next =
            next.map(|(vout, output)| ConfirmedOutput::new(OutPoint::new(txid, vout), output));
        if let Some(output) = &next {
            self.core.assert_unspent(output)?;
        }
        if is_terminal {
            self.core.assert_transaction_outputs_unspent(transaction)?;
        }
        self.tip.clone_from(&next);
        self.confirmed_steps.push(ConfirmedPathStep {
            label: label.to_owned(),
            txid,
            spent,
            next,
            confirmation,
        });
        self.confirmed_steps
            .last()
            .ok_or_else(|| CoreHarnessError::new("confirmed path step was not retained"))
    }

    fn assert_spends_tip(
        &self,
        transaction: &Transaction,
        label: &str,
    ) -> CoreResult<&ConfirmedOutput> {
        let tip = self.tip.as_ref().ok_or_else(|| {
            CoreHarnessError::new(format!("cannot execute {label} after terminal path step"))
        })?;
        if transaction.input.len() != 1 {
            return Err(CoreHarnessError::new(format!(
                "{label} must have exactly one graph-state input"
            )));
        }
        if transaction.input[0].previous_output != tip.outpoint {
            return Err(CoreHarnessError::new(format!(
                "{label} does not spend the current graph-state outpoint"
            )));
        }
        let output_value = transaction.output.iter().try_fold(0_u64, |sum, output| {
            sum.checked_add(output.value.to_sat())
                .ok_or_else(|| CoreHarnessError::new(format!("{label} output value overflow")))
        })?;
        if output_value > tip.output.value.to_sat() {
            return Err(CoreHarnessError::new(format!(
                "{label} creates more value than its graph-state input"
            )));
        }
        Ok(tip)
    }
}

fn compact_json(input: &str) -> String {
    input
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn bitcoin_amount(satoshis: u64) -> String {
    format!("{}.{:08}", satoshis / 100_000_000, satoshis % 100_000_000)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(encoded: &str) -> CoreResult<Vec<u8>> {
    let mut chunks = encoded.as_bytes().chunks_exact(2);
    let bytes = chunks
        .by_ref()
        .map(|pair| Ok((decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?))
        .collect::<CoreResult<Vec<_>>>()?;
    if !chunks.remainder().is_empty() {
        return Err(CoreHarnessError::new(
            "Bitcoin Core returned odd-length hex",
        ));
    }
    Ok(bytes)
}

fn decode_nibble(byte: u8) -> CoreResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(CoreHarnessError::new("Bitcoin Core returned non-hex data")),
    }
}

fn required_os(name: &'static str) -> CoreResult<OsString> {
    env::var_os(name).ok_or_else(|| {
        CoreHarnessError::new(format!("managed regtest omitted required variable {name}"))
    })
}

fn required_string(name: &'static str) -> CoreResult<String> {
    env::var(name).map_err(|_| {
        CoreHarnessError::new(format!("managed regtest omitted required variable {name}"))
    })
}
