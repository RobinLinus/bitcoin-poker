//! Canonical graph manifests and Merkle commitments.

use std::collections::HashSet;

use poker_codec::{CodecError, Encode, Writer};
use poker_settlement_types::{ChainError, LogicalNodeRecord, NodeId};
use sha2::{Digest, Sha256};

/// Deep-stack reference node count including the funded Deal-Alice obligation root.
pub const REFERENCE_TOTAL_NODE_COUNT: usize = 56_132;
/// Deep-stack reference number of post-activation gameplay transactions.
pub const REFERENCE_TRANSACTION_COUNT: usize = 56_131;
/// Deep-stack reference template count including origin-to-root activation.
pub const REFERENCE_WITH_ACTIVATION_TRANSACTION_COUNT: usize = 56_132;
/// Compatibility alias for the activation-inclusive template count.
pub const REFERENCE_WITH_FUNDING_TRANSACTION_COUNT: usize =
    REFERENCE_WITH_ACTIVATION_TRANSACTION_COUNT;
/// Deep-stack upper bound on post-activation semantic path length.
pub const REFERENCE_MAX_PATH_LENGTH: u16 = 33;

/// Canonical commitment and profile summary for one compiled graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphManifest {
    /// Identifier of the signed chain rules.
    pub chain_game_id: [u8; 32],
    /// SHA-256 of the canonical node-record Merkle root.
    pub graph_root: [u8; 32],
    /// Alice's verified Lamport public-bundle root.
    pub alice_lamport_bundle_root: [u8; 32],
    /// Bob's verified Lamport public-bundle root.
    pub bob_lamport_bundle_root: [u8; 32],
    /// Descriptor-selected compiler profile.
    pub compiler_id: [u8; 32],
    /// Descriptor-selected fee profile.
    pub fee_policy_id: [u8; 32],
    /// Number of state and terminal records, including the gameplay root.
    pub node_count: u32,
    /// Number of witness-independent post-activation gameplay transactions.
    pub transaction_count: u32,
    /// Longest ordinary semantic showdown path.
    pub maximum_path_length: u16,
}

impl Encode for GraphManifest {
    fn encode(&self, writer: &mut Writer) -> Result<(), CodecError> {
        self.chain_game_id.encode(writer)?;
        self.graph_root.encode(writer)?;
        self.alice_lamport_bundle_root.encode(writer)?;
        self.bob_lamport_bundle_root.encode(writer)?;
        self.compiler_id.encode(writer)?;
        self.fee_policy_id.encode(writer)?;
        self.node_count.encode(writer)?;
        self.transaction_count.encode(writer)?;
        self.maximum_path_length.encode(writer)
    }
}

/// Recompute the graph root from canonical node records.
///
/// Records are sorted by `node_id`, leaf-hashed with SHA-256, paired as
/// `SHA256(left || right)`, and an odd hash is promoted unchanged. The final
/// Merkle root is hashed once more as required by the specification.
///
/// # Errors
///
/// Rejects an empty graph, malformed records, duplicate identifiers, or a
/// record encoding failure.
pub fn compute_graph_root(records: &[LogicalNodeRecord]) -> Result<[u8; 32], ChainError> {
    if records.is_empty() {
        return Err(ChainError::InvalidLogicalRecord {
            reason: "graph contains no node records",
        });
    }
    let mut ordered: Vec<&LogicalNodeRecord> = records.iter().collect();
    ordered.sort_unstable_by_key(|record| record.node_id);
    let mut seen = HashSet::with_capacity(ordered.len());
    let mut level: Vec<[u8; 32]> = Vec::with_capacity(ordered.len());
    for record in ordered {
        record.validate()?;
        if !seen.insert(record.node_id) {
            return Err(ChainError::InvalidLogicalRecord {
                reason: "duplicate graph node identifier",
            });
        }
        level.push(Sha256::digest(record.encode_to_vec()?).into());
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut chunks = level.chunks_exact(2);
        for pair in &mut chunks {
            let mut hash = Sha256::new();
            hash.update(pair[0]);
            hash.update(pair[1]);
            next.push(hash.finalize().into());
        }
        if let Some(last) = chunks.remainder().first() {
            next.push(*last);
        }
        level = next;
    }
    Ok(Sha256::digest(level[0]).into())
}

/// Verify parent/child linkage independently of record ordering.
///
/// # Errors
///
/// Rejects missing roots, multiple roots, dangling children, wrong parent
/// pointers, duplicate child ownership, or unreachable records.
pub fn verify_tree_links(records: &[LogicalNodeRecord]) -> Result<NodeId, ChainError> {
    let mut by_id = std::collections::HashMap::with_capacity(records.len());
    for record in records {
        if by_id.insert(record.node_id, record).is_some() {
            return Err(invalid("duplicate graph node identifier"));
        }
    }
    let roots: Vec<_> = records
        .iter()
        .filter(|record| record.parent_node_id.is_none())
        .collect();
    let [root] = roots.as_slice() else {
        return Err(invalid("graph must contain exactly one root"));
    };
    let mut discovered = HashSet::with_capacity(records.len());
    let mut stack = vec![root.node_id];
    while let Some(parent_id) = stack.pop() {
        if !discovered.insert(parent_id) {
            return Err(invalid("node is reachable by more than one path"));
        }
        let parent = by_id
            .get(&parent_id)
            .ok_or_else(|| invalid("graph references a missing node"))?;
        for child_id in &parent.child_node_ids {
            let child = by_id
                .get(child_id)
                .ok_or_else(|| invalid("graph references a missing child"))?;
            if child.parent_node_id != Some(parent_id) {
                return Err(invalid("child parent pointer disagrees"));
            }
            stack.push(*child_id);
        }
    }
    if discovered.len() != records.len() {
        return Err(invalid("graph contains unreachable records"));
    }
    Ok(root.node_id)
}

const fn invalid(reason: &'static str) -> ChainError {
    ChainError::InvalidLogicalRecord { reason }
}
