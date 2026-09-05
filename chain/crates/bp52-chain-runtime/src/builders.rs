//! Fail-closed construction of action, reveal, showdown, and timeout witnesses.

use bitcoin::secp256k1::Secp256k1;
use bp52_chain_bitcoin::{
    AliceScoreCertificate, BitcoinBackendError, CardOpeningWitness, DefaultSighashSignature,
    RevealPattern, ShareRevealPredicate, ShowdownHandWitness, verify_alice_score_certificate,
    verify_alice_showdown, verify_bob_showdown_outcome, verify_showdown_hand,
    verify_sighash_default,
};
use bp52_chain_types::{
    Action, AuthorizationPolicy, EdgeKind, NodeId, NodeKind, Role, ShowdownOutcome, Street,
    root_node_id,
};
use bp52_lamport::{
    BobScoreCertificate, KeyContext, LamportPublicKey, LamportPurpose, LamportSecretKey, Score24,
    issue_bob_score_certificate, sign_alice_score,
};

use crate::backend::{edge_sighash, reject_mainnet, showdown_sighash};
use crate::{
    BitcoinSigner, ChainBackend, ChainMonitor, ConfirmedActiveNode, MatureTimeout,
    PublicPreimageStore, RuntimeError, SecretPreimageSource, ValidatedEdge, Witness,
    validate_exact_edge,
};

/// Revalidate every public datum carried by a non-timeout witness immediately
/// before it is attached to a transaction template.
///
/// Witnesses are intentionally serializable public data and can therefore be
/// decoded, copied, or mutated after construction. This attachment-boundary
/// check must remain independent of the witness builders: callers are not
/// required to have obtained a witness from this process.
pub(crate) fn validate_non_timeout_witness<'graph>(
    graph: &'graph dyn ChainBackend,
    active: &ConfirmedActiveNode<'_>,
    witness: &Witness,
) -> Result<ValidatedEdge<'graph>, RuntimeError> {
    active.validate(graph, witness.node_id())?;
    if matches!(witness, Witness::Timeout { .. }) {
        return Err(RuntimeError::TimeoutCapabilityRequired);
    }
    validate_witness_semantics(graph, witness)
}

/// Validate all graph bindings, authorization policy, signatures, OTS data,
/// openings, hand claims, score certificates, and branch outcomes carried by
/// one public witness. Monitor and attachment paths share this exact gate.
pub(crate) fn validate_witness_semantics<'graph>(
    graph: &'graph dyn ChainBackend,
    witness: &Witness,
) -> Result<ValidatedEdge<'graph>, RuntimeError> {
    let edge = validate_bound_witness_edge(graph, witness)?;
    match witness {
        Witness::Advance {
            phase,
            alice_signature,
            bob_signature,
            ..
        } => validate_advance_witness(graph, edge, *phase, *alice_signature, *bob_signature)?,
        Witness::Action {
            action,
            alice_signature,
            bob_signature,
            ..
        } => validate_action_witness(graph, edge, *action, *alice_signature, *bob_signature)?,
        Witness::Reveal {
            pattern,
            alice_signature,
            bob_signature,
            preimages,
            ..
        } => validate_reveal_witness(
            graph,
            edge,
            *pattern,
            *alice_signature,
            *bob_signature,
            preimages,
        )?,
        Witness::AliceShowdown {
            alice_signature,
            bob_signature,
            hand,
            certificate,
            ..
        } => validate_alice_showdown_witness(
            graph,
            edge,
            *alice_signature,
            *bob_signature,
            hand,
            certificate,
        )?,
        Witness::BobPayout {
            alice_showdown_node_id,
            outcome,
            alice_signature,
            bob_signature,
            hand,
            alice_certificate,
            bob_certificate,
            ..
        } => validate_bob_payout_witness(
            graph,
            edge,
            *alice_showdown_node_id,
            *outcome,
            *alice_signature,
            *bob_signature,
            hand,
            alice_certificate,
            bob_certificate,
        )?,
        Witness::Timeout {
            kind,
            beneficiary,
            alice_signature,
            bob_signature,
            ..
        } => validate_timeout_witness_semantics(
            graph,
            edge,
            *kind,
            *beneficiary,
            *alice_signature,
            *bob_signature,
        )?,
    }
    Ok(edge)
}

/// Build one exact fully preauthorized phase-progression witness.
///
/// The caller supplies only the child identifier selected by the public graph.
/// This function derives the phase from that exact edge and verifies both
/// fixed signatures before returning any witness bytes.
///
/// # Errors
///
/// Rejects an inactive parent, an unlisted/non-Advance child, a policy
/// mismatch, or either missing/invalid preauthorization.
pub fn build_advance_witness(
    graph: &dyn ChainBackend,
    active: &ConfirmedActiveNode<'_>,
    child_node_id: NodeId,
) -> Result<Witness, RuntimeError> {
    reject_mainnet(graph.network())?;
    let node_id = active.node_id();
    active.validate(graph, node_id)?;
    let listed = graph
        .edge(node_id, child_node_id)
        .ok_or(RuntimeError::MissingListedEdge {
            parent_node_id: node_id,
            child_node_id,
        })?;
    let EdgeKind::Advance { phase } = listed.kind else {
        return Err(RuntimeError::WrongAuthorization);
    };
    let edge = validate_exact_edge(graph, node_id, EdgeKind::Advance { phase })?;
    if edge.child.node_id != child_node_id
        || edge.edge.authorization != AuthorizationPolicy::BothPresigned
    {
        return Err(RuntimeError::WrongAuthorization);
    }
    let (alice_signature, bob_signature) = verified_pair(graph, edge)?;
    Ok(Witness::Advance {
        chain_game_id: graph.chain_game_id(),
        node_id,
        child_node_id,
        phase,
        alice_signature,
        bob_signature,
    })
}

/// Revalidate one timeout witness immediately before attachment, including
/// its unforgeable maturity capability.
pub(crate) fn validate_timeout_witness<'graph>(
    graph: &'graph dyn ChainBackend,
    mature_timeout: &MatureTimeout<'_>,
    witness: &Witness,
) -> Result<ValidatedEdge<'graph>, RuntimeError> {
    mature_timeout.validate(graph, witness.node_id())?;
    if !matches!(witness, Witness::Timeout { .. }) {
        return Err(RuntimeError::WrongAuthorization);
    }
    let edge = validate_witness_semantics(graph, witness)?;
    let timeout = edge.parent.timeout.ok_or(RuntimeError::InconsistentGraph {
        reason: "timeout witness parent has no timeout metadata",
    })?;
    if mature_timeout.maturity().node_id != edge.parent.node_id
        || mature_timeout.maturity().kind != timeout.kind
        || mature_timeout.maturity().csv != timeout.csv
    {
        return Err(RuntimeError::WrongAuthorization);
    }
    Ok(edge)
}

/// Build an exact action witness with the actor's live Bitcoin signature.
///
/// Only the opponent's signature is loaded from the preauthorization bundle.
/// The monitor retains the first complete witness so retransmitting the same
/// action does not call the live signer again. Requesting a different action
/// after issuance permanently halts the monitor.
///
/// # Errors
///
/// Rejects a wrong/missing graph edge, authorization mismatch, invalid fixed
/// or live Bitcoin signature, signer failure, or conflicting action reuse.
pub fn build_action_witness(
    graph: &dyn ChainBackend,
    monitor: &mut ChainMonitor,
    action: Action,
    signer: &dyn BitcoinSigner,
) -> Result<Witness, RuntimeError> {
    let node_id = monitor.confirmed_active_node(graph)?.node_id();
    if let Some(cached) = monitor.issued_authorization_witness(node_id).cloned() {
        if matches!(&cached, Witness::Action { action: issued, .. } if *issued == action) {
            if let Err(error) = validate_witness_semantics(graph, &cached) {
                monitor.halt_for_authorization_conflict();
                return Err(error);
            }
            return Ok(cached);
        }
        monitor.halt_for_authorization_conflict();
        return Err(RuntimeError::ConflictingActionAuthorization { node_id });
    }

    let edge = validate_exact_edge(graph, node_id, EdgeKind::Action(action))?;
    let AuthorizationPolicy::BettingAction { actor } = edge.edge.authorization else {
        return Err(RuntimeError::WrongAuthorization);
    };
    if edge.parent.node_kind != NodeKind::Betting {
        return Err(RuntimeError::WrongAuthorization);
    }
    let digest = edge_sighash(graph, edge)?;
    let opponent = actor.other();
    let opponent_signature = verified_preauthorization(graph, edge, opponent, digest)?;

    let prior = monitor.begin_authorization_issuance(node_id)?;
    let issued = (|| {
        let actor_signature =
            signer.sign_sighash_default(actor, node_id, edge.child.node_id, digest)?;
        verify_signature(graph, actor, digest, actor_signature)?;
        let (alice_signature, bob_signature) = match actor {
            Role::Alice => (actor_signature, opponent_signature),
            Role::Bob => (opponent_signature, actor_signature),
        };
        Ok::<_, RuntimeError>(Witness::Action {
            chain_game_id: graph.chain_game_id(),
            node_id,
            child_node_id: edge.child.node_id,
            action,
            alice_signature,
            bob_signature,
        })
    })();
    match issued {
        Ok(witness) => {
            monitor.complete_authorization_issuance(prior, witness.clone());
            Ok(witness)
        }
        Err(error) => Err(error),
    }
}

/// Build an exact betting-action witness from two just-in-time signatures.
///
/// This is the off-chain-channel counterpart of [`build_action_witness`]. It
/// deliberately performs no preauthorization lookup: both signatures must be
/// obtained only after the canonical ratchet selects this one child. The
/// caller is responsible for enforcing one durable selection per parent; this
/// function revalidates the graph edge, actor, digest, and both signatures.
///
/// # Errors
///
/// Rejects a missing/non-action edge, wrong actor, authorization mismatch, or
/// either signature not covering the exact selected transaction.
pub fn build_selected_action_witness(
    graph: &dyn ChainBackend,
    parent_node_id: NodeId,
    child_node_id: NodeId,
    action: Action,
    actor: Role,
    alice_signature: DefaultSighashSignature,
    bob_signature: DefaultSighashSignature,
) -> Result<Witness, RuntimeError> {
    reject_mainnet(graph.network())?;
    let edge = validate_exact_edge(graph, parent_node_id, EdgeKind::Action(action))?;
    if edge.child.node_id != child_node_id
        || edge.parent.node_kind != NodeKind::Betting
        || edge.edge.authorization != (AuthorizationPolicy::BettingAction { actor })
    {
        return Err(RuntimeError::WrongAuthorization);
    }
    let digest = edge_sighash(graph, edge)?;
    verify_signature(graph, Role::Alice, digest, alice_signature)?;
    verify_signature(graph, Role::Bob, digest, bob_signature)?;
    Ok(Witness::Action {
        chain_game_id: graph.chain_game_id(),
        node_id: parent_node_id,
        child_node_id,
        action,
        alice_signature,
        bob_signature,
    })
}

/// Sign one exact betting edge after the off-chain ratchet selects it.
///
/// This is the narrow signing-oracle boundary used by each participant. It
/// derives the digest from the authenticated graph and refuses arbitrary
/// digests, endpoint substitutions, non-betting edges, or a claimed actor that
/// differs from the graph policy. The signer implementation still enforces
/// that `signer_role` is the locally held key.
///
/// # Errors
///
/// Rejects an unlisted/substituted edge, wrong actor or signer, external signer
/// failure, or a signature that does not authorize the selected transaction.
pub fn sign_selected_action(
    graph: &dyn ChainBackend,
    parent_node_id: NodeId,
    child_node_id: NodeId,
    action: Action,
    actor: Role,
    signer_role: Role,
    signer: &dyn BitcoinSigner,
) -> Result<DefaultSighashSignature, RuntimeError> {
    reject_mainnet(graph.network())?;
    let edge = validate_exact_edge(graph, parent_node_id, EdgeKind::Action(action))?;
    if edge.child.node_id != child_node_id
        || edge.parent.node_kind != NodeKind::Betting
        || edge.edge.authorization != (AuthorizationPolicy::BettingAction { actor })
    {
        return Err(RuntimeError::WrongAuthorization);
    }
    let digest = edge_sighash(graph, edge)?;
    let signature =
        signer.sign_sighash_default(signer_role, parent_node_id, child_node_id, digest)?;
    verify_signature(graph, signer_role, digest, signature)?;
    Ok(signature)
}

/// Build the unique normal reveal witness at a deal/community reveal node.
///
/// # Errors
///
/// Rejects wrong node shape, wrong count/order, invalid lengths/hashes, or
/// either invalid preauthorization signature.
pub fn build_reveal_witness(
    graph: &dyn ChainBackend,
    active: &ConfirmedActiveNode<'_>,
    preimages: &[Vec<u8>],
    signer: &dyn BitcoinSigner,
) -> Result<Witness, RuntimeError> {
    reject_mainnet(graph.network())?;
    let node_id = active.node_id();
    active.validate(graph, node_id)?;
    build_selected_reveal_witness(graph, node_id, preimages, signer)
}

/// Build the unique reveal edge from an authenticated off-chain parent.
///
/// Unlike [`build_reveal_witness`], this takes the exact durable ratchet head
/// instead of a confirmation capability. The edge itself is unique and the
/// counterparty signature was safely fixed during graph setup.
pub fn build_selected_reveal_witness(
    graph: &dyn ChainBackend,
    node_id: NodeId,
    preimages: &[Vec<u8>],
    signer: &dyn BitcoinSigner,
) -> Result<Witness, RuntimeError> {
    reject_mainnet(graph.network())?;
    let pattern = unique_reveal_pattern(graph, node_id)?;
    let edge = validate_exact_edge(graph, node_id, reveal_edge_kind(pattern))?;
    if !matches!(
        edge.edge.authorization,
        AuthorizationPolicy::RevealPreimages { revealer } if revealer == pattern.revealer()
    ) {
        return Err(RuntimeError::WrongAuthorization);
    }
    validate_reveal_node(edge.parent.node_kind, pattern)?;
    let borrowed: Vec<&[u8]> = preimages.iter().map(Vec::as_slice).collect();
    ShareRevealPredicate::new(graph.accepted_deal(), pattern).verify(&borrowed)?;
    let digest = edge_sighash(graph, edge)?;
    let revealer = pattern.revealer();
    let opponent_signature = verified_preauthorization(graph, edge, revealer.other(), digest)?;
    let revealer_signature =
        signer.sign_sighash_default(revealer, node_id, edge.child.node_id, digest)?;
    verify_signature(graph, revealer, digest, revealer_signature)?;
    let (alice_signature, bob_signature) = match revealer {
        Role::Alice => (revealer_signature, opponent_signature),
        Role::Bob => (opponent_signature, revealer_signature),
    };
    Ok(Witness::Reveal {
        chain_game_id: graph.chain_game_id(),
        node_id,
        child_node_id: edge.child.node_id,
        pattern,
        alice_signature,
        bob_signature,
        preimages: preimages.to_vec(),
    })
}

/// Build Alice's exact hand witness and issue her one score certificate.
///
/// Previously published counterparty/community openings are taken only from
/// `public_preimages`; Alice's still-private hole openings come only from
/// `alice_secret`.
///
/// # Errors
///
/// Rejects graph/key/store substitution, missing or invalid openings, an
/// untrue hand claim, invalid preauthorizations, or score-key reuse.
pub fn build_alice_showdown_witness(
    graph: &dyn ChainBackend,
    monitor: &mut ChainMonitor,
    public_preimages: &PublicPreimageStore,
    alice_secret: &dyn SecretPreimageSource,
    subset_id: u8,
    score: u32,
    score_ots: &mut LamportSecretKey,
    alice_signer: &dyn BitcoinSigner,
) -> Result<Witness, RuntimeError> {
    let node_id = monitor.confirmed_active_node(graph)?.node_id();
    public_preimages.ensure_binding(graph.chain_game_id(), graph.accepted_deal())?;
    let score24 = Score24::new(score)?;
    if let Some(cached) = monitor.issued_authorization_witness(node_id).cloned() {
        if matches!(
            &cached,
            Witness::AliceShowdown { certificate, .. } if certificate.score_a() == score24
        ) {
            if let Err(error) = validate_witness_semantics(graph, &cached) {
                monitor.halt_for_authorization_conflict();
                score_ots.erase_after_branch_confirmation();
                return Err(error);
            }
            return Ok(cached);
        }
        monitor.halt_for_authorization_conflict();
        score_ots.erase_after_branch_confirmation();
        return Err(RuntimeError::ConflictingOtsAuthorization { node_id });
    }

    let edge = validate_exact_edge(graph, node_id, EdgeKind::AliceShowdown)?;
    if edge.parent.node_kind != NodeKind::AliceShowdown
        || edge.edge.authorization != AuthorizationPolicy::AliceScore
    {
        return Err(RuntimeError::WrongAuthorization);
    }
    let hand = showdown_hand(
        graph,
        public_preimages,
        alice_secret,
        Role::Alice,
        subset_id,
        score,
    )?;
    let verified_hand = verify_showdown_hand(graph.accepted_deal(), Role::Alice, &hand)?;
    let digest = showdown_sighash(graph, edge, verified_hand.score().category())?;
    let bob_signature = verified_preauthorization(graph, edge, Role::Bob, digest)?;
    let alice_signature =
        alice_signer.sign_sighash_default(Role::Alice, node_id, edge.child.node_id, digest)?;
    verify_signature(graph, Role::Alice, digest, alice_signature)?;
    let public_key = graph
        .lamport_public_key(node_id, LamportPurpose::AliceScore24Bit)
        .ok_or(RuntimeError::InconsistentGraph {
            reason: "Alice showdown node has no score Lamport public key",
        })?;
    validate_public_context(graph, node_id, LamportPurpose::AliceScore24Bit, public_key)?;
    validate_secret_context(graph, node_id, LamportPurpose::AliceScore24Bit, score_ots)?;
    if score_ots.signature_was_issued() {
        monitor.halt_for_authorization_conflict();
        score_ots.erase_after_branch_confirmation();
        return Err(bp52_lamport::LamportError::KeyAlreadyUsed.into());
    }
    if score_ots.is_erased() {
        monitor.halt_for_authorization_conflict();
        return Err(bp52_lamport::LamportError::KeyDestroyed.into());
    }
    if !score_ots.matches_public_key(public_key) {
        return Err(RuntimeError::InconsistentGraph {
            reason: "score Lamport secret does not match the compiled public key",
        });
    }
    let prior = monitor.begin_authorization_issuance(node_id)?;
    let issued = (|| {
        let score_signature = sign_alice_score(score_ots, score24)?;
        let (_, certificate) = verify_alice_showdown(
            graph.accepted_deal(),
            graph.chain_game_id(),
            public_key.context().node_id,
            public_key,
            &hand,
            score_signature,
        )?;
        Ok::<_, RuntimeError>(Witness::AliceShowdown {
            chain_game_id: graph.chain_game_id(),
            node_id,
            child_node_id: edge.child.node_id,
            alice_signature,
            bob_signature,
            hand,
            certificate,
        })
    })();
    match issued {
        Ok(witness) => {
            monitor.complete_authorization_issuance(prior, witness.clone());
            Ok(witness)
        }
        Err(error) => {
            score_ots.erase_after_branch_confirmation();
            Err(error)
        }
    }
}

/// Build Alice's unique showdown transition from a durable off-chain head.
/// The Lamport key remains the caller's persistent one-time-use guard.
#[allow(clippy::too_many_arguments)]
pub fn build_selected_alice_showdown_witness(
    graph: &dyn ChainBackend,
    parent_node_id: NodeId,
    public_preimages: &PublicPreimageStore,
    alice_secret: &dyn SecretPreimageSource,
    subset_id: u8,
    score: u32,
    score_ots: &mut LamportSecretKey,
    alice_signer: &dyn BitcoinSigner,
) -> Result<Witness, RuntimeError> {
    let mut guard = ChainMonitor::for_offchain_authorization(graph, parent_node_id)?;
    build_alice_showdown_witness(
        graph,
        &mut guard,
        public_preimages,
        alice_secret,
        subset_id,
        score,
        score_ots,
        alice_signer,
    )
}

/// Build Bob's score-certified terminal witness and request his live signature.
///
/// Alice's certificate is loaded from the exact confirmed-parent entry in
/// `public_preimages`. Bob's signer is called only after the graph edge, all
/// repeated/new openings, that certificate, Bob's claimed hand, comparison
/// branch, Alice's fixed preauthorization, and Bob's score-key binding have
/// passed verification. The monitor caches the issued witness so a retry of
/// the same payout does not reuse Bob's one-time score key or live signer.
///
/// # Errors
///
/// Rejects any invalid graph/runtime input, a missing recovered certificate,
/// wrong outcome, invalid Alice certificate/signature, Bob score-key reuse,
/// or invalid live Bob signature.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn build_bob_payout_witness(
    graph: &dyn ChainBackend,
    monitor: &mut ChainMonitor,
    public_preimages: &PublicPreimageStore,
    bob_secret: &dyn SecretPreimageSource,
    subset_id: u8,
    score_b: u32,
    outcome_branch: ShowdownOutcome,
    bob_score_ots: &mut LamportSecretKey,
    bob_signer: &dyn BitcoinSigner,
) -> Result<Witness, RuntimeError> {
    let node_id = monitor.confirmed_active_node(graph)?.node_id();
    let score24 = Score24::new(score_b)?;
    if let Some(cached) = monitor.issued_authorization_witness(node_id).cloned() {
        if matches!(
            &cached,
            Witness::BobPayout {
                outcome,
                hand,
                bob_certificate,
                ..
            } if *outcome == outcome_branch
                && hand.subset_id() == subset_id
                && bob_certificate.score_b() == score24
        ) {
            if let Err(error) = validate_witness_semantics(graph, &cached) {
                monitor.halt_for_authorization_conflict();
                bob_score_ots.erase_after_branch_confirmation();
                return Err(error);
            }
            return Ok(cached);
        }
        monitor.halt_for_authorization_conflict();
        bob_score_ots.erase_after_branch_confirmation();
        return Err(RuntimeError::ConflictingOtsAuthorization { node_id });
    }
    let edge = validate_exact_edge(graph, node_id, EdgeKind::BobPayout(outcome_branch))?;
    if edge.parent.node_kind != NodeKind::BobTerminal
        || edge.edge.authorization != AuthorizationPolicy::BobLivePayout
    {
        return Err(RuntimeError::WrongAuthorization);
    }
    public_preimages.ensure_binding(graph.chain_game_id(), graph.accepted_deal())?;
    let alice_showdown_node_id =
        edge.parent
            .parent_node_id
            .ok_or(RuntimeError::InconsistentGraph {
                reason: "Bob terminal node has no Alice showdown parent",
            })?;
    let alice_node = graph
        .node(alice_showdown_node_id)
        .ok_or(RuntimeError::NodeNotFound {
            node_id: alice_showdown_node_id,
        })?;
    if alice_node.node_kind != NodeKind::AliceShowdown {
        return Err(RuntimeError::InconsistentGraph {
            reason: "Bob terminal parent is not an Alice showdown node",
        });
    }
    let alice_certificate = public_preimages
        .alice_score_certificate(alice_showdown_node_id)
        .ok_or(RuntimeError::MissingAliceScoreCertificate {
            node_id: alice_showdown_node_id,
        })?;
    let alice_score_key = graph
        .lamport_public_key(alice_showdown_node_id, LamportPurpose::AliceScore24Bit)
        .ok_or(RuntimeError::InconsistentGraph {
            reason: "Alice showdown parent has no score Lamport public key",
        })?;
    validate_public_context(
        graph,
        alice_showdown_node_id,
        LamportPurpose::AliceScore24Bit,
        alice_score_key,
    )?;
    let bob_score_key = graph
        .lamport_public_key(node_id, LamportPurpose::BobScore24Bit)
        .ok_or(RuntimeError::InconsistentGraph {
            reason: "Bob terminal node has no score Lamport public key",
        })?;
    validate_public_context(graph, node_id, LamportPurpose::BobScore24Bit, bob_score_key)?;
    let hand = showdown_hand(
        graph,
        public_preimages,
        bob_secret,
        Role::Bob,
        subset_id,
        score_b,
    )?;
    validate_bob_outcome_before_signing(
        graph,
        alice_showdown_node_id,
        alice_score_key,
        alice_certificate,
        &hand,
        outcome_branch,
    )?;
    let verified_hand = verify_showdown_hand(graph.accepted_deal(), Role::Bob, &hand)?;
    let digest = showdown_sighash(graph, edge, verified_hand.score().category())?;
    let alice_signature = verified_preauthorization(graph, edge, Role::Alice, digest)?;
    validate_secret_context(graph, node_id, LamportPurpose::BobScore24Bit, bob_score_ots)?;
    if bob_score_ots.signature_was_issued() {
        monitor.halt_for_authorization_conflict();
        bob_score_ots.erase_after_branch_confirmation();
        return Err(bp52_lamport::LamportError::KeyAlreadyUsed.into());
    }
    if bob_score_ots.is_erased() {
        monitor.halt_for_authorization_conflict();
        return Err(bp52_lamport::LamportError::KeyDestroyed.into());
    }
    if !bob_score_ots.matches_public_key(bob_score_key) {
        return Err(RuntimeError::InconsistentGraph {
            reason: "Bob score Lamport secret does not match the compiled public key",
        });
    }

    let prior = monitor.begin_authorization_issuance(node_id)?;
    let issued = (|| {
        let bob_certificate = issue_bob_score_certificate(bob_score_ots, score24)?;
        verify_bob_showdown_outcome(
            graph.accepted_deal(),
            graph.chain_game_id(),
            alice_score_key.context().node_id,
            bob_score_key.context().node_id,
            alice_score_key,
            bob_score_key,
            alice_certificate,
            &bob_certificate,
            &hand,
            outcome_branch,
        )?;
        let bob_signature =
            bob_signer.sign_sighash_default(Role::Bob, node_id, edge.child.node_id, digest)?;
        verify_signature(graph, Role::Bob, digest, bob_signature)?;
        Ok::<_, RuntimeError>(Witness::BobPayout {
            chain_game_id: graph.chain_game_id(),
            node_id,
            child_node_id: edge.child.node_id,
            alice_showdown_node_id,
            outcome: outcome_branch,
            alice_signature,
            bob_signature,
            hand,
            alice_certificate: alice_certificate.clone(),
            bob_certificate,
        })
    })();
    match issued {
        Ok(witness) => {
            monitor.complete_authorization_issuance(prior, witness.clone());
            Ok(witness)
        }
        Err(error) => {
            bob_score_ots.erase_after_branch_confirmation();
            Err(error)
        }
    }
}

/// Build Bob's unique payout transition from a durable off-chain head.
/// The selected outcome and one-time score key are revalidated identically to
/// the confirmed-state builder, without exposing a CSV capability.
#[allow(clippy::too_many_arguments)]
pub fn build_selected_bob_payout_witness(
    graph: &dyn ChainBackend,
    parent_node_id: NodeId,
    public_preimages: &PublicPreimageStore,
    bob_secret: &dyn SecretPreimageSource,
    subset_id: u8,
    score_b: u32,
    outcome_branch: ShowdownOutcome,
    bob_score_ots: &mut LamportSecretKey,
    bob_signer: &dyn BitcoinSigner,
) -> Result<Witness, RuntimeError> {
    let mut guard = ChainMonitor::for_offchain_authorization(graph, parent_node_id)?;
    build_bob_payout_witness(
        graph,
        &mut guard,
        public_preimages,
        bob_secret,
        subset_id,
        score_b,
        outcome_branch,
        bob_score_ots,
        bob_signer,
    )
}

fn validate_bob_outcome_before_signing(
    graph: &dyn ChainBackend,
    _alice_showdown_node_id: NodeId,
    alice_score_key: &LamportPublicKey,
    alice_certificate: &AliceScoreCertificate,
    hand: &ShowdownHandWitness,
    outcome: ShowdownOutcome,
) -> Result<(), RuntimeError> {
    let score_a = verify_alice_score_certificate(
        graph.chain_game_id(),
        alice_score_key.context().node_id,
        alice_score_key,
        alice_certificate,
    )?;
    let score_b = verify_showdown_hand(graph.accepted_deal(), Role::Bob, hand)?.score();
    let valid = match outcome {
        ShowdownOutcome::AliceWin => score_a > score_b,
        ShowdownOutcome::BobWin => score_a < score_b,
        ShowdownOutcome::Split => score_a == score_b,
    };
    if !valid {
        return Err(BitcoinBackendError::WrongShowdownOutcome {
            score_a: score_a.as_u32(),
            score_b: score_b.as_u32(),
            outcome: match outcome {
                ShowdownOutcome::AliceWin => "AliceWin",
                ShowdownOutcome::BobWin => "BobWin",
                ShowdownOutcome::Split => "Split",
            },
        }
        .into());
    }
    Ok(())
}

/// Build a timeout witness after exact CSV maturity.
///
/// The defaulting player's fixed preauthorization is loaded before the
/// beneficiary is asked for a live signature. Both signatures cover the same
/// exact timeout template and are emitted in canonical Alice-then-Bob order.
///
/// # Errors
///
/// Rejects a node without matching timeout metadata, an early height, graph
/// inconsistency, missing or invalid fixed preauthorization, signer failure,
/// or an invalid returned signature.
pub fn build_timeout_witness(
    graph: &dyn ChainBackend,
    mature_timeout: &MatureTimeout<'_>,
    signer: &dyn BitcoinSigner,
) -> Result<Witness, RuntimeError> {
    reject_mainnet(graph.network())?;
    let node_id = mature_timeout.node_id();
    mature_timeout.validate(graph, node_id)?;
    let parent = graph
        .node(node_id)
        .ok_or(RuntimeError::NodeNotFound { node_id })?;
    let timeout = parent.timeout.ok_or(RuntimeError::InconsistentGraph {
        reason: "node has no timeout metadata",
    })?;
    if mature_timeout.maturity().kind != timeout.kind
        || mature_timeout.maturity().csv != timeout.csv
    {
        return Err(RuntimeError::InconsistentGraph {
            reason: "mature timeout capability differs from graph metadata",
        });
    }
    let edge = validate_exact_edge(graph, node_id, EdgeKind::Timeout(timeout.kind))?;
    if edge.edge.timeout != Some(timeout)
        || edge.edge.authorization
            != (AuthorizationPolicy::Timeout {
                beneficiary: timeout.beneficiary,
            })
    {
        return Err(RuntimeError::WrongAuthorization);
    }
    let digest = edge_sighash(graph, edge)?;
    let beneficiary = timeout.beneficiary;
    let opponent = beneficiary.other();
    let opponent_signature = verified_preauthorization(graph, edge, opponent, digest)?;
    let beneficiary_signature =
        signer.sign_sighash_default(timeout.beneficiary, node_id, edge.child.node_id, digest)?;
    verify_signature(graph, beneficiary, digest, beneficiary_signature)?;
    let (alice_signature, bob_signature) = match beneficiary {
        Role::Alice => (beneficiary_signature, opponent_signature),
        Role::Bob => (opponent_signature, beneficiary_signature),
    };
    Ok(Witness::Timeout {
        chain_game_id: graph.chain_game_id(),
        node_id,
        child_node_id: edge.child.node_id,
        kind: timeout.kind,
        beneficiary,
        alice_signature,
        bob_signature,
    })
}

fn validate_bound_witness_edge<'graph>(
    graph: &'graph dyn ChainBackend,
    witness: &Witness,
) -> Result<ValidatedEdge<'graph>, RuntimeError> {
    if witness.chain_game_id() != graph.chain_game_id() {
        return Err(RuntimeError::WrongChainGame);
    }
    let edge = validate_exact_edge(graph, witness.node_id(), witness.edge_kind())?;
    if edge.child.node_id != witness.child_node_id() {
        return Err(RuntimeError::InconsistentGraph {
            reason: "runtime witness names a different child",
        });
    }
    Ok(edge)
}

fn validate_action_witness(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    action: Action,
    alice_signature: DefaultSighashSignature,
    bob_signature: DefaultSighashSignature,
) -> Result<(), RuntimeError> {
    let AuthorizationPolicy::BettingAction { actor: _ } = edge.edge.authorization else {
        return Err(RuntimeError::WrongAuthorization);
    };
    if edge.parent.node_kind != NodeKind::Betting || edge.edge.kind != EdgeKind::Action(action) {
        return Err(RuntimeError::WrongAuthorization);
    }
    let digest = edge_sighash(graph, edge)?;
    // Betting siblings are deliberately absent from the setup-time
    // preauthorization bundle. Both participants authorize only the one edge
    // selected by the durable off-chain ratchet, so witness validation must
    // verify the two exact BIP340 signatures without requiring a nonexistent
    // fixed preauthorization entry.
    verify_signature(graph, Role::Alice, digest, alice_signature)?;
    verify_signature(graph, Role::Bob, digest, bob_signature)
}

fn validate_advance_witness(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    phase: bp52_chain_types::Phase,
    alice_signature: DefaultSighashSignature,
    bob_signature: DefaultSighashSignature,
) -> Result<(), RuntimeError> {
    if edge.edge.kind != (EdgeKind::Advance { phase })
        || edge.edge.authorization != AuthorizationPolicy::BothPresigned
    {
        return Err(RuntimeError::WrongAuthorization);
    }
    verify_fixed_pair(graph, edge, alice_signature, bob_signature)
}

fn validate_reveal_witness(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    pattern: RevealPattern,
    alice_signature: DefaultSighashSignature,
    bob_signature: DefaultSighashSignature,
    preimages: &[Vec<u8>],
) -> Result<(), RuntimeError> {
    let canonical_pattern = unique_reveal_pattern(graph, edge.parent.node_id)?;
    if canonical_pattern != pattern
        || !matches!(
            edge.edge.authorization,
            AuthorizationPolicy::RevealPreimages { revealer } if revealer == pattern.revealer()
        )
    {
        return Err(RuntimeError::WrongAuthorization);
    }
    validate_reveal_node(edge.parent.node_kind, pattern)?;
    let borrowed: Vec<&[u8]> = preimages.iter().map(Vec::as_slice).collect();
    ShareRevealPredicate::new(graph.accepted_deal(), pattern).verify(&borrowed)?;
    let digest = edge_sighash(graph, edge)?;
    let revealer = pattern.revealer();
    let (revealer_signature, opponent_signature) = match revealer {
        Role::Alice => (alice_signature, bob_signature),
        Role::Bob => (bob_signature, alice_signature),
    };
    verify_fixed_preauthorization(graph, edge, revealer.other(), digest, opponent_signature)?;
    verify_signature(graph, revealer, digest, revealer_signature)
}

fn validate_alice_showdown_witness(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    alice_signature: DefaultSighashSignature,
    bob_signature: DefaultSighashSignature,
    hand: &ShowdownHandWitness,
    certificate: &AliceScoreCertificate,
) -> Result<(), RuntimeError> {
    if edge.parent.node_kind != NodeKind::AliceShowdown
        || edge.edge.authorization != AuthorizationPolicy::AliceScore
    {
        return Err(RuntimeError::WrongAuthorization);
    }
    let category = verify_showdown_hand(graph.accepted_deal(), Role::Alice, hand)?
        .score()
        .category();
    let digest = showdown_sighash(graph, edge, category)?;
    verify_fixed_preauthorization(graph, edge, Role::Bob, digest, bob_signature)?;
    verify_signature(graph, Role::Alice, digest, alice_signature)?;
    let public_key = graph
        .lamport_public_key(edge.parent.node_id, LamportPurpose::AliceScore24Bit)
        .ok_or(RuntimeError::InconsistentGraph {
            reason: "Alice showdown node has no score Lamport public key",
        })?;
    validate_public_context(
        graph,
        edge.parent.node_id,
        LamportPurpose::AliceScore24Bit,
        public_key,
    )?;
    let (_, verified_certificate) = verify_alice_showdown(
        graph.accepted_deal(),
        graph.chain_game_id(),
        public_key.context().node_id,
        public_key,
        hand,
        certificate.lamport_signature().clone(),
    )?;
    if &verified_certificate != certificate {
        return Err(RuntimeError::InconsistentGraph {
            reason: "Alice showdown hand and score certificate disagree",
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_bob_payout_witness(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    alice_showdown_node_id: NodeId,
    outcome: ShowdownOutcome,
    alice_signature: DefaultSighashSignature,
    bob_signature: DefaultSighashSignature,
    hand: &ShowdownHandWitness,
    alice_certificate: &AliceScoreCertificate,
    bob_certificate: &BobScoreCertificate,
) -> Result<(), RuntimeError> {
    if edge.parent.node_kind != NodeKind::BobTerminal
        || edge.edge.authorization != AuthorizationPolicy::BobLivePayout
        || edge.parent.parent_node_id != Some(alice_showdown_node_id)
    {
        return Err(RuntimeError::WrongAuthorization);
    }
    let alice_node = graph
        .node(alice_showdown_node_id)
        .ok_or(RuntimeError::NodeNotFound {
            node_id: alice_showdown_node_id,
        })?;
    alice_node.validate()?;
    if alice_node.node_kind != NodeKind::AliceShowdown {
        return Err(RuntimeError::InconsistentGraph {
            reason: "Bob terminal parent is not an Alice showdown node",
        });
    }
    let alice_score_key = graph
        .lamport_public_key(alice_showdown_node_id, LamportPurpose::AliceScore24Bit)
        .ok_or(RuntimeError::InconsistentGraph {
            reason: "Alice showdown parent has no score Lamport public key",
        })?;
    validate_public_context(
        graph,
        alice_showdown_node_id,
        LamportPurpose::AliceScore24Bit,
        alice_score_key,
    )?;
    let bob_score_key = graph
        .lamport_public_key(edge.parent.node_id, LamportPurpose::BobScore24Bit)
        .ok_or(RuntimeError::InconsistentGraph {
            reason: "Bob terminal node has no score Lamport public key",
        })?;
    validate_public_context(
        graph,
        edge.parent.node_id,
        LamportPurpose::BobScore24Bit,
        bob_score_key,
    )?;
    let verified_bob = verify_bob_showdown_outcome(
        graph.accepted_deal(),
        graph.chain_game_id(),
        alice_score_key.context().node_id,
        bob_score_key.context().node_id,
        alice_score_key,
        bob_score_key,
        alice_certificate,
        bob_certificate,
        hand,
        outcome,
    )?;
    let digest = showdown_sighash(graph, edge, verified_bob.score().category())?;
    verify_fixed_preauthorization(graph, edge, Role::Alice, digest, alice_signature)?;
    verify_signature(graph, Role::Bob, digest, bob_signature)
}

fn validate_timeout_witness_semantics(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    kind: bp52_chain_types::TimeoutKind,
    beneficiary: Role,
    alice_signature: DefaultSighashSignature,
    bob_signature: DefaultSighashSignature,
) -> Result<(), RuntimeError> {
    let timeout = edge.parent.timeout.ok_or(RuntimeError::InconsistentGraph {
        reason: "timeout witness parent has no timeout metadata",
    })?;
    if kind != timeout.kind
        || beneficiary != timeout.beneficiary
        || edge.edge.timeout != Some(timeout)
        || edge.edge.authorization
            != (AuthorizationPolicy::Timeout {
                beneficiary: timeout.beneficiary,
            })
    {
        return Err(RuntimeError::WrongAuthorization);
    }
    let digest = edge_sighash(graph, edge)?;
    let (beneficiary_signature, opponent_signature) = match beneficiary {
        Role::Alice => (alice_signature, bob_signature),
        Role::Bob => (bob_signature, alice_signature),
    };
    verify_fixed_preauthorization(graph, edge, beneficiary.other(), digest, opponent_signature)?;
    verify_signature(graph, beneficiary, digest, beneficiary_signature)
}

fn verify_fixed_pair(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    alice_signature: DefaultSighashSignature,
    bob_signature: DefaultSighashSignature,
) -> Result<(), RuntimeError> {
    let digest = edge_sighash(graph, edge)?;
    verify_fixed_preauthorization(graph, edge, Role::Alice, digest, alice_signature)?;
    verify_fixed_preauthorization(graph, edge, Role::Bob, digest, bob_signature)
}

fn verify_fixed_preauthorization(
    graph: &dyn ChainBackend,
    edge: ValidatedEdge<'_>,
    role: Role,
    digest: [u8; 32],
    witness_signature: DefaultSighashSignature,
) -> Result<(), RuntimeError> {
    // Keep the graph's preauthorization as an availability/integrity gate,
    // but do not require a confirmed peer to reproduce the same Schnorr byte
    // string. BIP340 signing may validly produce another signature for the
    // same fixed DEFAULT digest and public key.
    let _ = verified_preauthorization(graph, edge, role, digest)?;
    verify_signature(graph, role, digest, witness_signature)
}

fn validate_secret_context(
    graph: &dyn ChainBackend,
    _node_id: NodeId,
    purpose: LamportPurpose,
    secret: &LamportSecretKey,
) -> Result<(), RuntimeError> {
    let context = secret.context();
    if context.chain_game_id != graph.chain_game_id() {
        return Err(RuntimeError::WrongChainGame);
    }
    if context.node_id != root_node_id(&graph.chain_game_id()) || context.purpose != purpose {
        return Err(RuntimeError::InconsistentGraph {
            reason: "Lamport secret context does not match runtime node/purpose",
        });
    }
    Ok(())
}

fn validate_public_context(
    graph: &dyn ChainBackend,
    _node_id: NodeId,
    purpose: LamportPurpose,
    public: &LamportPublicKey,
) -> Result<(), RuntimeError> {
    if public.context()
        != KeyContext::new(
            graph.chain_game_id(),
            root_node_id(&graph.chain_game_id()),
            purpose,
        )
    {
        return Err(RuntimeError::InconsistentGraph {
            reason: "Lamport public context does not match runtime node/purpose",
        });
    }
    Ok(())
}

fn verified_pair(
    graph: &dyn ChainBackend,
    edge: crate::backend::ValidatedEdge<'_>,
) -> Result<(DefaultSighashSignature, DefaultSighashSignature), RuntimeError> {
    let digest = edge_sighash(graph, edge)?;
    Ok((
        verified_preauthorization(graph, edge, Role::Alice, digest)?,
        verified_preauthorization(graph, edge, Role::Bob, digest)?,
    ))
}

fn verified_preauthorization(
    graph: &dyn ChainBackend,
    edge: crate::backend::ValidatedEdge<'_>,
    role: Role,
    digest: [u8; 32],
) -> Result<DefaultSighashSignature, RuntimeError> {
    let signature = graph
        .preauthorization_for_sighash(edge.parent.node_id, edge.child.node_id, role, digest)
        .ok_or(RuntimeError::MissingPreauthorization { role })?;
    verify_signature(graph, role, digest, signature)?;
    Ok(signature)
}

fn verify_signature(
    graph: &dyn ChainBackend,
    role: Role,
    digest: [u8; 32],
    signature: DefaultSighashSignature,
) -> Result<(), RuntimeError> {
    let secp = Secp256k1::verification_only();
    Ok(verify_sighash_default(
        &secp,
        graph.identity_key(role),
        digest,
        signature,
    )?)
}

fn unique_reveal_pattern(
    graph: &dyn ChainBackend,
    node_id: NodeId,
) -> Result<RevealPattern, RuntimeError> {
    let node = graph
        .node(node_id)
        .ok_or(RuntimeError::NodeNotFound { node_id })?;
    let mut pattern = None;
    for child in &node.child_node_ids {
        let edge = graph
            .edge(node_id, *child)
            .ok_or(RuntimeError::MissingListedEdge {
                parent_node_id: node_id,
                child_node_id: *child,
            })?;
        let candidate = match edge.kind {
            EdgeKind::HoleCardReveal {
                revealer: Role::Bob,
            } => Some(RevealPattern::DealAlice),
            EdgeKind::HoleCardReveal {
                revealer: Role::Alice,
            } => Some(RevealPattern::DealBob),
            EdgeKind::CommunityReveal {
                street: Street::Flop,
                revealer,
            } => Some(RevealPattern::Flop(revealer)),
            EdgeKind::CommunityReveal {
                street: Street::Turn,
                revealer,
            } => Some(RevealPattern::Turn(revealer)),
            EdgeKind::CommunityReveal {
                street: Street::River,
                revealer,
            } => Some(RevealPattern::River(revealer)),
            _ => None,
        };
        if let Some(candidate) = candidate {
            if pattern.replace(candidate).is_some() {
                return Err(RuntimeError::InconsistentGraph {
                    reason: "reveal node has multiple normal reveal edges",
                });
            }
        }
    }
    pattern.ok_or(RuntimeError::InconsistentGraph {
        reason: "node has no normal reveal edge",
    })
}

const fn reveal_edge_kind(pattern: RevealPattern) -> EdgeKind {
    match pattern {
        RevealPattern::DealAlice | RevealPattern::DealBob => EdgeKind::HoleCardReveal {
            revealer: pattern.revealer(),
        },
        RevealPattern::Flop(revealer) => EdgeKind::CommunityReveal {
            street: Street::Flop,
            revealer,
        },
        RevealPattern::Turn(revealer) => EdgeKind::CommunityReveal {
            street: Street::Turn,
            revealer,
        },
        RevealPattern::River(revealer) => EdgeKind::CommunityReveal {
            street: Street::River,
            revealer,
        },
    }
}

fn validate_reveal_node(kind: NodeKind, pattern: RevealPattern) -> Result<(), RuntimeError> {
    let valid = matches!(
        (kind, pattern),
        (
            NodeKind::Funded | NodeKind::DealAlice,
            RevealPattern::DealAlice
        ) | (NodeKind::DealBob, RevealPattern::DealBob)
            | (
                NodeKind::CommunityRevealFirst | NodeKind::CommunityRevealSecond,
                RevealPattern::Flop(_) | RevealPattern::Turn(_) | RevealPattern::River(_)
            )
    );
    if valid {
        Ok(())
    } else {
        Err(RuntimeError::InconsistentGraph {
            reason: "reveal pattern is incompatible with node kind",
        })
    }
}

fn showdown_hand(
    graph: &dyn ChainBackend,
    public: &PublicPreimageStore,
    secret: &dyn SecretPreimageSource,
    role: Role,
    subset_id: u8,
    score: u32,
) -> Result<ShowdownHandWitness, RuntimeError> {
    let slots = match role {
        Role::Alice => bp52_chain_bitcoin::ALICE_SEVEN_SLOTS,
        Role::Bob => bp52_chain_bitcoin::BOB_SEVEN_SLOTS,
    };
    let mut openings = Vec::with_capacity(7);
    for slot in slots {
        let (preimage_a, preimage_b) = match (role, slot) {
            (Role::Alice, 0 | 2) => (
                secret_value(secret, Role::Alice, slot)?,
                public_value(public, Role::Bob, slot)?,
            ),
            (Role::Bob, 1 | 3) => (
                public_value(public, Role::Alice, slot)?,
                secret_value(secret, Role::Bob, slot)?,
            ),
            (_, 4..=8) => (
                public_value(public, Role::Alice, slot)?,
                public_value(public, Role::Bob, slot)?,
            ),
            _ => {
                return Err(RuntimeError::InconsistentGraph {
                    reason: "invalid fixed showdown slot mapping",
                });
            }
        };
        openings.push(CardOpeningWitness::new(slot, preimage_a, preimage_b));
    }
    let openings: [CardOpeningWitness; 7] =
        openings
            .try_into()
            .map_err(|_| RuntimeError::InconsistentGraph {
                reason: "fixed showdown opening count changed",
            })?;
    let hand = ShowdownHandWitness::new(openings, subset_id, score);
    verify_showdown_hand(graph.accepted_deal(), role, &hand)?;
    Ok(hand)
}

fn public_value(
    public: &PublicPreimageStore,
    role: Role,
    slot: u8,
) -> Result<Vec<u8>, RuntimeError> {
    public
        .get(role, slot)
        .map(<[u8]>::to_vec)
        .ok_or(RuntimeError::MissingPreimage { role, slot })
}

fn secret_value(
    secret: &dyn SecretPreimageSource,
    role: Role,
    slot: u8,
) -> Result<Vec<u8>, RuntimeError> {
    secret
        .preimage(usize::from(slot))
        .map(<[u8]>::to_vec)
        .ok_or(RuntimeError::MissingPreimage { role, slot })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::{Amount, Network, OutPoint, ScriptBuf, TxOut, Txid};
    use bp52_chain_bitcoin::{
        ActionProgram, AliceScoreCertificate, AliceShowdownProgram, BobPayoutProgram,
        CardOpeningWitness, CompiledTapLeaf, CompiledTaprootState, DefaultSighashSignature,
        LeafProgram, RevealPattern, RevealProgram, ShareRevealPredicate, ShowdownHandWitness,
        TimeoutProgram, TransactionTemplate, sign_sighash_default, taproot_script_sighash_default,
    };
    use bp52_chain_types::{
        AcceptedDeal, Action, AuthorizationPolicy, EdgeKind, LogicalEdge, LogicalNodeRecord,
        NodeId, NodeKind, Phase, Role, ShowdownOutcome, TimeoutKind, TimeoutSpec, root_node_id,
    };
    use bp52_lamport::{
        BobScoreCertificate, KeyContext, LamportPublicKey, LamportPurpose, LamportSecretKey,
        Score24, generate_key, issue_alice_score_certificate,
    };
    use bp52_poker::evaluate_five_cards;
    use rand_core::OsRng;

    use super::{
        build_action_witness, build_advance_witness, build_alice_showdown_witness,
        build_bob_payout_witness, build_reveal_witness, build_selected_action_witness,
        build_timeout_witness, sign_selected_action,
    };
    use crate::{
        BitcoinSigner, ChainBackend, ChainMonitor, MonitorState, PublicPreimageStore, RuntimeError,
        SecretEraser, SecretPreimageSource, SignerError, Witness, attach_offchain_witness,
        attach_timeout_witness, attach_witness,
    };

    const GAME_ID: [u8; 32] = [9; 32];
    const PARENT_ID: NodeId = [1; 32];
    const ACTION_CHILD_ID: NodeId = [2; 32];
    const TIMEOUT_CHILD_ID: NodeId = [3; 32];

    #[derive(Clone, Copy)]
    enum TimeoutPreauthorization {
        Valid,
        Missing,
        Wrong,
    }

    struct TestGraph {
        network: Network,
        deal: AcceptedDeal,
        identity_keys: [[u8; 32]; 2],
        nodes: Vec<LogicalNodeRecord>,
        edges: Vec<LogicalEdge>,
        templates: Vec<(NodeId, TransactionTemplate)>,
        state: CompiledTaprootState,
        signatures: [DefaultSighashSignature; 2],
        timeout_signatures: [DefaultSighashSignature; 2],
        preauthorization_parent_id: NodeId,
        preauthorization_child_id: NodeId,
        alice_preauthorization_present: bool,
        wrong_opponent_signature: bool,
        timeout_preauthorization: TimeoutPreauthorization,
    }

    impl crate::backend::sealed::Sealed for TestGraph {}

    impl ChainBackend for TestGraph {
        fn network(&self) -> Network {
            self.network
        }

        fn network_id(&self) -> [u8; 32] {
            [0x11; 32]
        }

        fn chain_game_id(&self) -> [u8; 32] {
            GAME_ID
        }

        fn graph_root(&self) -> [u8; 32] {
            [0xa5; 32]
        }

        fn accepted_deal(&self) -> &AcceptedDeal {
            &self.deal
        }

        fn identity_key(&self, role: Role) -> [u8; 32] {
            self.identity_keys[usize::from(role.code())]
        }

        fn node(&self, node_id: NodeId) -> Option<&LogicalNodeRecord> {
            self.nodes.iter().find(|node| node.node_id == node_id)
        }

        fn edge(&self, parent_node_id: NodeId, child_node_id: NodeId) -> Option<&LogicalEdge> {
            self.edges.iter().find(|edge| {
                edge.parent_node_id == parent_node_id && edge.child_node_id == child_node_id
            })
        }

        fn transaction_template(&self, child_node_id: NodeId) -> Option<&TransactionTemplate> {
            self.templates
                .iter()
                .find_map(|(node_id, template)| (*node_id == child_node_id).then_some(template))
        }

        fn tap_leaf(
            &self,
            _parent_node_id: NodeId,
            child_node_id: NodeId,
        ) -> Option<&CompiledTapLeaf> {
            let predicate_id = self.node(child_node_id)?.required_predicate_id;
            self.state.leaf(predicate_id)
        }

        fn lamport_public_key(
            &self,
            _node_id: NodeId,
            _purpose: LamportPurpose,
        ) -> Option<&LamportPublicKey> {
            None
        }

        fn preauthorization(
            &self,
            parent_node_id: NodeId,
            child_node_id: NodeId,
            role: Role,
        ) -> Option<DefaultSighashSignature> {
            if parent_node_id != self.preauthorization_parent_id {
                return None;
            }
            if child_node_id == TIMEOUT_CHILD_ID {
                let beneficiary = self.node(parent_node_id)?.timeout?.beneficiary;
                if role != beneficiary.other() {
                    return None;
                }
                return match self.timeout_preauthorization {
                    TimeoutPreauthorization::Valid => {
                        Some(self.timeout_signatures[usize::from(role.code())])
                    }
                    TimeoutPreauthorization::Missing => None,
                    TimeoutPreauthorization::Wrong => {
                        Some(self.timeout_signatures[usize::from(beneficiary.code())])
                    }
                };
            }
            if child_node_id == self.preauthorization_child_id {
                if role == Role::Alice && !self.alice_preauthorization_present {
                    return None;
                }
                return Some(if self.wrong_opponent_signature && role == Role::Bob {
                    self.signatures[0]
                } else {
                    self.signatures[usize::from(role.code())]
                });
            }
            None
        }
    }

    const ALICE_SHOWDOWN_ID: NodeId = [30; 32];
    const BOB_TERMINAL_ID: NodeId = [31; 32];
    const PAYOUT_CHILD_ID: NodeId = [32; 32];
    const PAYOUT_PREDICATE_ID: [u8; 32] = [33; 32];
    const PAYOUT_DIGEST: [u8; 32] = [34; 32];

    struct SemanticShowdownGraph {
        deal: AcceptedDeal,
        identity_keys: [[u8; 32]; 2],
        nodes: Vec<LogicalNodeRecord>,
        edge: LogicalEdge,
        template: TransactionTemplate,
        alice_score_key: LamportPublicKey,
        bob_score_key: LamportPublicKey,
        alice_signature: DefaultSighashSignature,
    }

    impl crate::backend::sealed::Sealed for SemanticShowdownGraph {}

    impl ChainBackend for SemanticShowdownGraph {
        fn network(&self) -> Network {
            Network::Regtest
        }

        fn network_id(&self) -> [u8; 32] {
            [0x11; 32]
        }

        fn chain_game_id(&self) -> [u8; 32] {
            GAME_ID
        }

        fn graph_root(&self) -> [u8; 32] {
            [0xa5; 32]
        }

        fn accepted_deal(&self) -> &AcceptedDeal {
            &self.deal
        }

        fn identity_key(&self, role: Role) -> [u8; 32] {
            self.identity_keys[usize::from(role.code())]
        }

        fn node(&self, node_id: NodeId) -> Option<&LogicalNodeRecord> {
            self.nodes.iter().find(|node| node.node_id == node_id)
        }

        fn edge(&self, parent_node_id: NodeId, child_node_id: NodeId) -> Option<&LogicalEdge> {
            (self.edge.parent_node_id == parent_node_id && self.edge.child_node_id == child_node_id)
                .then_some(&self.edge)
        }

        fn transaction_template(&self, child_node_id: NodeId) -> Option<&TransactionTemplate> {
            (child_node_id == PAYOUT_CHILD_ID).then_some(&self.template)
        }

        fn tap_leaf(
            &self,
            _parent_node_id: NodeId,
            _child_node_id: NodeId,
        ) -> Option<&CompiledTapLeaf> {
            None
        }

        fn predicate_id(&self, parent_node_id: NodeId, child_node_id: NodeId) -> Option<[u8; 32]> {
            (parent_node_id == BOB_TERMINAL_ID && child_node_id == PAYOUT_CHILD_ID)
                .then_some(PAYOUT_PREDICATE_ID)
        }

        fn signature_digest(
            &self,
            parent_node_id: NodeId,
            child_node_id: NodeId,
        ) -> Result<[u8; 32], RuntimeError> {
            if parent_node_id == BOB_TERMINAL_ID && child_node_id == PAYOUT_CHILD_ID {
                Ok(PAYOUT_DIGEST)
            } else {
                Err(RuntimeError::InconsistentGraph {
                    reason: "test semantic edge not found",
                })
            }
        }

        fn lamport_public_key(
            &self,
            node_id: NodeId,
            purpose: LamportPurpose,
        ) -> Option<&LamportPublicKey> {
            match (node_id, purpose) {
                (ALICE_SHOWDOWN_ID, LamportPurpose::AliceScore24Bit) => Some(&self.alice_score_key),
                (BOB_TERMINAL_ID, LamportPurpose::BobScore24Bit) => Some(&self.bob_score_key),
                _ => None,
            }
        }

        fn preauthorization(
            &self,
            parent_node_id: NodeId,
            child_node_id: NodeId,
            role: Role,
        ) -> Option<DefaultSighashSignature> {
            (parent_node_id == BOB_TERMINAL_ID
                && child_node_id == PAYOUT_CHILD_ID
                && role == Role::Alice)
                .then_some(self.alice_signature)
        }

        fn assemble_witness(
            &self,
            parent_node_id: NodeId,
            child_node_id: NodeId,
            elements: &[Vec<u8>],
        ) -> Result<bitcoin::Witness, RuntimeError> {
            if parent_node_id != BOB_TERMINAL_ID || child_node_id != PAYOUT_CHILD_ID {
                return Err(RuntimeError::InconsistentGraph {
                    reason: "test semantic edge not found",
                });
            }
            Ok(bitcoin::Witness::from_slice(elements))
        }
    }

    struct PeerShowdownGraph {
        deal: AcceptedDeal,
        identity_keys: [[u8; 32]; 2],
        nodes: Vec<LogicalNodeRecord>,
        edges: Vec<LogicalEdge>,
        templates: Vec<(NodeId, TransactionTemplate)>,
        states: Vec<(NodeId, CompiledTaprootState)>,
        alice_score_key: LamportPublicKey,
        bob_score_key: LamportPublicKey,
        preauthorizations: Vec<(NodeId, NodeId, Role, DefaultSighashSignature)>,
    }

    impl crate::backend::sealed::Sealed for PeerShowdownGraph {}

    impl ChainBackend for PeerShowdownGraph {
        fn network(&self) -> Network {
            Network::Regtest
        }

        fn network_id(&self) -> [u8; 32] {
            [0x11; 32]
        }

        fn chain_game_id(&self) -> [u8; 32] {
            GAME_ID
        }

        fn graph_root(&self) -> [u8; 32] {
            [0xb5; 32]
        }

        fn accepted_deal(&self) -> &AcceptedDeal {
            &self.deal
        }

        fn identity_key(&self, role: Role) -> [u8; 32] {
            self.identity_keys[usize::from(role.code())]
        }

        fn node(&self, node_id: NodeId) -> Option<&LogicalNodeRecord> {
            self.nodes.iter().find(|node| node.node_id == node_id)
        }

        fn edge(&self, parent_node_id: NodeId, child_node_id: NodeId) -> Option<&LogicalEdge> {
            self.edges.iter().find(|edge| {
                edge.parent_node_id == parent_node_id && edge.child_node_id == child_node_id
            })
        }

        fn transaction_template(&self, child_node_id: NodeId) -> Option<&TransactionTemplate> {
            self.templates
                .iter()
                .find_map(|(node_id, template)| (*node_id == child_node_id).then_some(template))
        }

        fn tap_leaf(
            &self,
            parent_node_id: NodeId,
            child_node_id: NodeId,
        ) -> Option<&CompiledTapLeaf> {
            let predicate_id = self.node(child_node_id)?.required_predicate_id;
            self.states
                .iter()
                .find_map(|(node_id, state)| (*node_id == parent_node_id).then_some(state))?
                .leaf(predicate_id)
        }

        fn lamport_public_key(
            &self,
            node_id: NodeId,
            purpose: LamportPurpose,
        ) -> Option<&LamportPublicKey> {
            match (node_id, purpose) {
                (ALICE_SHOWDOWN_ID, LamportPurpose::AliceScore24Bit) => Some(&self.alice_score_key),
                (BOB_TERMINAL_ID, LamportPurpose::BobScore24Bit) => Some(&self.bob_score_key),
                _ => None,
            }
        }

        fn preauthorization(
            &self,
            parent_node_id: NodeId,
            child_node_id: NodeId,
            role: Role,
        ) -> Option<DefaultSighashSignature> {
            self.preauthorizations.iter().find_map(
                |(candidate_parent, candidate_child, candidate_role, signature)| {
                    (*candidate_parent == parent_node_id
                        && *candidate_child == child_node_id
                        && *candidate_role == role)
                        .then_some(*signature)
                },
            )
        }
    }

    struct VecSecretSource {
        values: [Vec<u8>; 9],
    }

    impl SecretPreimageSource for VecSecretSource {
        fn preimage(&self, slot: usize) -> Option<&[u8]> {
            self.values.get(slot).map(Vec::as_slice)
        }
    }

    struct TestSigner {
        role: Role,
        keypair: Keypair,
        calls: Cell<usize>,
    }

    #[derive(Default)]
    struct CountingEraser {
        calls: usize,
    }

    impl SecretEraser for CountingEraser {
        fn erase_node_secrets(
            &mut self,
            _chain_game_id: [u8; 32],
            _node_id: NodeId,
        ) -> Result<(), RuntimeError> {
            self.calls += 1;
            Ok(())
        }
    }

    struct PanickingEraser;

    impl SecretEraser for PanickingEraser {
        #[allow(clippy::panic)]
        fn erase_node_secrets(
            &mut self,
            _chain_game_id: [u8; 32],
            _node_id: NodeId,
        ) -> Result<(), RuntimeError> {
            panic!("injected durable erasure panic")
        }
    }

    impl BitcoinSigner for TestSigner {
        fn sign_sighash_default(
            &self,
            role: Role,
            _node_id: NodeId,
            _child_node_id: NodeId,
            digest: [u8; 32],
        ) -> Result<DefaultSighashSignature, SignerError> {
            if role != self.role {
                return Err(SignerError::new(
                    "test signer does not control requested role",
                ));
            }
            self.calls.set(self.calls.get() + 1);
            Ok(sign_sighash_default(
                &Secp256k1::new(),
                &self.keypair,
                digest,
            ))
        }
    }

    fn test_signer(role: Role) -> Result<TestSigner, bitcoin::secp256k1::Error> {
        let secret = match role {
            Role::Alice => [11; 32],
            Role::Bob => [12; 32],
        };
        Ok(TestSigner {
            role,
            keypair: Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&secret)?),
            calls: Cell::new(0),
        })
    }

    fn output(value: u64, script_pubkey: ScriptBuf) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        }
    }

    fn accepted_deal() -> AcceptedDeal {
        AcceptedDeal {
            protocol_version: 1,
            game_id: [4; 32],
            attempt: 0,
            hashes_a: [[5; 32]; 9],
            hashes_b: [[6; 32]; 9],
            verification_transcript_root: [7; 32],
            signature_a: [8; 64],
            signature_b: [9; 64],
        }
    }

    fn fixture() -> Result<(TestGraph, Keypair, Keypair), Box<dyn std::error::Error>> {
        fixture_with_timeout_beneficiary(Role::Bob)
    }

    #[allow(clippy::too_many_lines)]
    fn fixture_with_timeout_beneficiary(
        beneficiary: Role,
    ) -> Result<(TestGraph, Keypair, Keypair), Box<dyn std::error::Error>> {
        let secp = Secp256k1::new();
        let alice_secret = SecretKey::from_slice(&[11; 32])?;
        let bob_secret = SecretKey::from_slice(&[12; 32])?;
        let alice_keypair = Keypair::from_secret_key(&secp, &alice_secret);
        let bob_keypair = Keypair::from_secret_key(&secp, &bob_secret);
        let (alice_xonly, _) = alice_keypair.x_only_public_key();
        let (bob_xonly, _) = bob_keypair.x_only_public_key();
        let identity_keys = [alice_xonly.serialize(), bob_xonly.serialize()];
        let timeout = TimeoutSpec::new(TimeoutKind::Action, 5, beneficiary.other(), beneficiary)?;
        let action_program = LeafProgram::Action(ActionProgram::new(
            GAME_ID,
            PARENT_ID,
            Action::Raise,
            identity_keys,
        )?);
        let timeout_program =
            LeafProgram::Timeout(TimeoutProgram::new(GAME_ID, PARENT_ID, 5, identity_keys)?);
        let action_predicate = action_program.predicate_id();
        let timeout_predicate = timeout_program.predicate_id();
        let state =
            CompiledTaprootState::compile(&secp, [15; 32], &[action_program, timeout_program])?;

        let prior_output = output(1_100, ScriptBuf::from_bytes(vec![0x51]));
        let parent_output = output(1_000, state.script_pubkey());
        let parent_creation = TransactionTemplate::normal(
            Network::Regtest,
            OutPoint::new(Txid::from_byte_array([13; 32]), 0),
            prior_output,
            vec![parent_output.clone()],
            100,
        )?;
        let parent_outpoint = OutPoint::new(Txid::from_byte_array(parent_creation.txid()), 0);
        let terminal_output = output(900, ScriptBuf::from_bytes(vec![0x51]));
        let action_template = TransactionTemplate::normal(
            Network::Regtest,
            parent_outpoint,
            parent_output.clone(),
            vec![terminal_output.clone()],
            100,
        )?;
        let timeout_template = TransactionTemplate::timeout(
            Network::Regtest,
            parent_outpoint,
            parent_output,
            vec![terminal_output],
            100,
            5,
        )?;
        let action_leaf = state.leaf(action_predicate).ok_or("missing action leaf")?;
        let digest = taproot_script_sighash_default(
            action_template.transaction(),
            0,
            std::slice::from_ref(action_template.parent_output()),
            action_leaf.script(),
        )?;
        let signatures = [
            sign_sighash_default(&secp, &alice_keypair, digest),
            sign_sighash_default(&secp, &bob_keypair, digest),
        ];
        let timeout_leaf = state
            .leaf(timeout_predicate)
            .ok_or("missing timeout leaf")?;
        let timeout_digest = taproot_script_sighash_default(
            timeout_template.transaction(),
            0,
            std::slice::from_ref(timeout_template.parent_output()),
            timeout_leaf.script(),
        )?;
        let timeout_signatures = [
            sign_sighash_default(&secp, &alice_keypair, timeout_digest),
            sign_sighash_default(&secp, &bob_keypair, timeout_digest),
        ];
        let action_logical = action_template.to_logical_transaction();
        let timeout_logical = timeout_template.to_logical_transaction();
        let nodes = vec![
            LogicalNodeRecord {
                node_id: PARENT_ID,
                parent_node_id: Some([14; 32]),
                node_kind: NodeKind::Betting,
                logical_state_digest: [15; 32],
                transaction: Some(parent_creation.to_logical_transaction()),
                required_predicate_id: [16; 32],
                timeout: Some(timeout),
                child_node_ids: vec![ACTION_CHILD_ID, TIMEOUT_CHILD_ID],
            },
            LogicalNodeRecord {
                node_id: ACTION_CHILD_ID,
                parent_node_id: Some(PARENT_ID),
                node_kind: NodeKind::Terminal,
                logical_state_digest: [17; 32],
                transaction: Some(action_logical.clone()),
                required_predicate_id: action_predicate,
                timeout: None,
                child_node_ids: Vec::new(),
            },
            LogicalNodeRecord {
                node_id: TIMEOUT_CHILD_ID,
                parent_node_id: Some(PARENT_ID),
                node_kind: NodeKind::Terminal,
                logical_state_digest: [18; 32],
                transaction: Some(timeout_logical.clone()),
                required_predicate_id: timeout_predicate,
                timeout: None,
                child_node_ids: Vec::new(),
            },
        ];
        let edges = vec![
            LogicalEdge {
                parent_node_id: PARENT_ID,
                child_node_id: ACTION_CHILD_ID,
                kind: EdgeKind::Action(Action::Raise),
                transaction: action_logical,
                authorization: AuthorizationPolicy::BettingAction { actor: Role::Alice },
                timeout: None,
            },
            LogicalEdge {
                parent_node_id: PARENT_ID,
                child_node_id: TIMEOUT_CHILD_ID,
                kind: EdgeKind::Timeout(TimeoutKind::Action),
                transaction: timeout_logical,
                authorization: AuthorizationPolicy::Timeout { beneficiary },
                timeout: Some(timeout),
            },
        ];
        let graph = TestGraph {
            network: Network::Regtest,
            deal: accepted_deal(),
            identity_keys,
            nodes,
            edges,
            templates: vec![
                (ACTION_CHILD_ID, action_template),
                (TIMEOUT_CHILD_ID, timeout_template),
            ],
            state,
            signatures,
            timeout_signatures,
            preauthorization_parent_id: PARENT_ID,
            preauthorization_child_id: ACTION_CHILD_ID,
            alice_preauthorization_present: false,
            wrong_opponent_signature: false,
            timeout_preauthorization: TimeoutPreauthorization::Valid,
        };
        Ok((graph, alice_keypair, bob_keypair))
    }

    type RootRevealFixture = (TestGraph, Vec<Vec<u8>>);

    fn root_reveal_fixture() -> Result<RootRevealFixture, Box<dyn std::error::Error>> {
        let preimages = vec![vec![0x31; 16], vec![0x32; 17]];
        let mut deal = accepted_deal();
        deal.hashes_b[0] = bitcoin::hashes::sha256::Hash::hash(&preimages[0]).to_byte_array();
        deal.hashes_b[2] = bitcoin::hashes::sha256::Hash::hash(&preimages[1]).to_byte_array();

        let secp = Secp256k1::new();
        let alice_keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[11; 32])?);
        let bob_keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[12; 32])?);
        let identity_keys = [
            alice_keypair.x_only_public_key().0.serialize(),
            bob_keypair.x_only_public_key().0.serialize(),
        ];
        let reveal_program = LeafProgram::Reveal(RevealProgram::new(
            GAME_ID,
            PARENT_ID,
            ShareRevealPredicate::new(&deal, RevealPattern::DealAlice),
            identity_keys,
        )?);
        let reveal_predicate = reveal_program.predicate_id();
        let state = CompiledTaprootState::compile(&secp, [0x42; 32], &[reveal_program])?;
        let root_output = output(1_000, state.script_pubkey());
        let child_template = TransactionTemplate::normal(
            Network::Regtest,
            OutPoint::new(Txid::from_byte_array([0x41; 32]), 0),
            root_output,
            vec![output(900, ScriptBuf::from_bytes(vec![0x51]))],
            100,
        )?;
        let reveal_leaf = state.leaf(reveal_predicate).ok_or("missing reveal leaf")?;
        let digest = taproot_script_sighash_default(
            child_template.transaction(),
            0,
            std::slice::from_ref(child_template.parent_output()),
            reveal_leaf.script(),
        )?;
        let signatures = [
            sign_sighash_default(&secp, &alice_keypair, digest),
            sign_sighash_default(&secp, &bob_keypair, digest),
        ];
        let logical = child_template.to_logical_transaction();
        let nodes = vec![
            LogicalNodeRecord {
                node_id: PARENT_ID,
                parent_node_id: None,
                node_kind: NodeKind::Funded,
                logical_state_digest: [0x42; 32],
                transaction: None,
                required_predicate_id: [0x43; 32],
                timeout: None,
                child_node_ids: vec![ACTION_CHILD_ID],
            },
            LogicalNodeRecord {
                node_id: ACTION_CHILD_ID,
                parent_node_id: Some(PARENT_ID),
                node_kind: NodeKind::Terminal,
                logical_state_digest: [0x44; 32],
                transaction: Some(logical.clone()),
                required_predicate_id: reveal_predicate,
                timeout: None,
                child_node_ids: Vec::new(),
            },
        ];
        let edges = vec![LogicalEdge {
            parent_node_id: PARENT_ID,
            child_node_id: ACTION_CHILD_ID,
            kind: EdgeKind::HoleCardReveal {
                revealer: Role::Bob,
            },
            transaction: logical,
            authorization: AuthorizationPolicy::RevealPreimages {
                revealer: Role::Bob,
            },
            timeout: None,
        }];
        Ok((
            TestGraph {
                network: Network::Regtest,
                deal,
                identity_keys,
                nodes,
                edges,
                templates: vec![(ACTION_CHILD_ID, child_template)],
                state,
                signatures,
                timeout_signatures: signatures,
                preauthorization_parent_id: PARENT_ID,
                preauthorization_child_id: ACTION_CHILD_ID,
                alice_preauthorization_present: true,
                wrong_opponent_signature: false,
                timeout_preauthorization: TimeoutPreauthorization::Missing,
            },
            preimages,
        ))
    }

    type ShowdownFixture = (
        SemanticShowdownGraph,
        PublicPreimageStore,
        VecSecretSource,
        AliceScoreCertificate,
        u32,
        LamportSecretKey,
        Keypair,
    );

    #[allow(clippy::too_many_lines)]
    fn showdown_fixture(
        edge_outcome: ShowdownOutcome,
    ) -> Result<ShowdownFixture, Box<dyn std::error::Error>> {
        let preimages_a: [Vec<u8>; 9] =
            core::array::from_fn(|slot| vec![0x40 + u8::try_from(slot).unwrap_or_default(); 16]);
        let preimages_b: [Vec<u8>; 9] = core::array::from_fn(|slot| {
            vec![0x80 + u8::try_from(slot).unwrap_or_default(); 16 + slot]
        });
        let deal = AcceptedDeal {
            protocol_version: 1,
            game_id: [40; 32],
            attempt: 1,
            hashes_a: core::array::from_fn(|slot| {
                bitcoin::hashes::sha256::Hash::hash(&preimages_a[slot]).to_byte_array()
            }),
            hashes_b: core::array::from_fn(|slot| {
                bitcoin::hashes::sha256::Hash::hash(&preimages_b[slot]).to_byte_array()
            }),
            verification_transcript_root: [41; 32],
            signature_a: [42; 64],
            signature_b: [43; 64],
        };
        let mut public = PublicPreimageStore::new(GAME_ID, deal);
        for slot in [1_u8, 3] {
            public.insert(Role::Alice, slot, preimages_a[usize::from(slot)].clone())?;
        }
        for slot in 4_u8..=8 {
            public.insert(Role::Alice, slot, preimages_a[usize::from(slot)].clone())?;
            public.insert(Role::Bob, slot, preimages_b[usize::from(slot)].clone())?;
        }

        let alice_score = evaluate_five_cards([0, 4, 8, 12, 20])?;
        let bob_score = evaluate_five_cards([4, 12, 16, 20, 24])?;
        assert!(bob_score > alice_score);
        let (mut score_secret, score_key) = generate_key(
            &mut OsRng,
            KeyContext::new(
                GAME_ID,
                root_node_id(&GAME_ID),
                LamportPurpose::AliceScore24Bit,
            ),
        )?;
        let certificate =
            issue_alice_score_certificate(&mut score_secret, Score24::new(alice_score)?)?;
        let (bob_score_secret, bob_score_key) = generate_key(
            &mut OsRng,
            KeyContext::new(
                GAME_ID,
                root_node_id(&GAME_ID),
                LamportPurpose::BobScore24Bit,
            ),
        )?;

        let secp = Secp256k1::new();
        let alice_keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[21; 32])?);
        let bob_keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[22; 32])?);
        let identity_keys = [
            alice_keypair.x_only_public_key().0.serialize(),
            bob_keypair.x_only_public_key().0.serialize(),
        ];
        let alice_signature = sign_sighash_default(&secp, &alice_keypair, PAYOUT_DIGEST);

        let prior_output = output(1_100, ScriptBuf::from_bytes(vec![0x51]));
        let parent_output = output(1_000, ScriptBuf::from_bytes(vec![0x51]));
        let parent_creation = TransactionTemplate::normal(
            Network::Regtest,
            OutPoint::new(Txid::from_byte_array([44; 32]), 0),
            prior_output,
            vec![parent_output.clone()],
            100,
        )?;
        let payout_template = TransactionTemplate::normal(
            Network::Regtest,
            OutPoint::new(Txid::from_byte_array(parent_creation.txid()), 0),
            parent_output,
            vec![output(900, ScriptBuf::from_bytes(vec![0x51]))],
            100,
        )?;
        let payout_logical = payout_template.to_logical_transaction();
        let parent_logical = parent_creation.to_logical_transaction();
        let nodes = vec![
            LogicalNodeRecord {
                node_id: ALICE_SHOWDOWN_ID,
                parent_node_id: Some([45; 32]),
                node_kind: NodeKind::AliceShowdown,
                logical_state_digest: [46; 32],
                transaction: Some(parent_logical.clone()),
                required_predicate_id: [47; 32],
                timeout: None,
                child_node_ids: vec![BOB_TERMINAL_ID],
            },
            LogicalNodeRecord {
                node_id: BOB_TERMINAL_ID,
                parent_node_id: Some(ALICE_SHOWDOWN_ID),
                node_kind: NodeKind::BobTerminal,
                logical_state_digest: [48; 32],
                transaction: Some(parent_logical),
                required_predicate_id: [49; 32],
                timeout: None,
                child_node_ids: vec![PAYOUT_CHILD_ID],
            },
            LogicalNodeRecord {
                node_id: PAYOUT_CHILD_ID,
                parent_node_id: Some(BOB_TERMINAL_ID),
                node_kind: NodeKind::Terminal,
                logical_state_digest: [50; 32],
                transaction: Some(payout_logical.clone()),
                required_predicate_id: PAYOUT_PREDICATE_ID,
                timeout: None,
                child_node_ids: Vec::new(),
            },
        ];
        let edge = LogicalEdge {
            parent_node_id: BOB_TERMINAL_ID,
            child_node_id: PAYOUT_CHILD_ID,
            kind: EdgeKind::BobPayout(edge_outcome),
            transaction: payout_logical,
            authorization: AuthorizationPolicy::BobLivePayout,
            timeout: None,
        };
        let graph = SemanticShowdownGraph {
            deal,
            identity_keys,
            nodes,
            edge,
            template: payout_template,
            alice_score_key: score_key,
            bob_score_key,
            alice_signature,
        };
        Ok((
            graph,
            public,
            VecSecretSource {
                values: preimages_b,
            },
            certificate,
            bob_score,
            bob_score_secret,
            bob_keypair,
        ))
    }

    struct PeerShowdownFixture {
        graph: PeerShowdownGraph,
        public: PublicPreimageStore,
        alice_source: VecSecretSource,
        bob_source: VecSecretSource,
        score_secret: LamportSecretKey,
        bob_score_secret: LamportSecretKey,
        alice_score: u32,
        bob_score: u32,
        outcome: ShowdownOutcome,
        alice_keypair: Keypair,
        bob_keypair: Keypair,
    }

    #[allow(clippy::too_many_lines)]
    fn peer_showdown_fixture() -> Result<PeerShowdownFixture, Box<dyn std::error::Error>> {
        let preimages_a: [Vec<u8>; 9] =
            core::array::from_fn(|slot| vec![0x40 + u8::try_from(slot).unwrap_or_default(); 16]);
        let preimages_b: [Vec<u8>; 9] = core::array::from_fn(|slot| {
            vec![0x80 + u8::try_from(slot).unwrap_or_default(); 16 + slot]
        });
        let deal = AcceptedDeal {
            protocol_version: 1,
            game_id: [40; 32],
            attempt: 1,
            hashes_a: core::array::from_fn(|slot| {
                bitcoin::hashes::sha256::Hash::hash(&preimages_a[slot]).to_byte_array()
            }),
            hashes_b: core::array::from_fn(|slot| {
                bitcoin::hashes::sha256::Hash::hash(&preimages_b[slot]).to_byte_array()
            }),
            verification_transcript_root: [41; 32],
            signature_a: [42; 64],
            signature_b: [43; 64],
        };
        let mut public = PublicPreimageStore::new(GAME_ID, deal);
        for slot in [0_u8, 2] {
            public.insert(Role::Bob, slot, preimages_b[usize::from(slot)].clone())?;
        }
        for slot in [1_u8, 3] {
            public.insert(Role::Alice, slot, preimages_a[usize::from(slot)].clone())?;
        }
        for slot in 4_u8..=8 {
            public.insert(Role::Alice, slot, preimages_a[usize::from(slot)].clone())?;
            public.insert(Role::Bob, slot, preimages_b[usize::from(slot)].clone())?;
        }

        let alice_cards = bp52_chain_bitcoin::ALICE_SEVEN_SLOTS.map(|slot| {
            bp52_chain_bitcoin::verify_card_witness(
                &deal,
                &CardOpeningWitness::new(
                    slot,
                    preimages_a[usize::from(slot)].clone(),
                    preimages_b[usize::from(slot)].clone(),
                ),
            )
        });
        let alice_cards: Result<Vec<_>, _> = alice_cards.into_iter().collect();
        let alice_cards = alice_cards?;
        let alice_score = evaluate_five_cards([
            alice_cards[0],
            alice_cards[1],
            alice_cards[2],
            alice_cards[3],
            alice_cards[4],
        ])?;
        let bob_cards = bp52_chain_bitcoin::BOB_SEVEN_SLOTS.map(|slot| {
            bp52_chain_bitcoin::verify_card_witness(
                &deal,
                &CardOpeningWitness::new(
                    slot,
                    preimages_a[usize::from(slot)].clone(),
                    preimages_b[usize::from(slot)].clone(),
                ),
            )
        });
        let bob_cards: Result<Vec<_>, _> = bob_cards.into_iter().collect();
        let bob_cards = bob_cards?;
        let bob_score = evaluate_five_cards([
            bob_cards[0],
            bob_cards[1],
            bob_cards[2],
            bob_cards[3],
            bob_cards[4],
        ])?;
        let outcome = match alice_score.cmp(&bob_score) {
            std::cmp::Ordering::Greater => ShowdownOutcome::AliceWin,
            std::cmp::Ordering::Less => ShowdownOutcome::BobWin,
            std::cmp::Ordering::Equal => ShowdownOutcome::Split,
        };
        let (score_secret, score_key) = generate_key(
            &mut OsRng,
            KeyContext::new(
                GAME_ID,
                root_node_id(&GAME_ID),
                LamportPurpose::AliceScore24Bit,
            ),
        )?;
        let (bob_score_secret, bob_score_key) = generate_key(
            &mut OsRng,
            KeyContext::new(
                GAME_ID,
                root_node_id(&GAME_ID),
                LamportPurpose::BobScore24Bit,
            ),
        )?;

        let secp = Secp256k1::new();
        let alice_keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[21; 32])?);
        let bob_keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[22; 32])?);
        let identity_keys = [
            alice_keypair.x_only_public_key().0.serialize(),
            bob_keypair.x_only_public_key().0.serialize(),
        ];
        let alice_program = LeafProgram::AliceShowdown(AliceShowdownProgram::new(
            &deal,
            GAME_ID,
            ALICE_SHOWDOWN_ID,
            score_key.clone(),
            identity_keys,
        )?);
        let alice_predicate = alice_program.predicate_id();
        let alice_state = CompiledTaprootState::compile(&secp, [46; 32], &[alice_program])?;
        let bob_program = LeafProgram::BobPayout(BobPayoutProgram::new(
            &deal,
            GAME_ID,
            BOB_TERMINAL_ID,
            ALICE_SHOWDOWN_ID,
            outcome,
            score_key.clone(),
            bob_score_key.clone(),
            identity_keys,
        )?);
        let bob_predicate = bob_program.predicate_id();
        let bob_state = CompiledTaprootState::compile(&secp, [48; 32], &[bob_program])?;

        let prior_output = output(30_300, ScriptBuf::from_bytes(vec![0x51]));
        let alice_output = output(30_200, alice_state.script_pubkey());
        let parent_creation = TransactionTemplate::normal(
            Network::Regtest,
            OutPoint::new(Txid::from_byte_array([44; 32]), 0),
            prior_output,
            vec![alice_output.clone()],
            100,
        )?;
        let bob_output = output(30_100, bob_state.script_pubkey());
        let alice_template = TransactionTemplate::normal(
            Network::Regtest,
            OutPoint::new(Txid::from_byte_array(parent_creation.txid()), 0),
            alice_output,
            vec![bob_output.clone()],
            100,
        )?;
        let payout_template = TransactionTemplate::normal(
            Network::Regtest,
            OutPoint::new(Txid::from_byte_array(alice_template.txid()), 0),
            bob_output,
            vec![output(30_000, ScriptBuf::from_bytes(vec![0x51]))],
            100,
        )?;
        let alice_leaf = alice_state
            .leaf(alice_predicate)
            .ok_or("missing peer Alice showdown leaf")?;
        let alice_digest = taproot_script_sighash_default(
            alice_template.transaction(),
            0,
            std::slice::from_ref(alice_template.parent_output()),
            alice_leaf.script(),
        )?;
        let bob_leaf = bob_state
            .leaf(bob_predicate)
            .ok_or("missing peer Bob payout leaf")?;
        let bob_digest = taproot_script_sighash_default(
            payout_template.transaction(),
            0,
            std::slice::from_ref(payout_template.parent_output()),
            bob_leaf.script(),
        )?;
        let alice_logical = alice_template.to_logical_transaction();
        let payout_logical = payout_template.to_logical_transaction();
        let nodes = vec![
            LogicalNodeRecord {
                node_id: ALICE_SHOWDOWN_ID,
                parent_node_id: Some([45; 32]),
                node_kind: NodeKind::AliceShowdown,
                logical_state_digest: [46; 32],
                transaction: Some(parent_creation.to_logical_transaction()),
                required_predicate_id: [47; 32],
                timeout: None,
                child_node_ids: vec![BOB_TERMINAL_ID],
            },
            LogicalNodeRecord {
                node_id: BOB_TERMINAL_ID,
                parent_node_id: Some(ALICE_SHOWDOWN_ID),
                node_kind: NodeKind::BobTerminal,
                logical_state_digest: [48; 32],
                transaction: Some(alice_logical.clone()),
                required_predicate_id: alice_predicate,
                timeout: None,
                child_node_ids: vec![PAYOUT_CHILD_ID],
            },
            LogicalNodeRecord {
                node_id: PAYOUT_CHILD_ID,
                parent_node_id: Some(BOB_TERMINAL_ID),
                node_kind: NodeKind::Terminal,
                logical_state_digest: [50; 32],
                transaction: Some(payout_logical.clone()),
                required_predicate_id: bob_predicate,
                timeout: None,
                child_node_ids: Vec::new(),
            },
        ];
        let edges = vec![
            LogicalEdge {
                parent_node_id: ALICE_SHOWDOWN_ID,
                child_node_id: BOB_TERMINAL_ID,
                kind: EdgeKind::AliceShowdown,
                transaction: alice_logical,
                authorization: AuthorizationPolicy::AliceScore,
                timeout: None,
            },
            LogicalEdge {
                parent_node_id: BOB_TERMINAL_ID,
                child_node_id: PAYOUT_CHILD_ID,
                kind: EdgeKind::BobPayout(outcome),
                transaction: payout_logical,
                authorization: AuthorizationPolicy::BobLivePayout,
                timeout: None,
            },
        ];
        let preauthorizations = vec![
            (
                ALICE_SHOWDOWN_ID,
                BOB_TERMINAL_ID,
                Role::Alice,
                sign_sighash_default(&secp, &alice_keypair, alice_digest),
            ),
            (
                ALICE_SHOWDOWN_ID,
                BOB_TERMINAL_ID,
                Role::Bob,
                sign_sighash_default(&secp, &bob_keypair, alice_digest),
            ),
            (
                BOB_TERMINAL_ID,
                PAYOUT_CHILD_ID,
                Role::Alice,
                sign_sighash_default(&secp, &alice_keypair, bob_digest),
            ),
        ];
        let graph = PeerShowdownGraph {
            deal,
            identity_keys,
            nodes,
            edges,
            templates: vec![
                (BOB_TERMINAL_ID, alice_template),
                (PAYOUT_CHILD_ID, payout_template),
            ],
            states: vec![
                (ALICE_SHOWDOWN_ID, alice_state),
                (BOB_TERMINAL_ID, bob_state),
            ],
            alice_score_key: score_key,
            bob_score_key,
            preauthorizations,
        };
        Ok(PeerShowdownFixture {
            graph,
            public,
            alice_source: VecSecretSource {
                values: preimages_a,
            },
            bob_source: VecSecretSource {
                values: preimages_b,
            },
            score_secret,
            bob_score_secret,
            alice_score,
            bob_score,
            outcome,
            alice_keypair,
            bob_keypair,
        })
    }

    #[test]
    fn action_builder_validates_exact_edge_and_preserves_txid()
    -> Result<(), Box<dyn std::error::Error>> {
        let (graph, alice_keypair, _) = fixture()?;
        let signer = TestSigner {
            role: Role::Alice,
            keypair: alice_keypair,
            calls: Cell::new(0),
        };
        let mut monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), PARENT_ID, 100, 100);
        let witness = build_action_witness(&graph, &mut monitor, Action::Raise, &signer)?;
        assert!(matches!(witness, Witness::Action { .. }));
        assert_eq!(signer.calls.get(), 1);
        let prepared = {
            let active = monitor.confirmed_active_node(&graph)?;
            attach_witness(&graph, &active, &witness)?
        };
        assert_eq!(
            prepared.template_txid(),
            graph
                .transaction_template(ACTION_CHILD_ID)
                .ok_or("missing action template")?
                .txid()
        );
        assert_eq!(
            prepared.transaction().compute_txid().to_byte_array(),
            prepared.template_txid()
        );
        assert_eq!(prepared.network_id(), graph.network_id());
        assert!(!prepared.transaction().input[0].witness.is_empty());
        assert_eq!(
            build_action_witness(&graph, &mut monitor, Action::Raise, &signer)?,
            witness
        );
        assert_eq!(signer.calls.get(), 1);
        assert!(matches!(
            build_action_witness(&graph, &mut monitor, Action::Call, &signer),
            Err(RuntimeError::ConflictingActionAuthorization { node_id: PARENT_ID })
        ));
        assert_eq!(monitor.state(), MonitorState::Halted);
        Ok(())
    }

    #[test]
    fn selected_action_requires_both_exact_just_in_time_signatures()
    -> Result<(), Box<dyn std::error::Error>> {
        let (graph, _, _) = fixture()?;
        let witness = build_selected_action_witness(
            &graph,
            PARENT_ID,
            ACTION_CHILD_ID,
            Action::Raise,
            Role::Alice,
            graph.signatures[0],
            graph.signatures[1],
        )?;
        let prepared = attach_offchain_witness(&graph, PARENT_ID, &witness)?;
        assert_eq!(prepared.endpoints(), (PARENT_ID, ACTION_CHILD_ID));
        assert_eq!(prepared.template_txid(), graph.templates[0].1.txid());
        assert_eq!(
            prepared.transaction().compute_txid().to_byte_array(),
            graph.templates[0].1.txid()
        );
        assert!(matches!(
            build_selected_action_witness(
                &graph,
                PARENT_ID,
                ACTION_CHILD_ID,
                Action::Raise,
                Role::Bob,
                graph.signatures[0],
                graph.signatures[1],
            ),
            Err(RuntimeError::WrongAuthorization)
        ));
        assert!(matches!(
            build_selected_action_witness(
                &graph,
                PARENT_ID,
                ACTION_CHILD_ID,
                Action::Raise,
                Role::Alice,
                graph.signatures[1],
                graph.signatures[1],
            ),
            Err(RuntimeError::Bitcoin(_))
        ));
        assert!(matches!(
            attach_offchain_witness(&graph, TIMEOUT_CHILD_ID, &witness),
            Err(RuntimeError::WrongAuthorization)
        ));
        Ok(())
    }

    #[test]
    fn selected_action_signer_never_accepts_an_arbitrary_or_sibling_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        let (graph, alice_keypair, bob_keypair) = fixture()?;
        let alice = TestSigner {
            role: Role::Alice,
            keypair: alice_keypair,
            calls: Cell::new(0),
        };
        let bob = TestSigner {
            role: Role::Bob,
            keypair: bob_keypair,
            calls: Cell::new(0),
        };
        let alice_signature = sign_selected_action(
            &graph,
            PARENT_ID,
            ACTION_CHILD_ID,
            Action::Raise,
            Role::Alice,
            Role::Alice,
            &alice,
        )?;
        let bob_signature = sign_selected_action(
            &graph,
            PARENT_ID,
            ACTION_CHILD_ID,
            Action::Raise,
            Role::Alice,
            Role::Bob,
            &bob,
        )?;
        assert_eq!([alice.calls.get(), bob.calls.get()], [1, 1]);
        build_selected_action_witness(
            &graph,
            PARENT_ID,
            ACTION_CHILD_ID,
            Action::Raise,
            Role::Alice,
            alice_signature,
            bob_signature,
        )?;
        assert!(matches!(
            sign_selected_action(
                &graph,
                PARENT_ID,
                TIMEOUT_CHILD_ID,
                Action::Raise,
                Role::Alice,
                Role::Alice,
                &alice,
            ),
            Err(RuntimeError::WrongAuthorization)
                | Err(RuntimeError::MissingListedEdge { .. })
                | Err(RuntimeError::EdgeNotFound { .. })
        ));
        assert!(matches!(
            sign_selected_action(
                &graph,
                PARENT_ID,
                ACTION_CHILD_ID,
                Action::Raise,
                Role::Bob,
                Role::Alice,
                &alice,
            ),
            Err(RuntimeError::WrongAuthorization)
        ));
        assert_eq!(alice.calls.get(), 1);
        Ok(())
    }

    #[test]
    fn advance_builder_selects_an_exact_both_presigned_child()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut graph, _, _) = fixture()?;
        graph.edges[0].kind = EdgeKind::Advance {
            phase: Phase::FlopRevealFirst,
        };
        graph.edges[0].authorization = AuthorizationPolicy::BothPresigned;
        graph.alice_preauthorization_present = true;
        let monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), PARENT_ID, 100, 100);
        let active = monitor.confirmed_active_node(&graph)?;
        let witness = build_advance_witness(&graph, &active, ACTION_CHILD_ID)?;
        assert!(matches!(
            witness,
            Witness::Advance {
                phase: Phase::FlopRevealFirst,
                child_node_id: ACTION_CHILD_ID,
                ..
            }
        ));
        let prepared = attach_witness(&graph, &active, &witness)?;
        assert_eq!(prepared.template_txid(), graph.templates[0].1.txid());
        assert!(matches!(
            build_advance_witness(&graph, &active, TIMEOUT_CHILD_ID),
            Err(RuntimeError::WrongAuthorization)
        ));
        Ok(())
    }

    #[test]
    fn funded_root_executes_the_deal_alice_reveal_obligation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (graph, preimages) = root_reveal_fixture()?;
        let monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), PARENT_ID, 100, 100);
        let active = monitor.confirmed_active_node(&graph)?;
        let signer = test_signer(Role::Bob)?;
        let witness = build_reveal_witness(&graph, &active, &preimages, &signer)?;
        assert!(matches!(
            witness,
            Witness::Reveal {
                pattern: RevealPattern::DealAlice,
                ..
            }
        ));
        let prepared = attach_witness(&graph, &active, &witness)?;
        assert_eq!(prepared.template_txid(), graph.templates[0].1.txid());

        let mut changed_opening = witness;
        if let Witness::Reveal { preimages, .. } = &mut changed_opening {
            preimages[0][0] ^= 1;
        }
        assert!(matches!(
            attach_witness(&graph, &active, &changed_opening),
            Err(RuntimeError::Bitcoin(_))
        ));
        Ok(())
    }

    #[test]
    fn peer_broadcast_confirmation_recovers_reveal_and_timeout_witnesses()
    -> Result<(), Box<dyn std::error::Error>> {
        {
            let (graph, preimages) = root_reveal_fixture()?;
            let mut monitor =
                ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), PARENT_ID, 100, 101);
            let signer = test_signer(Role::Bob)?;
            let mut witness = {
                let active = monitor.confirmed_active_node(&graph)?;
                build_reveal_witness(&graph, &active, &preimages, &signer)?
            };
            let digest = graph.signature_digest(PARENT_ID, ACTION_CHILD_ID)?;
            let secp = Secp256k1::new();
            let alice_keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[11; 32])?);
            let alternate = secp.sign_schnorr_with_aux_rand(
                &Message::from_digest(digest),
                &alice_keypair,
                &[0x51; 32],
            );
            if let Witness::Reveal {
                alice_signature, ..
            } = &mut witness
            {
                *alice_signature = DefaultSighashSignature::from_bytes(alternate.serialize())?;
            }
            let confirmed = {
                let active = monitor.confirmed_active_node(&graph)?;
                attach_witness(&graph, &active, &witness)?
                    .transaction()
                    .clone()
            };
            let mut public = PublicPreimageStore::new(GAME_ID, graph.deal);
            let mut eraser = CountingEraser::default();
            monitor.confirm_child(
                &graph,
                ACTION_CHILD_ID,
                &confirmed,
                101,
                &mut public,
                &mut eraser,
            )?;
            assert_eq!(public.get(Role::Bob, 0), Some(preimages[0].as_slice()));
            assert_eq!(public.get(Role::Bob, 2), Some(preimages[1].as_slice()));
            assert_eq!(eraser.calls, 1);
        }

        {
            let (graph, _, bob_keypair) = fixture()?;
            let signer = TestSigner {
                role: Role::Bob,
                keypair: bob_keypair,
                calls: Cell::new(0),
            };
            let mut monitor =
                ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), PARENT_ID, 100, 105);
            let confirmed = {
                let mature = monitor.mature_timeout(&graph)?;
                let witness = build_timeout_witness(&graph, &mature, &signer)?;
                attach_timeout_witness(&graph, &mature, &witness)?
                    .transaction()
                    .clone()
            };
            let mut public = PublicPreimageStore::new(GAME_ID, graph.deal);
            let mut eraser = CountingEraser::default();
            monitor.confirm_child(
                &graph,
                TIMEOUT_CHILD_ID,
                &confirmed,
                105,
                &mut public,
                &mut eraser,
            )?;
            assert_eq!(eraser.calls, 1);
            assert!(matches!(
                monitor.state(),
                MonitorState::Terminal {
                    node_id: TIMEOUT_CHILD_ID,
                    ..
                }
            ));
        }

        Ok(())
    }

    #[test]
    fn peer_timeout_with_missing_signature_halts() -> Result<(), Box<dyn std::error::Error>> {
        let (graph, _, bob_keypair) = fixture()?;
        let signer = TestSigner {
            role: Role::Bob,
            keypair: bob_keypair,
            calls: Cell::new(0),
        };
        let mut monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), PARENT_ID, 100, 105);
        let mut malformed = {
            let mature = monitor.mature_timeout(&graph)?;
            let witness = build_timeout_witness(&graph, &mature, &signer)?;
            attach_timeout_witness(&graph, &mature, &witness)?
                .transaction()
                .clone()
        };
        let mut stack = malformed.input[0]
            .witness
            .iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        stack.remove(0);
        malformed.input[0].witness = bitcoin::Witness::from_slice(&stack);

        let mut public = PublicPreimageStore::new(GAME_ID, graph.deal);
        let mut eraser = CountingEraser::default();
        assert!(matches!(
            monitor.confirm_child(
                &graph,
                TIMEOUT_CHILD_ID,
                &malformed,
                105,
                &mut public,
                &mut eraser,
            ),
            Err(RuntimeError::InvalidWitnessEncoding { .. })
        ));
        assert_eq!(eraser.calls, 1);
        assert_eq!(monitor.state(), MonitorState::Halted);
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn peer_showdowns_recover_certificates_and_accept_equivalent_numeric_encodings()
    -> Result<(), Box<dyn std::error::Error>> {
        let PeerShowdownFixture {
            graph,
            mut public,
            alice_source,
            bob_source,
            mut score_secret,
            mut bob_score_secret,
            alice_score,
            bob_score,
            outcome,
            alice_keypair,
            bob_keypair,
        } = peer_showdown_fixture()?;
        let mut monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), ALICE_SHOWDOWN_ID, 100, 102);
        let alice_signer = TestSigner {
            role: Role::Alice,
            keypair: alice_keypair,
            calls: Cell::new(0),
        };

        let (mut mismatched_score_secret, _) = generate_key(
            &mut OsRng,
            KeyContext::new(
                GAME_ID,
                root_node_id(&GAME_ID),
                LamportPurpose::AliceScore24Bit,
            ),
        )?;
        assert!(matches!(
            build_alice_showdown_witness(
                &graph,
                &mut monitor,
                &public,
                &alice_source,
                0,
                alice_score,
                &mut mismatched_score_secret,
                &alice_signer,
            ),
            Err(RuntimeError::InconsistentGraph { .. })
        ));
        assert!(!mismatched_score_secret.signature_was_issued());
        assert!(matches!(monitor.state(), MonitorState::Active { .. }));

        let alice_witness = build_alice_showdown_witness(
            &graph,
            &mut monitor,
            &public,
            &alice_source,
            0,
            alice_score,
            &mut score_secret,
            &alice_signer,
        )?;
        let cached_retry = build_alice_showdown_witness(
            &graph,
            &mut monitor,
            &public,
            &alice_source,
            20,
            alice_score,
            &mut score_secret,
            &alice_signer,
        )?;
        assert_eq!(cached_retry, alice_witness);
        let expected_certificate = match &alice_witness {
            Witness::AliceShowdown { certificate, .. } => certificate.clone(),
            _ => return Err("expected Alice showdown witness".into()),
        };
        let mut peer_alice_witness = alice_witness;
        let alice_digest = graph.signature_digest(ALICE_SHOWDOWN_ID, BOB_TERMINAL_ID)?;
        let alternate = Secp256k1::new().sign_schnorr_with_aux_rand(
            &Message::from_digest(alice_digest),
            &alice_keypair,
            &[0x61; 32],
        );
        if let Witness::AliceShowdown {
            alice_signature, ..
        } = &mut peer_alice_witness
        {
            *alice_signature = DefaultSighashSignature::from_bytes(alternate.serialize())?;
        }
        {
            let active = monitor.confirmed_active_node(&graph)?;
            let mut wrong_opening = peer_alice_witness.clone();
            if let Witness::AliceShowdown { hand, .. } = &mut wrong_opening {
                let mut openings = hand.openings().clone();
                let first = &openings[0];
                let mut preimage_a = first.preimage_a().to_vec();
                preimage_a[0] ^= 1;
                openings[0] =
                    CardOpeningWitness::new(first.slot(), preimage_a, first.preimage_b().to_vec());
                *hand = ShowdownHandWitness::new(openings, hand.subset_id(), hand.claimed_score());
            }
            assert!(matches!(
                attach_witness(&graph, &active, &wrong_opening),
                Err(RuntimeError::Bitcoin(_))
            ));

            let mut wrong_certificate = peer_alice_witness.clone();
            if let Witness::AliceShowdown { certificate, .. } = &mut wrong_certificate {
                let mut preimages = certificate.lamport_signature().preimages().to_vec();
                preimages[0][0] ^= 1;
                *certificate = AliceScoreCertificate::from_parts(
                    certificate.score_a(),
                    bp52_lamport::LamportSignature::from_parts(
                        LamportPurpose::AliceScore24Bit,
                        preimages,
                    )?,
                )?;
            }
            assert!(matches!(
                attach_witness(&graph, &active, &wrong_certificate),
                Err(RuntimeError::Bitcoin(_))
            ));
        }
        let mut confirmed_alice = {
            let active = monitor.confirmed_active_node(&graph)?;
            attach_witness(&graph, &active, &peer_alice_witness)?
                .transaction()
                .clone()
        };
        let mut stack = confirmed_alice.input[0]
            .witness
            .iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let canonical_eval_value = bitcoin::script::read_scriptint_non_minimal(&stack[51])
            .map_err(|_| RuntimeError::InvalidWitnessEncoding {
                reason: "test evaluator value is not a Script number",
            })?;
        stack[51].push(0);
        assert_eq!(
            bitcoin::script::read_scriptint_non_minimal(&stack[51]).ok(),
            Some(canonical_eval_value)
        );
        confirmed_alice.input[0].witness = bitcoin::Witness::from_slice(&stack);

        let mut eraser = CountingEraser::default();
        monitor.confirm_child(
            &graph,
            BOB_TERMINAL_ID,
            &confirmed_alice,
            101,
            &mut public,
            &mut eraser,
        )?;
        assert_eq!(eraser.calls, 1);
        assert_eq!(
            public.alice_score_certificate(ALICE_SHOWDOWN_ID),
            Some(&expected_certificate)
        );

        let signer = TestSigner {
            role: Role::Bob,
            keypair: bob_keypair,
            calls: Cell::new(0),
        };
        let bob_witness = build_bob_payout_witness(
            &graph,
            &mut monitor,
            &public,
            &bob_source,
            0,
            bob_score,
            outcome,
            &mut bob_score_secret,
            &signer,
        )?;
        assert!(bob_score_secret.signature_was_issued());
        assert_eq!(signer.calls.get(), 1);
        assert_eq!(
            build_bob_payout_witness(
                &graph,
                &mut monitor,
                &public,
                &bob_source,
                0,
                bob_score,
                outcome,
                &mut bob_score_secret,
                &signer,
            )?,
            bob_witness
        );
        assert_eq!(signer.calls.get(), 1);
        let mut confirmed_bob = {
            let active = monitor.confirmed_active_node(&graph)?;
            attach_witness(&graph, &active, &bob_witness)?
                .transaction()
                .clone()
        };
        // Regression: Bob's evaluator starts after both 49-element score
        // certificates and two signatures, at ordinary witness index 100.
        let mut stack = confirmed_bob.input[0]
            .witness
            .iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let canonical_eval_value = bitcoin::script::read_scriptint_non_minimal(&stack[100])
            .map_err(|_| RuntimeError::InvalidWitnessEncoding {
                reason: "test Bob evaluator value is not a Script number",
            })?;
        stack[100].push(0);
        assert_eq!(
            bitcoin::script::read_scriptint_non_minimal(&stack[100]).ok(),
            Some(canonical_eval_value)
        );
        confirmed_bob.input[0].witness = bitcoin::Witness::from_slice(&stack);
        monitor.confirm_child(
            &graph,
            PAYOUT_CHILD_ID,
            &confirmed_bob,
            102,
            &mut public,
            &mut eraser,
        )?;
        assert_eq!(eraser.calls, 2);
        assert!(matches!(
            monitor.state(),
            MonitorState::Terminal {
                node_id: PAYOUT_CHILD_ID,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn conflicting_alice_score_retry_halts_and_erases_the_ots()
    -> Result<(), Box<dyn std::error::Error>> {
        let PeerShowdownFixture {
            graph,
            public,
            alice_source,
            mut score_secret,
            alice_score,
            alice_keypair,
            ..
        } = peer_showdown_fixture()?;
        let mut monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), ALICE_SHOWDOWN_ID, 100, 100);
        let alice_signer = TestSigner {
            role: Role::Alice,
            keypair: alice_keypair,
            calls: Cell::new(0),
        };
        let _ = build_alice_showdown_witness(
            &graph,
            &mut monitor,
            &public,
            &alice_source,
            0,
            alice_score,
            &mut score_secret,
            &alice_signer,
        )?;
        assert!(matches!(
            build_alice_showdown_witness(
                &graph,
                &mut monitor,
                &public,
                &alice_source,
                0,
                alice_score + 1,
                &mut score_secret,
                &alice_signer,
            ),
            Err(RuntimeError::ConflictingOtsAuthorization {
                node_id: ALICE_SHOWDOWN_ID
            })
        ));
        assert_eq!(monitor.state(), MonitorState::Halted);
        assert!(score_secret.is_erased());
        Ok(())
    }

    #[test]
    fn exact_peer_spend_with_conflicting_public_store_halts_after_erasure()
    -> Result<(), Box<dyn std::error::Error>> {
        let PeerShowdownFixture {
            graph,
            mut public,
            alice_source,
            mut score_secret,
            alice_score,
            alice_keypair,
            ..
        } = peer_showdown_fixture()?;
        let mut monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), ALICE_SHOWDOWN_ID, 100, 101);
        let alice_signer = TestSigner {
            role: Role::Alice,
            keypair: alice_keypair,
            calls: Cell::new(0),
        };
        let witness = build_alice_showdown_witness(
            &graph,
            &mut monitor,
            &public,
            &alice_source,
            0,
            alice_score,
            &mut score_secret,
            &alice_signer,
        )?;
        let certificate = match &witness {
            Witness::AliceShowdown { certificate, .. } => certificate.clone(),
            _ => return Err("expected Alice showdown witness".into()),
        };
        let confirmed = {
            let active = monitor.confirmed_active_node(&graph)?;
            attach_witness(&graph, &active, &witness)?
                .transaction()
                .clone()
        };
        let conflicting_node_id = [0x99; 32];
        public.insert_alice_score_certificate(conflicting_node_id, certificate)?;
        let mut eraser = CountingEraser::default();
        assert!(matches!(
            monitor.confirm_child(
                &graph,
                BOB_TERMINAL_ID,
                &confirmed,
                101,
                &mut public,
                &mut eraser,
            ),
            Err(RuntimeError::ConflictingAliceScoreCertificate {
                node_id: ALICE_SHOWDOWN_ID
            })
        ));
        assert_eq!(eraser.calls, 1);
        assert_eq!(monitor.state(), MonitorState::Halted);
        assert!(matches!(
            monitor.confirmed_active_node(&graph),
            Err(RuntimeError::NoConfirmedActiveNode)
        ));
        assert!(public.alice_score_certificate(ALICE_SHOWDOWN_ID).is_none());
        assert!(
            public
                .alice_score_certificate(conflicting_node_id)
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn attachment_revalidates_mutated_action_signatures() -> Result<(), Box<dyn std::error::Error>>
    {
        let (graph, alice_keypair, _) = fixture()?;
        let signer = TestSigner {
            role: Role::Alice,
            keypair: alice_keypair,
            calls: Cell::new(0),
        };
        let mut monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), PARENT_ID, 100, 101);
        let mut confirmed_transaction = {
            let witness = build_action_witness(&graph, &mut monitor, Action::Raise, &signer)?;
            let active = monitor.confirmed_active_node(&graph)?;
            let confirmed_transaction = attach_witness(&graph, &active, &witness)?
                .transaction()
                .clone();

            let mut wrong_bitcoin_signature = witness.clone();
            if let Witness::Action {
                alice_signature, ..
            } = &mut wrong_bitcoin_signature
            {
                *alice_signature = graph.signatures[1];
            }
            assert!(matches!(
                attach_witness(&graph, &active, &wrong_bitcoin_signature),
                Err(RuntimeError::Bitcoin(_))
            ));

            let mut wrong_opponent_signature = witness;
            if let Witness::Action { bob_signature, .. } = &mut wrong_opponent_signature {
                *bob_signature = graph.signatures[0];
            }
            assert!(matches!(
                attach_witness(&graph, &active, &wrong_opponent_signature),
                Err(RuntimeError::Bitcoin(_))
            ));
            confirmed_transaction
        };
        let mut ordinary = confirmed_transaction.input[0]
            .witness
            .iter()
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        ordinary[0][0] ^= 1;
        confirmed_transaction.input[0].witness = bitcoin::Witness::from_slice(&ordinary);

        let mut public = PublicPreimageStore::new(GAME_ID, graph.deal);
        let mut eraser = CountingEraser::default();
        assert!(matches!(
            monitor.confirm_child(
                &graph,
                ACTION_CHILD_ID,
                &confirmed_transaction,
                101,
                &mut public,
                &mut eraser,
            ),
            Err(RuntimeError::Bitcoin(_))
        ));
        assert_eq!(eraser.calls, 1);
        assert_eq!(monitor.state(), MonitorState::Halted);
        assert!(matches!(
            monitor.confirmed_active_node(&graph),
            Err(RuntimeError::NoConfirmedActiveNode)
        ));
        Ok(())
    }

    #[test]
    fn confirmation_cannot_claim_a_height_above_the_observed_tip()
    -> Result<(), Box<dyn std::error::Error>> {
        let (graph, alice_keypair, _) = fixture()?;
        let signer = TestSigner {
            role: Role::Alice,
            keypair: alice_keypair,
            calls: Cell::new(0),
        };
        let mut monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), PARENT_ID, 100, 100);
        let confirmed_transaction = {
            let witness = build_action_witness(&graph, &mut monitor, Action::Raise, &signer)?;
            let active = monitor.confirmed_active_node(&graph)?;
            attach_witness(&graph, &active, &witness)?
                .transaction()
                .clone()
        };
        let mut public = PublicPreimageStore::new(GAME_ID, graph.deal);
        let mut eraser = CountingEraser::default();
        assert!(matches!(
            monitor.confirm_child(
                &graph,
                ACTION_CHILD_ID,
                &confirmed_transaction,
                101,
                &mut public,
                &mut eraser,
            ),
            Err(RuntimeError::UnexpectedConfirmation)
        ));
        assert_eq!(eraser.calls, 0);
        assert!(matches!(
            monitor.state(),
            MonitorState::Active {
                node_id: PARENT_ID,
                confirmed_height: 100,
                ..
            }
        ));

        monitor.observe_tip(101)?;
        monitor.confirm_child(
            &graph,
            ACTION_CHILD_ID,
            &confirmed_transaction,
            101,
            &mut public,
            &mut eraser,
        )?;
        assert_eq!(eraser.calls, 1);
        assert!(matches!(
            monitor.state(),
            MonitorState::Terminal {
                node_id: ACTION_CHILD_ID,
                confirmed_height: 101,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn exact_confirmed_spend_halts_before_external_erasure_can_unwind()
    -> Result<(), Box<dyn std::error::Error>> {
        let (graph, alice_keypair, _) = fixture()?;
        let signer = TestSigner {
            role: Role::Alice,
            keypair: alice_keypair,
            calls: Cell::new(0),
        };
        let mut monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), PARENT_ID, 100, 101);
        let confirmed_transaction = {
            let witness = build_action_witness(&graph, &mut monitor, Action::Raise, &signer)?;
            let active = monitor.confirmed_active_node(&graph)?;
            attach_witness(&graph, &active, &witness)?
                .transaction()
                .clone()
        };
        let mut public = PublicPreimageStore::new(GAME_ID, graph.deal);
        let mut eraser = PanickingEraser;
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let _ = monitor.confirm_child(
                &graph,
                ACTION_CHILD_ID,
                &confirmed_transaction,
                101,
                &mut public,
                &mut eraser,
            );
        }));
        assert!(unwind.is_err());
        assert_eq!(monitor.state(), MonitorState::Halted);
        assert!(matches!(
            monitor.confirmed_active_node(&graph),
            Err(RuntimeError::NoConfirmedActiveNode)
        ));
        Ok(())
    }

    #[test]
    fn invalid_action_inputs_are_rejected_before_live_signing()
    -> Result<(), Box<dyn std::error::Error>> {
        let (graph, alice_keypair, bob_keypair) = fixture()?;
        let signer = TestSigner {
            role: Role::Alice,
            keypair: alice_keypair,
            calls: Cell::new(0),
        };
        let mut monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), PARENT_ID, 100, 100);
        assert!(matches!(
            build_action_witness(&graph, &mut monitor, Action::Call, &signer),
            Err(RuntimeError::EdgeNotFound { .. })
        ));
        assert_eq!(signer.calls.get(), 0);
        assert!(matches!(monitor.state(), MonitorState::Active { .. }));

        let (mut bad_graph, _, _) = fixture()?;
        bad_graph.wrong_opponent_signature = true;
        assert!(matches!(
            build_action_witness(&bad_graph, &mut monitor, Action::Raise, &signer),
            Err(RuntimeError::Bitcoin(_))
        ));
        assert_eq!(signer.calls.get(), 0);
        assert!(matches!(monitor.state(), MonitorState::Active { .. }));

        let invalid_live_signer = TestSigner {
            role: Role::Alice,
            keypair: bob_keypair,
            calls: Cell::new(0),
        };
        assert!(matches!(
            build_action_witness(&graph, &mut monitor, Action::Raise, &invalid_live_signer),
            Err(RuntimeError::Bitcoin(_))
        ));
        assert_eq!(invalid_live_signer.calls.get(), 1);
        assert_eq!(monitor.state(), MonitorState::Halted);
        Ok(())
    }

    #[test]
    fn timeout_signer_is_not_called_before_exact_maturity() -> Result<(), Box<dyn std::error::Error>>
    {
        let (graph, _, bob_keypair) = fixture()?;
        let signer = TestSigner {
            role: Role::Bob,
            keypair: bob_keypair,
            calls: Cell::new(0),
        };
        let immature_monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), PARENT_ID, 100, 104);
        assert!(matches!(
            immature_monitor.mature_timeout(&graph),
            Err(RuntimeError::TimeoutImmature {
                matures_at: 105,
                ..
            })
        ));
        assert_eq!(signer.calls.get(), 0);
        let monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), PARENT_ID, 100, 105);
        let mature = monitor.mature_timeout(&graph)?;
        let active = monitor.confirmed_active_node(&graph)?;
        let witness = build_timeout_witness(&graph, &mature, &signer)?;
        let Witness::Timeout {
            beneficiary: Role::Bob,
            alice_signature,
            bob_signature,
            ..
        } = &witness
        else {
            return Err(RuntimeError::WrongAuthorization.into());
        };
        let (alice_signature, bob_signature) = (*alice_signature, *bob_signature);
        assert_eq!(alice_signature, graph.timeout_signatures[0]);
        assert_eq!(bob_signature, graph.timeout_signatures[1]);
        assert_eq!(signer.calls.get(), 1);
        assert!(matches!(
            attach_witness(&graph, &active, &witness),
            Err(RuntimeError::TimeoutCapabilityRequired)
        ));
        let prepared = attach_timeout_witness(&graph, &mature, &witness)?;
        assert_eq!(
            prepared.template_txid(),
            graph
                .transaction_template(TIMEOUT_CHILD_ID)
                .ok_or("missing timeout template")?
                .txid()
        );

        let mut swapped = witness.clone();
        if let Witness::Timeout {
            alice_signature,
            bob_signature,
            ..
        } = &mut swapped
        {
            std::mem::swap(alice_signature, bob_signature);
        }
        assert!(matches!(
            attach_timeout_witness(&graph, &mature, &swapped),
            Err(RuntimeError::Bitcoin(_))
        ));

        let mut mutated_opponent = witness.clone();
        if let Witness::Timeout {
            alice_signature, ..
        } = &mut mutated_opponent
        {
            *alice_signature = graph.signatures[0];
        }
        assert!(matches!(
            attach_timeout_witness(&graph, &mature, &mutated_opponent),
            Err(RuntimeError::Bitcoin(_))
        ));

        let mut mutated_beneficiary = witness;
        if let Witness::Timeout { bob_signature, .. } = &mut mutated_beneficiary {
            *bob_signature = graph.signatures[1];
        }
        assert!(matches!(
            attach_timeout_witness(&graph, &mature, &mutated_beneficiary),
            Err(RuntimeError::Bitcoin(_))
        ));
        Ok(())
    }

    #[test]
    fn timeout_requires_valid_opponent_preauthorization_before_live_signing()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut missing_graph, _, bob_keypair) = fixture()?;
        missing_graph.timeout_preauthorization = TimeoutPreauthorization::Missing;
        let missing_signer = TestSigner {
            role: Role::Bob,
            keypair: bob_keypair,
            calls: Cell::new(0),
        };
        let missing_monitor =
            ChainMonitor::active_for_test(GAME_ID, missing_graph.graph_root(), PARENT_ID, 100, 105);
        let mature = missing_monitor.mature_timeout(&missing_graph)?;
        assert!(matches!(
            build_timeout_witness(&missing_graph, &mature, &missing_signer),
            Err(RuntimeError::MissingPreauthorization { role: Role::Alice })
        ));
        assert_eq!(missing_signer.calls.get(), 0);

        let (mut wrong_graph, _, bob_keypair) = fixture()?;
        wrong_graph.timeout_preauthorization = TimeoutPreauthorization::Wrong;
        let wrong_signer = TestSigner {
            role: Role::Bob,
            keypair: bob_keypair,
            calls: Cell::new(0),
        };
        let wrong_monitor =
            ChainMonitor::active_for_test(GAME_ID, wrong_graph.graph_root(), PARENT_ID, 100, 105);
        let mature = wrong_monitor.mature_timeout(&wrong_graph)?;
        assert!(matches!(
            build_timeout_witness(&wrong_graph, &mature, &wrong_signer),
            Err(RuntimeError::Bitcoin(_))
        ));
        assert_eq!(wrong_signer.calls.get(), 0);

        let (graph, alice_keypair, _) = fixture()?;
        let wrong_live_signer = TestSigner {
            role: Role::Bob,
            keypair: alice_keypair,
            calls: Cell::new(0),
        };
        let monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), PARENT_ID, 100, 105);
        let mature = monitor.mature_timeout(&graph)?;
        assert!(matches!(
            build_timeout_witness(&graph, &mature, &wrong_live_signer),
            Err(RuntimeError::Bitcoin(_))
        ));
        assert_eq!(wrong_live_signer.calls.get(), 1);
        Ok(())
    }

    #[test]
    fn alice_beneficiary_timeout_still_uses_canonical_signature_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let (graph, alice_keypair, _) = fixture_with_timeout_beneficiary(Role::Alice)?;
        let signer = TestSigner {
            role: Role::Alice,
            keypair: alice_keypair,
            calls: Cell::new(0),
        };
        let monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), PARENT_ID, 100, 105);
        let mature = monitor.mature_timeout(&graph)?;
        let witness = build_timeout_witness(&graph, &mature, &signer)?;
        let Witness::Timeout {
            beneficiary: Role::Alice,
            alice_signature,
            bob_signature,
            ..
        } = &witness
        else {
            return Err(RuntimeError::WrongAuthorization.into());
        };
        assert_eq!(*alice_signature, graph.timeout_signatures[0]);
        assert_eq!(*bob_signature, graph.timeout_signatures[1]);
        assert_eq!(signer.calls.get(), 1);
        attach_timeout_witness(&graph, &mature, &witness)?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn bob_payout_rejects_wrong_outcome_before_live_signing()
    -> Result<(), Box<dyn std::error::Error>> {
        let (
            wrong_graph,
            mut public,
            bob_secret,
            certificate,
            bob_score,
            mut bob_score_secret,
            bob_keypair,
        ) = showdown_fixture(ShowdownOutcome::AliceWin)?;
        let signer = TestSigner {
            role: Role::Bob,
            keypair: bob_keypair,
            calls: Cell::new(0),
        };
        let mut wrong_monitor = ChainMonitor::active_for_test(
            GAME_ID,
            wrong_graph.graph_root(),
            BOB_TERMINAL_ID,
            100,
            100,
        );
        assert!(matches!(
            build_bob_payout_witness(
                &wrong_graph,
                &mut wrong_monitor,
                &public,
                &bob_secret,
                0,
                bob_score,
                ShowdownOutcome::AliceWin,
                &mut bob_score_secret,
                &signer,
            ),
            Err(RuntimeError::MissingAliceScoreCertificate {
                node_id: ALICE_SHOWDOWN_ID
            })
        ));
        assert_eq!(signer.calls.get(), 0);
        assert!(!bob_score_secret.signature_was_issued());
        public.insert_alice_score_certificate(ALICE_SHOWDOWN_ID, certificate)?;
        assert!(matches!(
            build_bob_payout_witness(
                &wrong_graph,
                &mut wrong_monitor,
                &public,
                &bob_secret,
                0,
                bob_score,
                ShowdownOutcome::AliceWin,
                &mut bob_score_secret,
                &signer,
            ),
            Err(RuntimeError::Bitcoin(_))
        ));
        assert_eq!(signer.calls.get(), 0);
        assert!(!bob_score_secret.signature_was_issued());

        let (
            graph,
            mut public,
            bob_secret,
            certificate,
            bob_score,
            mut bob_score_secret,
            bob_keypair,
        ) = showdown_fixture(ShowdownOutcome::BobWin)?;
        public.insert_alice_score_certificate(ALICE_SHOWDOWN_ID, certificate)?;
        let signer = TestSigner {
            role: Role::Bob,
            keypair: bob_keypair,
            calls: Cell::new(0),
        };
        let mut monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), BOB_TERMINAL_ID, 100, 100);
        let witness = build_bob_payout_witness(
            &graph,
            &mut monitor,
            &public,
            &bob_secret,
            0,
            bob_score,
            ShowdownOutcome::BobWin,
            &mut bob_score_secret,
            &signer,
        )?;
        assert!(matches!(witness, Witness::BobPayout { .. }));
        assert!(bob_score_secret.signature_was_issued());
        assert_eq!(signer.calls.get(), 1);
        let active = monitor.confirmed_active_node(&graph)?;
        let prepared = attach_witness(&graph, &active, &witness)?;
        assert_eq!(prepared.template_txid(), graph.template.txid());

        let mut changed_opening = witness.clone();
        if let Witness::BobPayout { hand, .. } = &mut changed_opening {
            let mut openings = hand.openings().clone();
            let first = &openings[0];
            let mut wrong_preimage = first.preimage_a().to_vec();
            wrong_preimage[0] ^= 1;
            openings[0] =
                CardOpeningWitness::new(first.slot(), wrong_preimage, first.preimage_b().to_vec());
            *hand = ShowdownHandWitness::new(openings, hand.subset_id(), hand.claimed_score());
        }
        assert!(matches!(
            attach_witness(&graph, &active, &changed_opening),
            Err(RuntimeError::Bitcoin(_))
        ));

        let mut changed_certificate = witness.clone();
        if let Witness::BobPayout {
            alice_certificate, ..
        } = &mut changed_certificate
        {
            let mut preimages = alice_certificate.lamport_signature().preimages().to_vec();
            preimages[0][0] ^= 1;
            *alice_certificate = AliceScoreCertificate::from_parts(
                alice_certificate.score_a(),
                bp52_lamport::LamportSignature::from_parts(
                    LamportPurpose::AliceScore24Bit,
                    preimages,
                )?,
            )?;
        }
        assert!(matches!(
            attach_witness(&graph, &active, &changed_certificate),
            Err(RuntimeError::Bitcoin(_))
        ));

        let mut changed_bob_certificate = witness.clone();
        if let Witness::BobPayout {
            bob_certificate, ..
        } = &mut changed_bob_certificate
        {
            let mut preimages = bob_certificate.lamport_signature().preimages().to_vec();
            preimages[0][0] ^= 1;
            *bob_certificate = BobScoreCertificate::from_parts(
                bob_certificate.score_b(),
                bp52_lamport::LamportSignature::from_parts(
                    LamportPurpose::BobScore24Bit,
                    preimages,
                )?,
            )?;
        }
        assert!(matches!(
            attach_witness(&graph, &active, &changed_bob_certificate),
            Err(RuntimeError::Bitcoin(_))
        ));

        let mut changed_live_signature = witness;
        if let Witness::BobPayout {
            alice_signature,
            bob_signature,
            ..
        } = &mut changed_live_signature
        {
            *bob_signature = *alice_signature;
        }
        assert!(matches!(
            attach_witness(&graph, &active, &changed_live_signature),
            Err(RuntimeError::Bitcoin(_))
        ));
        Ok(())
    }

    #[test]
    fn conflicting_bob_score_retry_halts_and_erases_the_ots()
    -> Result<(), Box<dyn std::error::Error>> {
        let (
            graph,
            mut public,
            bob_secret,
            alice_certificate,
            bob_score,
            mut bob_score_secret,
            bob_keypair,
        ) = showdown_fixture(ShowdownOutcome::BobWin)?;
        public.insert_alice_score_certificate(ALICE_SHOWDOWN_ID, alice_certificate)?;
        let signer = TestSigner {
            role: Role::Bob,
            keypair: bob_keypair,
            calls: Cell::new(0),
        };
        let mut monitor =
            ChainMonitor::active_for_test(GAME_ID, graph.graph_root(), BOB_TERMINAL_ID, 100, 100);
        let _ = build_bob_payout_witness(
            &graph,
            &mut monitor,
            &public,
            &bob_secret,
            0,
            bob_score,
            ShowdownOutcome::BobWin,
            &mut bob_score_secret,
            &signer,
        )?;
        assert!(matches!(
            build_bob_payout_witness(
                &graph,
                &mut monitor,
                &public,
                &bob_secret,
                0,
                bob_score + 1,
                ShowdownOutcome::BobWin,
                &mut bob_score_secret,
                &signer,
            ),
            Err(RuntimeError::ConflictingOtsAuthorization {
                node_id: BOB_TERMINAL_ID
            })
        ));
        assert_eq!(signer.calls.get(), 1);
        assert!(bob_score_secret.is_erased());
        assert_eq!(monitor.state(), MonitorState::Halted);
        Ok(())
    }
}
