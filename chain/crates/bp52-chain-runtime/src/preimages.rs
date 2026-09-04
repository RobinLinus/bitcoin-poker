//! Bounded storage for preimages already made public on chain.

use std::collections::BTreeMap;

use bitcoin::hashes::{Hash, sha256};
use bp52_chain_bitcoin::{AliceScoreCertificate, CardOpeningWitness, RevealPattern};
use bp52_chain_types::{AcceptedDeal, NodeId, Role};
use bp52_protocol::SecretContribution;
use bp52_protocol::contribution::RetainedPreimages;

use crate::RuntimeError;

const SLOT_COUNT: u8 = 9;
const MIN_PREIMAGE_BYTES: usize = 16;
const MAX_PREIMAGE_BYTES: usize = 67;

/// Maximum Alice-then-Bob public openings retained for one accepted deal.
pub const MAX_PUBLIC_PREIMAGES: usize = 18;

/// Result of adding a verified public opening.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertStatus {
    /// A previously unseen public opening was retained.
    Inserted,
    /// The same public opening had already been retained.
    AlreadyPresent,
}

/// Read-only access to one party's still-secret accepted preimages.
///
/// The trait deliberately exposes borrows only. It provides no plaintext
/// export, persistence, cloning, or debugging facility.
pub trait SecretPreimageSource {
    /// Borrow one secret preimage from the fixed v1 slot mapping.
    fn preimage(&self, slot: usize) -> Option<&[u8]>;
}

impl SecretPreimageSource for SecretContribution {
    fn preimage(&self, slot: usize) -> Option<&[u8]> {
        SecretContribution::preimage(self, slot)
    }
}

impl SecretPreimageSource for RetainedPreimages {
    fn preimage(&self, slot: usize) -> Option<&[u8]> {
        self.get(slot)
    }
}

/// Public, bounded, deal-bound preimages recovered from confirmed witnesses.
///
/// Inserting the same opening again is idempotent, which is necessary because
/// later showdown transactions repeat earlier witness data. A conflicting
/// value for an already populated `(role, slot)` is a hard error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicPreimageStore {
    chain_game_id: [u8; 32],
    accepted_deal: AcceptedDeal,
    entries: BTreeMap<(Role, u8), Vec<u8>>,
    alice_score_certificate: Option<(NodeId, AliceScoreCertificate)>,
}

impl PublicPreimageStore {
    /// Create an empty store bound to one exact compiled game and deal.
    #[must_use]
    pub const fn new(chain_game_id: [u8; 32], accepted_deal: AcceptedDeal) -> Self {
        Self {
            chain_game_id,
            accepted_deal,
            entries: BTreeMap::new(),
            alice_score_certificate: None,
        }
    }

    /// Return the compiled chain-game binding.
    #[must_use]
    pub const fn chain_game_id(&self) -> [u8; 32] {
        self.chain_game_id
    }

    /// Return the exact accepted deal whose hashes are checked on insertion.
    #[must_use]
    pub const fn accepted_deal(&self) -> &AcceptedDeal {
        &self.accepted_deal
    }

    /// Return the number of distinct public openings retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether no public openings have been observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Borrow a verified public opening.
    #[must_use]
    pub fn get(&self, role: Role, slot: u8) -> Option<&[u8]> {
        self.entries.get(&(role, slot)).map(Vec::as_slice)
    }

    /// Borrow the verified Alice score certificate recovered from a confirmed
    /// showdown witness at one exact Alice-showdown node.
    #[must_use]
    pub fn alice_score_certificate(
        &self,
        alice_showdown_node_id: NodeId,
    ) -> Option<&AliceScoreCertificate> {
        self.alice_score_certificate
            .as_ref()
            .and_then(|(node_id, certificate)| {
                (*node_id == alice_showdown_node_id).then_some(certificate)
            })
    }

    /// Verify and retain one public opening.
    ///
    /// # Errors
    ///
    /// Rejects an invalid slot, invalid length, hash mismatch, or a value that
    /// conflicts with an opening already recovered from the chain.
    pub fn insert(
        &mut self,
        role: Role,
        slot: u8,
        preimage: Vec<u8>,
    ) -> Result<InsertStatus, RuntimeError> {
        verify_preimage(&self.accepted_deal, role, slot, &preimage)?;
        if let Some(existing) = self.entries.get(&(role, slot)) {
            return if existing == &preimage {
                Ok(InsertStatus::AlreadyPresent)
            } else {
                Err(RuntimeError::ConflictingPreimage { role, slot })
            };
        }
        if self.entries.len() >= MAX_PUBLIC_PREIMAGES {
            return Err(RuntimeError::InvalidWitnessEncoding {
                reason: "public preimage store exceeded the fixed v1 bound",
            });
        }
        self.entries.insert((role, slot), preimage);
        Ok(InsertStatus::Inserted)
    }

    /// Verify and retain a complete reveal in canonical slot order.
    ///
    /// Validation is transactional: no entry is changed unless every supplied
    /// preimage is valid and nonconflicting.
    ///
    /// # Errors
    ///
    /// Rejects a wrong count or any invalid/conflicting opening.
    pub fn insert_reveal(
        &mut self,
        pattern: RevealPattern,
        preimages: &[Vec<u8>],
    ) -> Result<Vec<InsertStatus>, RuntimeError> {
        if preimages.len() != pattern.slots().len() {
            return Err(RuntimeError::InvalidWitnessEncoding {
                reason: "reveal preimage count does not match its fixed pattern",
            });
        }
        let role = pattern.revealer();
        for (&slot, preimage) in pattern.slots().iter().zip(preimages) {
            verify_preimage(&self.accepted_deal, role, slot, preimage)?;
            if self
                .entries
                .get(&(role, slot))
                .is_some_and(|existing| existing != preimage)
            {
                return Err(RuntimeError::ConflictingPreimage { role, slot });
            }
        }
        pattern
            .slots()
            .iter()
            .zip(preimages)
            .map(|(&slot, preimage)| self.insert(role, slot, preimage.clone()))
            .collect()
    }

    /// Retain both halves of every opening carried by a showdown witness.
    ///
    /// # Errors
    ///
    /// Rejects any invalid or conflicting opening without partially updating
    /// the store.
    pub fn insert_showdown_openings(
        &mut self,
        openings: &[CardOpeningWitness; 7],
    ) -> Result<(), RuntimeError> {
        for opening in openings {
            verify_preimage(
                &self.accepted_deal,
                Role::Alice,
                opening.slot(),
                opening.preimage_a(),
            )?;
            verify_preimage(
                &self.accepted_deal,
                Role::Bob,
                opening.slot(),
                opening.preimage_b(),
            )?;
            for (role, preimage) in [
                (Role::Alice, opening.preimage_a()),
                (Role::Bob, opening.preimage_b()),
            ] {
                if self
                    .entries
                    .get(&(role, opening.slot()))
                    .is_some_and(|existing| existing.as_slice() != preimage)
                {
                    return Err(RuntimeError::ConflictingPreimage {
                        role,
                        slot: opening.slot(),
                    });
                }
            }
        }
        for opening in openings {
            self.insert(Role::Alice, opening.slot(), opening.preimage_a().to_vec())?;
            self.insert(Role::Bob, opening.slot(), opening.preimage_b().to_vec())?;
        }
        Ok(())
    }

    pub(crate) fn insert_alice_score_certificate(
        &mut self,
        alice_showdown_node_id: NodeId,
        certificate: AliceScoreCertificate,
    ) -> Result<InsertStatus, RuntimeError> {
        match &self.alice_score_certificate {
            Some((existing_node_id, existing_certificate))
                if *existing_node_id == alice_showdown_node_id
                    && existing_certificate == &certificate =>
            {
                Ok(InsertStatus::AlreadyPresent)
            }
            Some(_) => Err(RuntimeError::ConflictingAliceScoreCertificate {
                node_id: alice_showdown_node_id,
            }),
            None => {
                self.alice_score_certificate = Some((alice_showdown_node_id, certificate));
                Ok(InsertStatus::Inserted)
            }
        }
    }

    pub(crate) fn ensure_binding(
        &self,
        chain_game_id: [u8; 32],
        accepted_deal: &AcceptedDeal,
    ) -> Result<(), RuntimeError> {
        if self.chain_game_id != chain_game_id {
            return Err(RuntimeError::WrongChainGame);
        }
        if &self.accepted_deal != accepted_deal {
            return Err(RuntimeError::WrongAcceptedDeal);
        }
        Ok(())
    }
}

pub(crate) fn verify_preimage(
    deal: &AcceptedDeal,
    role: Role,
    slot: u8,
    preimage: &[u8],
) -> Result<(), RuntimeError> {
    if slot >= SLOT_COUNT {
        return Err(RuntimeError::InvalidSlot { slot });
    }
    if !(MIN_PREIMAGE_BYTES..=MAX_PREIMAGE_BYTES).contains(&preimage.len()) {
        return Err(RuntimeError::InvalidPreimageLength {
            role,
            slot,
            actual: preimage.len(),
        });
    }
    let expected = match role {
        Role::Alice => deal.hashes_a[usize::from(slot)],
        Role::Bob => deal.hashes_b[usize::from(slot)],
    };
    if sha256::Hash::hash(preimage).to_byte_array() != expected {
        return Err(RuntimeError::WrongPreimage { role, slot });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::{Hash, sha256};
    use bp52_chain_bitcoin::RevealPattern;
    use bp52_chain_types::{AcceptedDeal, Role};

    use super::{InsertStatus, PublicPreimageStore};
    use crate::RuntimeError;

    fn preimage(role: Role, slot: usize) -> Vec<u8> {
        let role_byte = match role {
            Role::Alice => 0x20,
            Role::Bob => 0x80,
        };
        vec![role_byte + u8::try_from(slot).unwrap_or_default(); 16 + slot]
    }

    fn deal() -> AcceptedDeal {
        AcceptedDeal {
            protocol_version: 1,
            game_id: [3; 32],
            attempt: 7,
            hashes_a: core::array::from_fn(|slot| {
                sha256::Hash::hash(&preimage(Role::Alice, slot)).to_byte_array()
            }),
            hashes_b: core::array::from_fn(|slot| {
                sha256::Hash::hash(&preimage(Role::Bob, slot)).to_byte_array()
            }),
            verification_transcript_root: [4; 32],
            signature_a: [5; 64],
            signature_b: [6; 64],
        }
    }

    #[test]
    fn repeated_public_data_is_idempotent_and_bounded() -> Result<(), RuntimeError> {
        let mut store = PublicPreimageStore::new([9; 32], deal());
        let opening = preimage(Role::Alice, 7);
        assert_eq!(
            store.insert(Role::Alice, 7, opening.clone())?,
            InsertStatus::Inserted
        );
        assert_eq!(
            store.insert(Role::Alice, 7, opening.clone())?,
            InsertStatus::AlreadyPresent
        );
        assert_eq!(store.get(Role::Alice, 7), Some(opening.as_slice()));
        assert_eq!(store.len(), 1);

        let flop = [4_usize, 5, 6]
            .map(|slot| preimage(Role::Bob, slot))
            .to_vec();
        store.insert_reveal(RevealPattern::Flop(Role::Bob), &flop)?;
        store.insert_reveal(RevealPattern::Flop(Role::Bob), &flop)?;
        assert_eq!(store.len(), 4);
        Ok(())
    }

    #[test]
    fn invalid_preimages_and_wrong_bindings_fail_closed() {
        let accepted = deal();
        let mut store = PublicPreimageStore::new([9; 32], accepted);
        assert!(matches!(
            store.insert(Role::Bob, 1, vec![1; 15]),
            Err(RuntimeError::InvalidPreimageLength { .. })
        ));
        assert!(matches!(
            store.insert(Role::Bob, 1, vec![1; 17]),
            Err(RuntimeError::WrongPreimage { .. })
        ));
        assert!(matches!(
            store.insert(Role::Bob, 9, vec![1; 16]),
            Err(RuntimeError::InvalidSlot { .. })
        ));
        assert!(matches!(
            store.ensure_binding([8; 32], &accepted),
            Err(RuntimeError::WrongChainGame)
        ));
        let mut other = accepted;
        other.attempt += 1;
        assert!(matches!(
            store.ensure_binding([9; 32], &other),
            Err(RuntimeError::WrongAcceptedDeal)
        ));
    }
}
