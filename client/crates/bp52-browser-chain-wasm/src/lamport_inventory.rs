//! Compact lifecycle tracking for deterministically derived Lamport keys.
//!
//! Plaintext secret keys are never retained. A selected key is regenerated
//! from the worker snapshot seed, checked against the authenticated public key
//! retained in the active graph page, used once, and dropped. Only two
//! lifecycle bits per expected key survive between calls and in checkpoints.

use bp52_chain_types::{NodeId, Role};
use bp52_lamport::{
    ExpectedLamportEntry, KeyContext, LamportPublicBundle, LamportPublicKey, LamportPurpose,
    LamportRole, LamportSecretKey, generate_key,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use zeroize::Zeroizing;

use super::tagged_hash;

const LAMPORT_RNG_TAG: &[u8] = b"BP52/browser-chain-lamport-rng/v1";
const BITS_PER_STATE: usize = 2;
const STATES_PER_BYTE: usize = 8 / BITS_PER_STATE;
const STATE_MASK: u8 = 0b11;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum KeyState {
    Fresh = 0,
    Issued = 1,
    Erased = 2,
}

impl KeyState {
    fn decode(value: u8) -> Result<Self, String> {
        match value {
            0 => Ok(Self::Fresh),
            1 => Ok(Self::Issued),
            2 => Ok(Self::Erased),
            _ => Err("Lamport inventory contains an unknown lifecycle state".to_owned()),
        }
    }
}

/// Two-bit lifecycle inventory for deterministically derived local keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeterministicLamportInventory {
    key_count: usize,
    states: Vec<u8>,
    bundle_root: Option<[u8; 32]>,
    bundle_signature: Option<[u8; 64]>,
}

impl DeterministicLamportInventory {
    /// Construct a fresh bitmap and the corresponding public keys.
    pub(crate) fn generate_public_keys(
        snapshot_key: &[u8; 32],
        shared_config_hash: [u8; 32],
        chain_game_id: [u8; 32],
        role: Role,
        expected: &[ExpectedLamportEntry],
    ) -> Result<(Self, Vec<LamportPublicKey>), String> {
        let mut public = Vec::with_capacity(expected.len());
        for entry in expected {
            let (_secret, public_key) = derive_key(
                snapshot_key,
                shared_config_hash,
                chain_game_id,
                role,
                entry.node_id,
                entry.purpose,
            )?;
            public.push(public_key);
        }
        Ok((Self::fresh(expected.len()), public))
    }

    pub(crate) fn fresh(key_count: usize) -> Self {
        Self {
            key_count,
            states: vec![0; key_count.div_ceil(STATES_PER_BYTE)],
            bundle_root: None,
            bundle_signature: None,
        }
    }

    /// Bind the compact root/signature facts from the generated local bundle.
    pub(crate) fn bind_bundle(
        &mut self,
        bundle: &LamportPublicBundle,
        chain_game_id: [u8; 32],
        role: Role,
    ) -> Result<(), String> {
        let expected_role = match role {
            Role::Alice => LamportRole::Alice,
            Role::Bob => LamportRole::Bob,
        };
        if bundle.chain_game_id() != chain_game_id
            || bundle.role() != expected_role
            || bundle.entries().len() != self.key_count
        {
            return Err("local Lamport receipt differs from its inventory".to_owned());
        }
        let root = bundle.bundle_root();
        let signature = *bundle.signature();
        if self.bundle_root.is_some_and(|existing| existing != root)
            || self
                .bundle_signature
                .is_some_and(|existing| existing != signature)
        {
            return Err("local Lamport receipt conflicts with its prior binding".to_owned());
        }
        self.bundle_root = Some(root);
        self.bundle_signature = Some(signature);
        Ok(())
    }

    /// Verify a transiently regenerated bundle against compact receipt facts.
    pub(crate) fn verify_regenerated_bundle(
        &self,
        bundle: &LamportPublicBundle,
    ) -> Result<(), String> {
        if bundle.entries().len() != self.key_count
            || self.bundle_root != Some(bundle.bundle_root())
            || self.bundle_signature != Some(*bundle.signature())
        {
            return Err("regenerated local Lamport bundle differs from its receipt".to_owned());
        }
        Ok(())
    }

    /// Number of lifecycle entries represented by the bitmap.
    pub(crate) const fn len(&self) -> usize {
        self.key_count
    }

    /// Bytes retained by the packed lifecycle bitmap.
    #[cfg(test)]
    pub(crate) fn retained_state_bytes(&self) -> usize {
        self.states.len()
    }

    /// Regenerate one fresh key and authenticate it against the page's public key.
    pub(crate) fn derive_fresh_key(
        &self,
        index: usize,
        snapshot_key: &[u8; 32],
        shared_config_hash: [u8; 32],
        chain_game_id: [u8; 32],
        role: Role,
        node_id: NodeId,
        purpose: LamportPurpose,
        expected_public: &LamportPublicKey,
    ) -> Result<LamportSecretKey, String> {
        if self.state(index)? != KeyState::Fresh {
            return Err("Lamport key is no longer fresh".to_owned());
        }
        let (secret, public) = derive_key(
            snapshot_key,
            shared_config_hash,
            chain_game_id,
            role,
            node_id,
            purpose,
        )?;
        if expected_public.context() != KeyContext::new(chain_game_id, node_id, purpose)
            || public != *expected_public
            || !secret.matches_public_key(expected_public)
        {
            return Err("regenerated Lamport key differs from its authenticated bundle".to_owned());
        }
        Ok(secret)
    }

    /// Persist the lifecycle reached by one temporary derived key.
    pub(crate) fn record_key_state(
        &mut self,
        index: usize,
        key: &LamportSecretKey,
    ) -> Result<(), String> {
        let prior = self.state(index)?;
        if prior != KeyState::Fresh {
            return Err("Lamport lifecycle was already consumed".to_owned());
        }
        let next = if key.is_erased() {
            KeyState::Erased
        } else if key.signature_was_issued() {
            KeyState::Issued
        } else {
            KeyState::Fresh
        };
        self.set_state(index, next)
    }

    /// Mark one graph-indexed key as irreversibly erased after its node spends.
    pub(crate) fn erase_index(&mut self, index: usize) -> Result<(), String> {
        self.set_state(index, KeyState::Erased)
    }

    /// Prove the exact inventory is still unused without deriving secrets.
    ///
    /// Generation already authenticated every deterministic public half. This
    /// check rejects readiness after any key has been issued or erased.
    pub(crate) fn fresh_count(&self) -> Result<u32, String> {
        for index in 0..self.key_count {
            if self.state(index)? != KeyState::Fresh {
                return Err("Lamport inventory is not entirely fresh".to_owned());
            }
        }
        u32::try_from(self.key_count).map_err(|_| "Lamport key count exceeds u32".to_owned())
    }

    /// Return the canonical packed checkpoint representation.
    pub(crate) fn checkpoint_bytes(&self) -> &[u8] {
        &self.states
    }

    /// Validate a packed checkpoint bitmap without retaining it.
    pub(crate) fn validate_packed(key_count: usize, stored: &[u8]) -> Result<(), String> {
        Self::fresh(key_count).restore_packed(stored)
    }

    /// Return whether a validated packed bitmap contains an issued key.
    pub(crate) fn packed_contains_issued(key_count: usize, stored: &[u8]) -> Result<bool, String> {
        let mut inventory = Self::fresh(key_count);
        inventory.restore_packed(stored)?;
        for index in 0..key_count {
            if inventory.state(index)? == KeyState::Issued {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Restore authenticated checkpoint state without allowing replay-derived
    /// erasures to be downgraded.
    pub(crate) fn restore_packed(&mut self, stored: &[u8]) -> Result<(), String> {
        if stored.len() != self.key_count.div_ceil(STATES_PER_BYTE) {
            return Err("restored Lamport bitmap length differs from the graph".to_owned());
        }
        if let Some(last) = stored.last() {
            let used = self.key_count % STATES_PER_BYTE;
            if used != 0 && last >> (used * BITS_PER_STATE) != 0 {
                return Err("Lamport bitmap has nonzero unused tail bits".to_owned());
            }
        }
        for index in 0..self.key_count {
            let current = self.state(index)?;
            let shift = (index % STATES_PER_BYTE) * BITS_PER_STATE;
            let restored =
                KeyState::decode((stored[index / STATES_PER_BYTE] >> shift) & STATE_MASK)?;
            if current == KeyState::Erased && restored != KeyState::Erased {
                return Err("checkpoint attempts to revive an erased Lamport key".to_owned());
            }
            if current == KeyState::Issued && restored == KeyState::Fresh {
                return Err("checkpoint attempts to reuse an issued Lamport key".to_owned());
            }
            self.set_state(index, restored)?;
        }
        Ok(())
    }

    fn state(&self, index: usize) -> Result<KeyState, String> {
        if index >= self.key_count {
            return Err("Lamport lifecycle index is out of bounds".to_owned());
        }
        let shift = (index % STATES_PER_BYTE) * BITS_PER_STATE;
        KeyState::decode((self.states[index / STATES_PER_BYTE] >> shift) & STATE_MASK)
    }

    fn set_state(&mut self, index: usize, state: KeyState) -> Result<(), String> {
        if index >= self.key_count {
            return Err("Lamport lifecycle index is out of bounds".to_owned());
        }
        let byte = &mut self.states[index / STATES_PER_BYTE];
        let shift = (index % STATES_PER_BYTE) * BITS_PER_STATE;
        *byte = (*byte & !(STATE_MASK << shift)) | ((state as u8) << shift);
        Ok(())
    }
}

pub(crate) fn derive_key(
    snapshot_key: &[u8; 32],
    shared_config_hash: [u8; 32],
    chain_game_id: [u8; 32],
    role: Role,
    node_id: NodeId,
    purpose: LamportPurpose,
) -> Result<(LamportSecretKey, LamportPublicKey), String> {
    let mut material = Zeroizing::new(Vec::with_capacity(130));
    material.extend_from_slice(snapshot_key);
    material.extend_from_slice(&shared_config_hash);
    material.extend_from_slice(&chain_game_id);
    material.extend_from_slice(&node_id);
    material.push(purpose as u8);
    material.push(role.code());
    let mut rng = ChaCha20Rng::from_seed(tagged_hash(LAMPORT_RNG_TAG, &material));
    generate_key(&mut rng, KeyContext::new(chain_game_id, node_id, purpose))
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use bp52_chain_types::Role;
    use bp52_lamport::{ExpectedLamportEntry, LamportPurpose, Score24, sign_alice_score};

    use super::DeterministicLamportInventory;

    #[test]
    fn inventory_retains_two_bits_and_derives_only_selected_key() -> Result<(), String> {
        let profile_inventory = DeterministicLamportInventory::fresh(5_103);
        assert_eq!(profile_inventory.len(), 5_103);
        assert_eq!(
            profile_inventory.retained_state_bytes(),
            5_103_usize.div_ceil(4)
        );

        let game = [3; 32];
        let shared = [5; 32];
        let snapshot = [7; 32];
        let expected = (0_u16..2)
            .map(|index| {
                let mut node = [0_u8; 32];
                node[..2].copy_from_slice(&index.to_le_bytes());
                ExpectedLamportEntry::new(node, LamportPurpose::AliceScore24Bit)
            })
            .collect::<Vec<_>>();
        let (mut inventory, public) = DeterministicLamportInventory::generate_public_keys(
            &snapshot,
            shared,
            game,
            Role::Alice,
            &expected,
        )?;
        assert_eq!(inventory.len(), 2);
        let selected = 1;
        let mut key = inventory.derive_fresh_key(
            selected,
            &snapshot,
            shared,
            game,
            Role::Alice,
            expected[selected].node_id,
            expected[selected].purpose,
            &public[selected],
        )?;
        sign_alice_score(
            &mut key,
            Score24::new(1).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        inventory.record_key_state(selected, &key)?;
        assert!(
            inventory
                .derive_fresh_key(
                    selected,
                    &snapshot,
                    shared,
                    game,
                    Role::Alice,
                    expected[selected].node_id,
                    expected[selected].purpose,
                    &public[selected],
                )
                .is_err()
        );
        assert_eq!(inventory.checkpoint_bytes(), &[0b0000_0100]);
        Ok(())
    }

    #[test]
    fn restore_cannot_revive_replay_erasure() -> Result<(), String> {
        let game = [11; 32];
        let node = [12; 32];
        let expected = [ExpectedLamportEntry::new(
            node,
            LamportPurpose::BobScore24Bit,
        )];
        let (mut inventory, _public) = DeterministicLamportInventory::generate_public_keys(
            &[13; 32],
            [14; 32],
            game,
            Role::Bob,
            &expected,
        )?;
        inventory.erase_index(0)?;
        assert!(inventory.restore_packed(&[0]).is_err());
        inventory.restore_packed(&[2])?;

        let mut five = DeterministicLamportInventory::fresh(5);
        assert!(five.restore_packed(&[0, 0b0000_0100]).is_err());
        assert!(five.restore_packed(&[0b0000_0011, 0]).is_err());
        Ok(())
    }
}
