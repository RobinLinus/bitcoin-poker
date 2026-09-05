use super::*;
use crate::{verify_setup_certificate, verify_share_reveal};

#[test]
fn two_live_participants_persist_exchange_and_accept_same_certificate() {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let key_a = SigningKey::from_bytes(&[3; 32]).expect("A key");
            let key_b = SigningKey::from_bytes(&[5; 32]).expect("B key");
            let mut keys = [
                (
                    Into::<[u8; 32]>::into(key_a.verifying_key().to_bytes()),
                    [3; 32],
                ),
                (
                    Into::<[u8; 32]>::into(key_b.verifying_key().to_bytes()),
                    [5; 32],
                ),
            ];
            keys.sort_by_key(|entry| entry.0);
            let config = GameConfig {
                network_genesis: [1; 32],
                session_anchor: [2; 32],
                identity_a: keys[0].0,
                identity_b: keys[1].0,
                session_nonce: [3; 32],
                rules_hash: [4; 32],
            };
            let mut a = LiveParticipant::new(config.clone(), Role::A, keys[0].1, [0x51; 32])
                .expect("participant A");
            let mut b = LiveParticipant::new(config, Role::B, keys[1].1, [0x62; 32])
                .expect("participant B");
            for _ in 0..20 {
                if a.snapshot().accepted && b.snapshot().accepted {
                    break;
                }
                let outgoing_a = a.prepare_outgoing().expect("prepare A");
                let outgoing_b = b.prepare_outgoing().expect("prepare B");
                if let Some(bytes) = &outgoing_a {
                    assert_eq!(a.prepare_outgoing().expect("retransmit A"), outgoing_a);
                    a.confirm_persisted_outgoing(bytes).expect("persist A");
                }
                if let Some(bytes) = &outgoing_b {
                    b.confirm_persisted_outgoing(bytes).expect("persist B");
                }
                if let Some(bytes) = &outgoing_a {
                    b.accept_peer(bytes).expect("accept A");
                }
                if let Some(bytes) = &outgoing_b {
                    a.accept_peer(bytes).expect("accept B");
                }
            }
            assert!(a.snapshot().accepted && b.snapshot().accepted);
            assert_eq!(
                a.certificate().expect("cert A"),
                b.certificate().expect("cert B")
            );
            assert_eq!(a.certificate().expect("cert").len(), 102_070);
            assert!(verify_setup_certificate(a.certificate().expect("cert replay")).is_ok());
            let commitment = [0x91; 32];
            let signature = a
                .sign_offchain_commitment(commitment, &[0x92; 32])
                .expect("sign off-chain commitment");
            a.verify_offchain_commitment(Role::A, commitment, signature)
                .expect("verify own off-chain commitment");
            b.verify_offchain_commitment(Role::A, commitment, signature)
                .expect("peer verifies off-chain commitment");
            assert!(
                b.verify_offchain_commitment(Role::A, [0x93; 32], signature)
                    .is_err()
            );
            let reveal = a
                .authorized_share_reveal(1, Role::B.as_u8(), 0, &[0x33; 32])
                .expect("authorized private hole reveal");
            assert_eq!(reveal.len(), 199);
            let verified = verify_share_reveal(a.accepted().expect("accepted"), &reveal)
                .expect("verified reveal");
            assert_eq!(
                (
                    verified.sender(),
                    verified.recipient(),
                    verified.slot(),
                    verified.stage()
                ),
                (Role::A, Role::B.as_u8(), 1, 0)
            );
            assert!(
                a.authorized_share_reveal(0, Role::B.as_u8(), 0, &[0x44; 32])
                    .is_err()
            );
            let mut tampered = reveal;
            tampered[120] ^= 1;
            assert!(verify_share_reveal(a.accepted().expect("accepted"), &tampered).is_err());
        })
        .expect("spawn")
        .join()
        .expect("join");
}
