#![no_main]

use bp52_codec::Decode;
use bp52_protocol::{
    PROTOCOL_VERSION, Role,
    messages::{Envelope, PayloadType, UnsignedEnvelope},
    state::{ATTEMPT_ENVELOPE_COUNT, AttemptSchedule, expected_envelope, first_blinder},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut game_id = [0_u8; 32];
    let context_bytes = data.get(1..).unwrap_or_default();
    let copied = context_bytes.len().min(game_id.len());
    game_id[..copied].copy_from_slice(&context_bytes[..copied]);

    let attempt = read_u32(data.get(33..).unwrap_or_default());
    let sequence = read_u32(data.get(37..).unwrap_or_default());
    let selected_role = if data.get(41).copied().unwrap_or(0) & 1 == 0 {
        Role::Alice
    } else {
        Role::Bob
    };

    let entry = expected_envelope(sequence, selected_role);
    assert_eq!(entry.is_some(), sequence < ATTEMPT_ENVELOPE_COUNT);
    if let Some(entry) = entry {
        assert_eq!(entry.sequence, sequence);
    }

    let mut schedule = AttemptSchedule::new(game_id, attempt);
    assert_eq!(schedule.first_blinder(), first_blinder(&game_id, attempt));
    assert_eq!(schedule.next_sequence(), 0);
    let _ = schedule.expected();
    let _ = schedule.timeout_outcome();

    // Raw inputs exercise all canonical envelope size and field decoders.
    if let Ok(envelope) = Envelope::decode_exact(data.get(42..).unwrap_or_default()) {
        let _ = schedule.validate_header(&envelope);
    }

    // Also reach every schedule-header branch immediately from an empty
    // corpus. Growing a raw input into a complete signed envelope first would
    // otherwise waste most of a short CI fuzz campaign.
    // Put the progression selector in the first byte so even a tiny corpus
    // reaches the complete T0..T16 chain during a short CI smoke campaign.
    let requested_steps = usize::from(data.first().copied().unwrap_or(0))
        % (usize::try_from(ATTEMPT_ENVELOPE_COUNT).expect("constant fits usize") + 1);
    for step in 0..requested_steps {
        let Ok(expected) = schedule.expected() else {
            break;
        };
        let envelope = Envelope {
            unsigned: UnsignedEnvelope {
                protocol_version: PROTOCOL_VERSION,
                game_id,
                attempt,
                round: expected.round,
                sender_role: expected.sender,
                sequence: expected.sequence,
                previous_message_hash: schedule.transcript_root(),
                payload_type: expected.payload_type,
                payload: vec![0_u8; expected.payload_type.max_payload_len()],
            },
            signature: [0_u8; 64],
        };
        assert!(schedule.validate_header(&envelope).is_ok());

        // Mutated headers never change the cursor. Use one mutation per step
        // so every rejection branch is reachable without constructing signed
        // semantic payloads.
        let mutation = data.get(1 + step).copied().unwrap_or(step as u8) % 8;
        let mut invalid = envelope.clone();
        mutate_header(&mut invalid, mutation);
        let root_before = schedule.transcript_root();
        let sequence_before = schedule.next_sequence();
        assert!(schedule.validate_header(&invalid).is_err());
        assert_eq!(schedule.transcript_root(), root_before);
        assert_eq!(schedule.next_sequence(), sequence_before);

        // The exact canonical envelope advances once. Replaying it must fail
        // and leave the newly advanced state unchanged.
        assert!(schedule.fuzzing_advance_authenticated(&envelope).is_ok());
        assert_eq!(schedule.next_sequence(), sequence_before + 1);
        let root_after = schedule.transcript_root();
        assert!(schedule.fuzzing_advance_authenticated(&envelope).is_err());
        assert_eq!(schedule.transcript_root(), root_after);
        assert_eq!(schedule.next_sequence(), sequence_before + 1);
    }

    if requested_steps == usize::try_from(ATTEMPT_ENVELOPE_COUNT).expect("constant fits usize") {
        assert!(schedule.expected().is_err());
    }
});

fn mutate_header(envelope: &mut Envelope, mutation: u8) {
    match mutation {
        0 => envelope.unsigned.protocol_version ^= 1,
        1 => envelope.unsigned.game_id[0] ^= 1,
        2 => envelope.unsigned.attempt ^= 1,
        3 => envelope.unsigned.sequence ^= 1,
        4 => envelope.unsigned.previous_message_hash[0] ^= 1,
        5 => envelope.unsigned.round ^= 1,
        6 => envelope.unsigned.sender_role = opposite(envelope.unsigned.sender_role),
        _ => {
            envelope.unsigned.payload_type =
                if envelope.unsigned.payload_type == PayloadType::KeyOpen {
                    PayloadType::KeyCommit
                } else {
                    PayloadType::KeyOpen
                };
        }
    }
}

fn read_u32(data: &[u8]) -> u32 {
    let mut bytes = [0_u8; 4];
    let copied = data.len().min(bytes.len());
    bytes[..copied].copy_from_slice(&data[..copied]);
    u32::from_le_bytes(bytes)
}

fn opposite(role: Role) -> Role {
    match role {
        Role::Alice => Role::Bob,
        Role::Bob => Role::Alice,
    }
}
