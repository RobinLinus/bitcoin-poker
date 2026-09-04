#![no_main]

use bp52_codec::{Decode, Encode, Reader};
use bp52_group::{CiphertextBytes, decode_point, decode_scalar};
use bp52_protocol::{
    SealedRetainedPreimages,
    messages::{
        AcceptedDeal, Ciphertext, ENCRYPTION_LINK_PROOF_SIZE, Envelope, HASH_LENGTH_PROOF_SIZE,
        PayloadType, PlayerBundle, RawEnvelope, SlotPublic, UnsignedEnvelope,
    },
    payloads::ProtocolPayload,
    uniqueness::UniquenessTranscript,
};
use bp52_uniqueness::{PartialDecryptionBatch, ScaleRound};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    canonical_roundtrip::<Envelope>(data);
    canonical_roundtrip::<RawEnvelope>(data);
    canonical_roundtrip::<UnsignedEnvelope>(data);
    canonical_roundtrip::<PlayerBundle>(data);
    canonical_roundtrip::<AcceptedDeal>(data);
    canonical_roundtrip::<ScaleRound>(data);
    canonical_roundtrip::<PartialDecryptionBatch>(data);
    canonical_roundtrip::<UniquenessTranscript>(data);
    if let Ok(encoded) = structured_bundle(data).encode_to_vec() {
        canonical_roundtrip::<PlayerBundle>(&encoded);
    }

    if let Some((&kind, body)) = data.split_first() {
        if let Ok(payload_type) = PayloadType::try_from(u16::from(kind)) {
            if let Ok(payload) = ProtocolPayload::decode_exact(payload_type, body) {
                assert_eq!(payload.encode_body().as_deref(), Ok(body));
            }
        }
    }

    if let Some(bytes) = prefix_array::<32>(data) {
        if let Ok(point) = decode_point(bytes, true) {
            assert_eq!(point.compress().to_bytes(), bytes);
        }
        let _ = decode_point(bytes, false);
        if let Ok(scalar) = decode_scalar(bytes) {
            assert_eq!(scalar.to_bytes(), bytes);
        }
    }
    if let Some(bytes) = prefix_array::<64>(data) {
        let ciphertext = CiphertextBytes {
            r: prefix_array::<32>(&bytes).unwrap_or([0_u8; 32]),
            s: prefix_array::<32>(&bytes[32..]).unwrap_or([0_u8; 32]),
        };
        if let Ok(decoded) = ciphertext.decompress() {
            assert_eq!(decoded.to_bytes(), ciphertext);
        }
        let _ = ciphertext.decompress_contribution();
    }

    let mut reader = Reader::new(data);
    let bound = data.first().copied().map_or(0, usize::from);
    let _ = reader.read_byte_vector(bound);
    let _ = reader.finish();

    if let Ok(value) = SealedRetainedPreimages::from_bytes(data) {
        assert_eq!(value.as_bytes(), data);
    }
});

fn canonical_roundtrip<T: Decode + Encode>(data: &[u8]) {
    if let Ok(value) = T::decode_exact(data) {
        assert_eq!(value.encode_to_vec().as_deref(), Ok(data));
    }
}

fn prefix_array<const N: usize>(data: &[u8]) -> Option<[u8; N]> {
    data.get(..N)?.try_into().ok()
}

fn structured_bundle(data: &[u8]) -> PlayerBundle {
    let role = if data.first().copied().unwrap_or(0) & 1 == 0 {
        bp52_protocol::Role::Alice
    } else {
        bp52_protocol::Role::Bob
    };
    let slots = std::array::from_fn(|index| SlotPublic {
        hash: filled_array(data, index),
        // The all-zero Ristretto encoding is the canonical identity. Message
        // decoding permits it; later attributable validation rejects it.
        value_commitment: [0_u8; 32],
        ciphertext: Ciphertext {
            r: [0_u8; 32],
            s: [0_u8; 32],
        },
    });
    PlayerBundle {
        role,
        slots,
        circuit_id: filled_array(data, 9),
        hash_length_proof: expanded(data, HASH_LENGTH_PROOF_SIZE),
        encryption_link_proof: expanded(data, ENCRYPTION_LINK_PROOF_SIZE),
    }
}

fn filled_array<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    std::array::from_fn(|index| {
        if data.is_empty() {
            0
        } else {
            data[(index + offset) % data.len()]
        }
    })
}

fn expanded(data: &[u8], length: usize) -> Vec<u8> {
    if data.is_empty() {
        return vec![0_u8; length];
    }
    (0..length).map(|index| data[index % data.len()]).collect()
}
