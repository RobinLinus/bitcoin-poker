#![no_main]

use bp52_circuit::hash_length::HASH_LENGTH_PROOF_SIZE;
use bp52_codec::{Decode, Encode};
use bp52_proof_backend::parse_exact_proof;
use bp52_sigma::{
    encryption_link::{ENCRYPTION_LINK_PROOF_SIZE, EncryptionLinkProof},
    partial_decrypt::{PARTIAL_DECRYPT_PROOF_SIZE, PartialDecryptionProof},
    scale::{SCALE_PROOF_SIZE, ScaleProof},
    schnorr::{KEY_PROOF_SIZE, KeyProof},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    canonical_roundtrip::<KeyProof>(data);
    canonical_roundtrip::<EncryptionLinkProof>(data);
    canonical_roundtrip::<ScaleProof>(data);
    canonical_roundtrip::<PartialDecryptionProof>(data);

    // Starting from an empty corpus, libFuzzer otherwise needs a long time to
    // grow inputs to the fixed 1.7--13.8 KiB proof sizes. Cyclic expansion
    // reaches every element parser immediately while the raw calls above keep
    // exercising short, long, and trailing-data rejection.
    canonical_roundtrip::<KeyProof>(&expanded(data, KEY_PROOF_SIZE));
    canonical_roundtrip::<EncryptionLinkProof>(&expanded(data, ENCRYPTION_LINK_PROOF_SIZE));
    canonical_roundtrip::<ScaleProof>(&expanded(data, SCALE_PROOF_SIZE));
    canonical_roundtrip::<PartialDecryptionProof>(&expanded(data, PARTIAL_DECRYPT_PROOF_SIZE));

    // Exercise exact-size gates as well as each backend proof element parser.
    for expected in [
        KEY_PROOF_SIZE,
        ENCRYPTION_LINK_PROOF_SIZE,
        SCALE_PROOF_SIZE,
        PARTIAL_DECRYPT_PROOF_SIZE,
        HASH_LENGTH_PROOF_SIZE,
    ] {
        let _ = parse_exact_proof(data, expected);
        let _ = parse_exact_proof(&expanded(data, expected), expected);
    }
});

fn canonical_roundtrip<T: Decode + Encode>(data: &[u8]) {
    if let Ok(value) = T::decode_exact(data) {
        assert_eq!(value.encode_to_vec().as_deref(), Ok(data));
    }
}

fn expanded(data: &[u8], length: usize) -> Vec<u8> {
    if data.is_empty() {
        return vec![0_u8; length];
    }
    (0..length).map(|index| data[index % data.len()]).collect()
}
