#![no_main]

use bp52_chain_runtime::Witness;
use bp52_lamport::{
    AliceScoreCertificate, BobScoreCertificate, LamportPublicBundle, LamportPublicKey,
    LamportSignature, SealedLamportSecretKey,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    exact_roundtrip(data, LamportPublicKey::decode, LamportPublicKey::encode);
    exact_roundtrip(data, LamportSignature::decode, LamportSignature::encode);
    exact_roundtrip(
        data,
        AliceScoreCertificate::decode,
        AliceScoreCertificate::encode,
    );
    exact_roundtrip(
        data,
        BobScoreCertificate::decode,
        BobScoreCertificate::encode,
    );
    exact_roundtrip(
        data,
        LamportPublicBundle::decode,
        LamportPublicBundle::encode,
    );
    if let Ok(value) = Witness::decode(data) {
        assert_eq!(
            value.encode().expect("decoded witness must re-encode"),
            data
        );
    }
    if let Ok(value) = SealedLamportSecretKey::from_bytes(data) {
        assert_eq!(value.as_bytes(), data);
    }
});

fn exact_roundtrip<T, E>(
    data: &[u8],
    decode: impl FnOnce(&[u8]) -> Result<T, E>,
    encode: impl FnOnce(&T) -> Vec<u8>,
) {
    if let Ok(value) = decode(data) {
        assert_eq!(encode(&value), data);
    }
}
